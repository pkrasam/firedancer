#include "../../../../disco/tiles.h"

#include "fd_archiver.h"
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <linux/unistd.h>
#include <sys/socket.h>
#include <linux/if_xdp.h>
#include "generated/archiver_playback_seccomp.h"

#define NET_SHRED_OUT_IDX  (0UL)
#define NET_QUIC_OUT_IDX   (1UL)
#define NET_GOSSIP_OUT_IDX (2UL)
#define NET_REPAIR_OUT_IDX (3UL)

struct fd_archiver_playback_stats {
  ulong net_shred_out_cnt;
  ulong net_quic_out_cnt;
  ulong net_gossip_out_cnt;
  ulong net_repair_out_cnt;
};
typedef struct fd_archiver_playback_stats fd_archiver_playback_stats_t;

typedef struct {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       chunk;
} fd_archiver_playback_out_ctx_t;

struct fd_archiver_playback_tile_ctx {
  void * archive_map;
  ulong  archive_size;
  ulong  archive_off;

  fd_archiver_playback_stats_t stats;

  long tick_per_ms;

  long next_publish_tick;

  ulong pending_publish_link_idx;
  fd_archiver_frag_header_t pending_publish_header;

  fd_archiver_playback_out_ctx_t out[ 32 ];
};
typedef struct fd_archiver_playback_tile_ctx fd_archiver_playback_tile_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 4096UL;
}

FD_FN_PURE static inline ulong
loose_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  return 1UL * FD_SHMEM_GIGANTIC_PAGE_SZ;
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  (void)topo;
  (void)tile;

  populate_sock_filter_policy_archiver_playback( out_cnt,
                                                 out,
                                                 (uint)fd_log_private_logfile_fd(),
                                                 (uint)tile->archiver.archive_fd );
  return sock_filter_policy_archiver_playback_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  (void)topo;
  (void)tile;
  (void)out_fds_cnt;

  ulong out_cnt = 0UL;

  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  if( FD_LIKELY( -1!=tile->archiver.archive_fd ) )
    out_fds[ out_cnt++ ] = tile->archiver.archive_fd; /* archive file */

  return out_cnt;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_archiver_playback_tile_ctx_t), sizeof(fd_archiver_playback_tile_ctx_t) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static inline long 
now( fd_archiver_playback_tile_ctx_t * ctx ) {
  (void)ctx;
  return fd_tickcount();
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
    (void)topo;
    (void)tile;

    void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

    FD_SCRATCH_ALLOC_INIT( l, scratch );
    fd_archiver_playback_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_archiver_playback_tile_ctx_t), sizeof(fd_archiver_playback_tile_ctx_t) ); 
    memset( ctx, 0, sizeof(fd_archiver_playback_tile_ctx_t) );
    FD_SCRATCH_ALLOC_FINI( l, scratch_align() );

    tile->archiver.archive_fd = open( tile->archiver.archive_path, O_RDONLY, 0666 );
    if ( FD_UNLIKELY( tile->archiver.archive_fd == -1 ) ) {
      FD_LOG_ERR(( "failed to open archive file %s %d %d %s", tile->archiver.archive_path, tile->archiver.archive_fd, errno, strerror(errno) ));
    }
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_archiver_playback_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_archiver_playback_tile_ctx_t), sizeof(fd_archiver_playback_tile_ctx_t) );
  FD_SCRATCH_ALLOC_FINI( l, scratch_align() );

  ctx->tick_per_ms = (long)(fd_tempo_tick_per_ns( NULL ) * 1000000.);

  /* mmap the file in */
  struct stat st;
  if( FD_UNLIKELY( fstat( tile->archiver.archive_fd, &st ) ) ) {
    FD_LOG_ERR(( "fstat on archive fd failed (%i-%s)", errno, strerror(errno) ));
  }
  ctx->archive_size = (ulong)st.st_size;
  void * map_addr = mmap( NULL, ctx->archive_size, PROT_READ, MAP_PRIVATE, tile->archiver.archive_fd, 0 );
  if( FD_UNLIKELY( map_addr == MAP_FAILED ) ) {
    FD_LOG_ERR(( "mmap of archive file failed (%i-%s)", errno, strerror(errno) ));
  }
  ctx->archive_map = map_addr;
  ctx->archive_off = 0UL;

  /* scan for the last non-zero byte - the archive file may have trailing zero bytes */
  uchar * p         = (uchar *)map_addr;
  for( long i=(long)ctx->archive_size - 1L; i>=0L; i-- ) {
    if( p[i] != 0U ) {
      ctx->archive_size = (ulong)i + 1UL;
      break;
    }
  }

  /* Setup output links */
  for( ulong i=0; i<tile->out_cnt; i++ ) {
    fd_topo_link_t * link      = &topo->links[ tile->out_link_id[ i ] ];
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    ctx->out[ i ].mem    = link_wksp->wksp;
    ctx->out[ i ].chunk0 = fd_dcache_compact_chunk0( link_wksp->wksp, link->dcache );
    ctx->out[ i ].wmark  = fd_dcache_compact_wmark( link_wksp->wksp, link->dcache, link->mtu );
    ctx->out[ i ].chunk  = ctx->out[ i ].chunk0;
  }
}

static inline int
should_delay_publish( fd_archiver_playback_tile_ctx_t * ctx ) {
  if( FD_UNLIKELY(( ctx->next_publish_tick == 0L )) ) {
    return 0;
  }

  return now( ctx ) < ctx->next_publish_tick;
}

static inline void
publish( fd_archiver_playback_tile_ctx_t * ctx,
         fd_stem_context_t *               stem ) {
  /* Publish the pending fragment */
  fd_stem_publish( stem, ctx->pending_publish_link_idx, ctx->pending_publish_header.sig, ctx->out[ ctx->pending_publish_link_idx ].chunk, ctx->pending_publish_header.sz, 0UL, 0UL, 0UL);
  ctx->out[ ctx->pending_publish_link_idx ].chunk = fd_dcache_compact_next( ctx->out[ ctx->pending_publish_link_idx ].chunk,
                                                                               ctx->pending_publish_header.sz,
                                                                           ctx->out[ ctx->pending_publish_link_idx ].chunk0,
                                                                            ctx->out[ ctx->pending_publish_link_idx ].wmark );

  /* Reset the state */
  memset( &ctx->pending_publish_header, 0, FD_ARCHIVER_FRAG_HEADER_FOOTPRINT );
}
 
static inline void
after_credit( fd_archiver_playback_tile_ctx_t *     ctx,
              fd_stem_context_t *                   stem,
              int *                                 opt_poll_in,
              int *                                 charge_busy ) {
  (void)ctx;
  (void)stem;
  (void)opt_poll_in;
  (void)charge_busy;

  /* Check to see if we have a pending frag ready to publish */
  if( FD_LIKELY(( ctx->pending_publish_header.magic )) ) {
    /* If we should delay, do not consume any more fragments from the archive but instead return */
    if( FD_UNLIKELY( should_delay_publish( ctx ) )) {
      return;
    } else {
      /* If we have caught up, publish the fragment */
      publish( ctx, stem );
    }
  }

  /* Check if we've reached EOF in the archive. */
  if( FD_UNLIKELY( ctx->archive_off >= ctx->archive_size ||
                   (ctx->archive_size - ctx->archive_off) < FD_ARCHIVER_FRAG_HEADER_FOOTPRINT ) ) {
    FD_LOG_WARNING(( "playback_stats net_shred_out_cnt=%lu, net_quic_out_cnt=%lu, net_gossip_out_cnt=%lu, net_repair_out_cnt=%lu",
                     ctx->stats.net_shred_out_cnt,
                     ctx->stats.net_quic_out_cnt,
                     ctx->stats.net_gossip_out_cnt,
                     ctx->stats.net_repair_out_cnt ));
    FD_LOG_ERR(( "end of archive file" ));
  }

  /* Consume the header */
  uchar const * hdr_ptr = (uchar const *)ctx->archive_map + ctx->archive_off;
  fd_memcpy( &ctx->pending_publish_header, hdr_ptr, FD_ARCHIVER_FRAG_HEADER_FOOTPRINT );
  ctx->archive_off += FD_ARCHIVER_FRAG_HEADER_FOOTPRINT;
  if( FD_UNLIKELY( ctx->pending_publish_header.magic != FD_ARCHIVER_HEADER_MAGIC ) ) {
    FD_LOG_ERR(( "bad magic in archive header: %lu", ctx->pending_publish_header.magic ));
  }

  /* Determine the output link on which to send the frag */
  ulong out_link_idx = 0UL;
  switch ( ctx->pending_publish_header.tile_id ) {
    case FD_ARCHIVER_TILE_ID_SHRED:
    out_link_idx = NET_SHRED_OUT_IDX;
    ctx->stats.net_shred_out_cnt += 1;
    break;
    case FD_ARCHIVER_TILE_ID_QUIC:
    out_link_idx = NET_QUIC_OUT_IDX;
    ctx->stats.net_quic_out_cnt += 1;
    break;
    case FD_ARCHIVER_TILE_ID_GOSSIP:
    out_link_idx = NET_GOSSIP_OUT_IDX;
    ctx->stats.net_gossip_out_cnt += 1;
    break;
    case FD_ARCHIVER_TILE_ID_REPAIR:
    out_link_idx = NET_REPAIR_OUT_IDX;
    ctx->stats.net_repair_out_cnt += 1;
    break;
    default:
    FD_LOG_ERR(( "unsupported tile id" ));
  }

  /* Copy fragment from archive file into the output link, ready for publishing */
  if( FD_UNLIKELY( (ctx->archive_size - ctx->archive_off) < ctx->pending_publish_header.sz ) ) {
    FD_LOG_WARNING(( "playback_stats net_shred_out_cnt=%lu, net_quic_out_cnt=%lu, net_gossip_out_cnt=%lu, net_repair_out_cnt=%lu",
                     ctx->stats.net_shred_out_cnt,
                     ctx->stats.net_quic_out_cnt,
                     ctx->stats.net_gossip_out_cnt,
                     ctx->stats.net_repair_out_cnt ));
    FD_LOG_ERR(( "archive file too small" ));
  }
  ctx->pending_publish_link_idx = out_link_idx;

  uchar const * frag_ptr = (uchar const *)ctx->archive_map + ctx->archive_off;
  uchar       * dst      = (uchar *)fd_chunk_to_laddr( ctx->out[ out_link_idx ].mem, ctx->out[ out_link_idx ].chunk );
  fd_memcpy( dst, frag_ptr, ctx->pending_publish_header.sz );
  ctx->archive_off += ctx->pending_publish_header.sz;
  ctx->next_publish_tick = now( ctx ) + ctx->pending_publish_header.ticks_since_prev_fragment;
}

#define STEM_BURST (1UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_archiver_playback_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_archiver_playback_tile_ctx_t)

#define STEM_CALLBACK_AFTER_CREDIT        after_credit

#include "../../../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_archiver_playback = {
  .name                     = "arch_p",
  .loose_footprint          = loose_footprint,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
