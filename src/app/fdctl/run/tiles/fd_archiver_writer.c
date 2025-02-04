#define _GNU_SOURCE  /* Enable GNU and POSIX extensions */

#include "../../../../disco/tiles.h"

#include "fd_archiver.h"
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <linux/unistd.h>
#include <sys/socket.h>
#include <linux/if_xdp.h>
#include "generated/archiver_writer_seccomp.h"

#define FD_ARCHIVER_WRITER_OUT_BUF_SZ (10240UL)

/* Initial size of the mmapped region. This will grow. */
#define FD_ARCHIVER_WRITER_MMAP_INITIAL_SIZE  (2147483648UL)

struct fd_archiver_writer_stats {
  ulong net_shred_in_cnt;
  ulong quic_verify_in_cnt;
  ulong net_gossip_in_cnt;
  ulong net_repair_in_cnt;
};
typedef struct fd_archiver_writer_stats fd_archiver_writer_stats_t;

typedef struct {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
} fd_archiver_writer_in_ctx_t;

struct fd_archiver_writer_tile_ctx {
  double                      tick_per_ns;
  fd_archiver_writer_in_ctx_t in[ 32 ];

  fd_archiver_writer_stats_t stats;

  int     archive_file_fd;
  uchar * mmap_addr;
  ulong   mmap_size;
  ulong   mmap_off;
};
typedef struct fd_archiver_writer_tile_ctx fd_archiver_writer_tile_ctx_t;

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

  populate_sock_filter_policy_archiver_writer( out_cnt,
                                               out,
                                               (uint)fd_log_private_logfile_fd(),
                                               (uint)tile->archiver.archive_fd );
  return sock_filter_policy_archiver_writer_instr_cnt;
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
  l = FD_LAYOUT_APPEND( l, alignof(fd_archiver_writer_tile_ctx_t), sizeof(fd_archiver_writer_tile_ctx_t) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
    (void)topo;
    (void)tile;

    void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

    FD_SCRATCH_ALLOC_INIT( l, scratch );
    fd_archiver_writer_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_archiver_writer_tile_ctx_t), sizeof(fd_archiver_writer_tile_ctx_t) ); 
    memset( ctx, 0, sizeof(fd_archiver_writer_tile_ctx_t) );
    FD_SCRATCH_ALLOC_FINI( l, scratch_align() );

    tile->archiver.archive_fd = open( tile->archiver.archive_path, O_RDWR | O_CREAT, 0666 );
    if ( FD_UNLIKELY( tile->archiver.archive_fd == -1 ) ) {
      FD_LOG_ERR(( "failed to open or create archive file %s %d %d %s", tile->archiver.archive_path, tile->archiver.archive_fd, errno, strerror(errno) ));
    }
    ctx->archive_file_fd = tile->archiver.archive_fd;
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_archiver_writer_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_archiver_writer_tile_ctx_t), sizeof(fd_archiver_writer_tile_ctx_t) );
  FD_SCRATCH_ALLOC_FINI( l, scratch_align() );

  /* Setup the archive tile to be in the expected state */
  int err = ftruncate( tile->archiver.archive_fd, 0UL );
  if( FD_UNLIKELY( err==-1 ) ) {
    FD_LOG_ERR(( "failed to truncate the archive file (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  err = ftruncate( tile->archiver.archive_fd, FD_ARCHIVER_WRITER_MMAP_INITIAL_SIZE );
  if( FD_UNLIKELY( err==-1 ) ) {
    FD_LOG_ERR(( "failed to set initial size of archive file (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  long seek = lseek( tile->archiver.archive_fd, 0UL, SEEK_SET );
  if( FD_UNLIKELY( seek!=0L ) ) {
    FD_LOG_ERR(( "failed to seek to the beginning of the archive file" ));
  }

  /* mmap the file in */
  ctx->mmap_size  = FD_ARCHIVER_WRITER_MMAP_INITIAL_SIZE;
  ctx->mmap_off  = 0UL;
  ctx->mmap_addr = mmap( NULL,
                         ctx->mmap_size,
                         PROT_WRITE,
                         MAP_SHARED,
                         tile->archiver.archive_fd,
                         0 );
  if( ctx->mmap_addr == MAP_FAILED ) {
    FD_LOG_ERR(( "failed to mmap archive file. errno=%i (%s)", errno, strerror(errno) ));
  }
  if( madvise( ctx->mmap_addr, ctx->mmap_size, MADV_SEQUENTIAL ) ) {
    FD_LOG_WARNING(( "madvise(MADV_SEQUENTIAL) failed (%i-%s)", errno, strerror(errno) ));
  }

  /* Input links */
  for( ulong i=0; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    ctx->in[ i ].mem    = link_wksp->wksp;
    ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].mem, link->dcache );
    ctx->in[ i ].wmark  = fd_dcache_compact_wmark ( ctx->in[ i ].mem, link->dcache, link->mtu );
  }

  ctx->tick_per_ns = fd_tempo_tick_per_ns( NULL );
}

static inline long 
now( fd_archiver_writer_tile_ctx_t * ctx ) {
  return (long)(((double)fd_tickcount()) / ctx->tick_per_ns);
}

static void
during_housekeeping( fd_archiver_writer_tile_ctx_t * ctx ) {
  // if( msync( ctx->mmap_addr, ctx->mmap_size, MS_ASYNC ) != 0 ) {
  //   FD_LOG_WARNING(( "msync failed. errno=%i", errno ));
  // }

  FD_LOG_WARNING(( "writer stats: net_shred_in_cnt=%lu quic_verify_in_cnt=%lu net_gossip_in_cnt=%lu net_repair_in_cnt=%lu",
    ctx->stats.net_shred_in_cnt,
    ctx->stats.quic_verify_in_cnt,
    ctx->stats.net_gossip_in_cnt,
    ctx->stats.net_repair_in_cnt ));
}

/* Expand the mmap region if the next write would exceed the current size. */
static void
resize_mmap( fd_archiver_writer_tile_ctx_t * ctx ) {
  ulong new_size = ctx->mmap_size << 1;

  /* ftruncate to new_size */
  if( FD_UNLIKELY( ftruncate( ctx->archive_file_fd, (off_t)new_size ) ) ) {
    FD_LOG_ERR(( "ftruncate to %lu bytes failed: %i (%s)",
                 new_size, errno, strerror(errno) ));
  }

  /* mremap our existing mapping to the new size */
  void * new_map = mremap( ctx->mmap_addr, 
                           ctx->mmap_size,
                           new_size,
                           MREMAP_MAYMOVE );
  if( new_map == MAP_FAILED ) {
    FD_LOG_ERR(( "mremap failed: %i (%s)", errno, strerror(errno) ));
  }
  if( madvise( new_map, new_size, MADV_SEQUENTIAL ) ) {
    FD_LOG_WARNING(( "madvise(MADV_SEQUENTIAL) after mremap failed (%i-%s)", errno, strerror(errno) ));
  }

  ctx->mmap_addr = (uchar *)new_map;
  ctx->mmap_size = new_size;
}

static inline void
during_frag( fd_archiver_writer_tile_ctx_t * ctx,
             ulong                           in_idx,
             ulong                           seq,
             ulong                           sig,
             ulong                           tspub,
             ulong                           chunk,
             ulong                           sz ) {
  (void)seq;
  (void)sig;
  (void)tspub;

  if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark ) ) {
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));
  }

  /* Write the incoming fragment to the ostream */
  /* This is safe to do inside during_frag because this tile is a reliable consumer and so can never be overran. */
  uchar * src = (uchar *)fd_chunk_to_laddr( ctx->in[in_idx].mem, chunk );

  /* Update the timestamp of the fragment, so that we have a total ordering */
  fd_archiver_frag_header_t * header = fd_type_pun( src );
  header->timestamp                  = now( ctx );

  /* Resize the mmap region if necessary */
  if( FD_UNLIKELY( ctx->mmap_off + sz > ctx->mmap_size ) ) {
    resize_mmap( ctx );
  }

  /* Copy fragment into the mapped region */
  uchar * dst = ctx->mmap_addr + ctx->mmap_off;
  memcpy( dst, src, sz );
  ctx->mmap_off += sz;

  /* Sanity-check header has not been overwritten */
  fd_archiver_frag_header_t * written_header = fd_type_pun( dst );
  if( FD_UNLIKELY(( written_header->magic != FD_ARCHIVER_HEADER_MAGIC )) ) {
    FD_LOG_ERR(( "bad magic" ));
  }

  ctx->stats.net_repair_in_cnt  += header->tile_id == FD_ARCHIVER_TILE_ID_REPAIR;
  ctx->stats.net_gossip_in_cnt  += header->tile_id == FD_ARCHIVER_TILE_ID_GOSSIP;
  ctx->stats.net_shred_in_cnt   += header->tile_id == FD_ARCHIVER_TILE_ID_SHRED;
  ctx->stats.quic_verify_in_cnt += header->tile_id == FD_ARCHIVER_TILE_ID_VERIFY;
}

#define STEM_BURST (1UL)
#define STEM_LAZY  (2147483647)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_archiver_writer_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_archiver_writer_tile_ctx_t)

#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_DURING_FRAG         during_frag

#include "../../../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_archiver_writer = {
  .name                     = "arch_w",
  .loose_footprint          = loose_footprint,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
