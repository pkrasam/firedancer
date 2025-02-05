#ifndef HEADER_fd_src_waltz_quic_fd_quic_pkt_meta_h
#define HEADER_fd_src_waltz_quic_fd_quic_pkt_meta_h

#include "fd_quic_common.h"

typedef struct fd_quic_pkt_meta      fd_quic_pkt_meta_t;
typedef struct fd_quic_pkt_meta_list fd_quic_pkt_meta_list_t;
typedef struct fd_quic_pkt_meta_trackers fd_quic_pkt_meta_trackers_t;

/* TODO convert to a union with various types of metadata overlaid */

/* fd_quic_pkt_meta_var used for tracking max_data, max_stream_data and
 * max_streams
 *
 * type:      FD_QUIC_PKT_META_TYPE_STREAM_DATA
 *            FD_QUIC_PKT_META_TYPE_OTHER
 * flags:     FD_QUIC_PKT_META_FLAGS_*
 * value:     max_data          number of bytes
 *            max_stream_data   number of bytes
 *            max_streams       number of streams
 */
union fd_quic_pkt_meta_key {
  union {
#define FD_QUIC_PKT_META_STREAM_MASK ((1UL<<62UL)-1UL)
    ulong stream_id;
    struct {
      ulong flags:62;
      ulong type:2;
#define FD_QUIC_PKT_META_TYPE_OTHER           0UL
#define FD_QUIC_PKT_META_TYPE_STREAM_DATA     1UL
    };
#define FD_QUIC_PKT_META_KEY( TYPE, FLAGS, STREAM_ID ) \
    ((fd_quic_pkt_meta_key_t)                          \
     { .stream_id = ( ( (ulong)(STREAM_ID) )    |      \
                      ( (ulong)(TYPE) << 62UL ) |      \
                      ( (ulong)(FLAGS) ) ) } )
    /* FD_QUIC_PKT_META_STREAM_ID
     * This is used to extract the stream_id, since some of the bits are used
     * for "type".
     * The more natural way "stream_id:62" caused compilation warnings and ugly
     * work-arounds */
#define FD_QUIC_PKT_META_STREAM_ID( KEY ) ( (KEY).stream_id & FD_QUIC_PKT_META_STREAM_MASK )
  };
};
typedef union fd_quic_pkt_meta_key fd_quic_pkt_meta_key_t;

struct fd_quic_pkt_meta_var {
  fd_quic_pkt_meta_key_t key;
  union {
    ulong                value;
    fd_quic_range_t      range;
  };
};
typedef struct fd_quic_pkt_meta_var fd_quic_pkt_meta_var_t;

/* the max number of pkt_meta_var entries in pkt_meta
   this limits the number of max_data, max_stream_data and max_streams
   allowed in a single quic packet */
#define FD_QUIC_PKT_META_VAR_MAX 16

/* fd_quic_pkt_meta

   tracks the metadata of data sent to the peer
   used when acks arrive to determine what is being acked specifically */
struct fd_quic_pkt_meta {
  /* stores metadata about what was sent in the identified packet */
  ulong pkt_number;  /* packet number (in pn_space) */
  uchar enc_level;   /* encryption level of packet */
  uchar pn_space;    /* packet number space (derived from enc_level) */
  uchar var_sz;      /* number of populated entries in var */

  /* does/should the referenced packet contain:
       FD_QUIC_PKT_META_FLAGS_HS_DATA             handshake data
       FD_QUIC_PKT_META_FLAGS_STREAM              stream data
       FD_QUIC_PKT_META_FLAGS_HS_DONE             handshake-done frame
       FD_QUIC_PKT_META_FLAGS_MAX_DATA            max_data frame
       FD_QUIC_PKT_META_FLAGS_MAX_STREAMS_UNIDIR  max_streams frame (unidir)
       FD_QUIC_PKT_META_FLAGS_CLOSE               close frame
       FD_QUIC_PKT_META_FLAGS_PING                set to send a PING frame

     some of these flags are mutually exclusive */
  uint                   flags;       /* flags */
# define          FD_QUIC_PKT_META_FLAGS_HS_DATA            (1u<<0u)
# define          FD_QUIC_PKT_META_FLAGS_STREAM             (1u<<1u)
# define          FD_QUIC_PKT_META_FLAGS_HS_DONE            (1u<<2u)
# define          FD_QUIC_PKT_META_FLAGS_MAX_DATA           (1u<<3u)
# define          FD_QUIC_PKT_META_FLAGS_MAX_STREAMS_UNIDIR (1u<<4u)
# define          FD_QUIC_PKT_META_FLAGS_CLOSE              (1u<<5u)
# define          FD_QUIC_PKT_META_FLAGS_PING               (1u<<6u)
  fd_quic_range_t        range;       /* CRYPTO data range; FIXME use pkt_meta var instead */
  ulong                  stream_id;   /* if this contains stream data,
                                         the stream id, else zero */

  ulong                  tx_time;     /* transmit time */
  ulong                  expiry;      /* time pkt_meta expires... this is the time the
                                         ack is expected by */

  fd_quic_pkt_meta_var_t var[FD_QUIC_PKT_META_VAR_MAX];

  /* treap fields */
  ulong parent;
  ulong left;
  ulong right;
  ulong prio;
  ulong next;
  ulong prev;
};

#define TREAP_NAME      fd_quic_pkt_meta_treap
#define TREAP_T         fd_quic_pkt_meta_t
#define TREAP_QUERY_T   ulong
#define TREAP_CMP(q,e)  (int)((long)(q) - (long)(e)->pkt_number)
#define TREAP_LT(e0,e1) ((e0)->pkt_number < (e1)->pkt_number)
#define TREAP_OPTIMIZE_ITERATION 1
#include "../../util/tmpl/fd_treap.c"

#define POOL_NAME fd_quic_pkt_meta_pool
#define POOL_T    fd_quic_pkt_meta_t
#include "../../util/tmpl/fd_pool.c"

/* alias for transparent ds */
typedef fd_quic_pkt_meta_treap_t fd_quic_pkt_meta_ds_t;
typedef fd_quic_pkt_meta_treap_fwd_iter_t fd_quic_pkt_meta_ds_fwd_iter_t;

static inline fd_quic_pkt_meta_ds_fwd_iter_t
fd_quic_pkt_meta_ds_fwd_iter_init( fd_quic_pkt_meta_ds_t * treap,
                                  fd_quic_pkt_meta_t *   pool ) {
  return fd_quic_pkt_meta_treap_fwd_iter_init( treap, pool );
}

static inline fd_quic_pkt_meta_t *
fd_quic_pkt_meta_ds_fwd_iter_ele( fd_quic_pkt_meta_ds_fwd_iter_t iter,
                                  fd_quic_pkt_meta_t *   pool ) {
  return fd_quic_pkt_meta_treap_fwd_iter_ele( iter, pool );
}

static inline fd_quic_pkt_meta_ds_fwd_iter_t
fd_quic_pkt_meta_ds_fwd_iter_next( fd_quic_pkt_meta_ds_fwd_iter_t iter,
                                   fd_quic_pkt_meta_t *   pool ) {
  return fd_quic_pkt_meta_treap_fwd_iter_next( iter, pool );
}

static inline int
fd_quic_pkt_meta_ds_fwd_iter_done( fd_quic_pkt_meta_ds_fwd_iter_t iter ) {
  return fd_quic_pkt_meta_treap_fwd_iter_done( iter );
}

static inline ulong
fd_quic_pkt_meta_ds_idx_lower_bound( fd_quic_pkt_meta_ds_t * treap,
                                     ulong                   pkt_number,
                                     fd_quic_pkt_meta_t *   pool ) {
  return fd_quic_pkt_meta_treap_idx_lower_bound( treap, pkt_number, pool );
}

/* end transparent ds */

struct fd_quic_pkt_meta_trackers {
  fd_quic_pkt_meta_ds_t sent_pkt_metas[4];
  fd_quic_pkt_meta_t *    pkt_meta_mem;    /* owns the memory for fd_pool of pkt_meta */
  fd_quic_pkt_meta_t *    pkt_meta_pool_join;
};

/*
   process the pkt_meta in the chosen DS
   cb verbatim executed with current pkt_meta named 'e'
   prev_cb verbatim executed with previous pkt_meta named 'prev'
   condition is the condition to stop processing
*/
#define FD_QUIC_PKT_META_PROCESS( cb, prev_cb, condition, sent, pool, start ) \
  do { \
    fd_quic_pkt_meta_t *       prev  =  NULL; \
    for( fd_quic_pkt_meta_ds_fwd_iter_t iter = start; \
                                               !fd_quic_pkt_meta_ds_fwd_iter_done( iter ); \
                                               iter = fd_quic_pkt_meta_ds_fwd_iter_next( iter, pool ) ) { \
      fd_quic_pkt_meta_t * e = fd_quic_pkt_meta_ds_fwd_iter_ele( iter, pool ); \
      if ( condition ) { \
        break; \
      } \
      if ( prev ) { \
        prev_cb; \
      } \
      cb; \
      prev = e; \
    } \
    if( prev ) { \
      prev_cb; \
    } \
  } while( 0 );

#define FD_QUIC_PKT_META_PROCESS_FROM_BEGIN( cb, prev_cb, condition, sent, pool) \
  FD_QUIC_PKT_META_PROCESS( cb, prev_cb, condition, sent, pool, fd_quic_pkt_meta_ds_fwd_iter_init( sent, pool ) )

void *
fd_quic_pkt_meta_trackers_init( fd_quic_pkt_meta_trackers_t * trackers,
                                fd_quic_pkt_meta_t          * pkt_meta_mem,
                                ulong                         total_meta_cnt );

void
fd_quic_pkt_meta_insert( fd_quic_pkt_meta_ds_t * ds,
                         fd_quic_pkt_meta_t    * pkt_meta,
                         fd_quic_pkt_meta_t    * pool );

/*
   remove all pkt_meta in the range [pkt_number_lo, pkt_number_hi]
   rm from treap and return to pool
*/
void
fd_quic_pkt_meta_remove_range( fd_quic_pkt_meta_ds_t * ds,
                               fd_quic_pkt_meta_t    * pool,
                               ulong                   pkt_number_lo,
                               ulong                   pkt_number_hi );

fd_quic_pkt_meta_t *
fd_quic_pkt_meta_min( fd_quic_pkt_meta_ds_t * ds,
                      fd_quic_pkt_meta_t    * pool );

void
fd_quic_pkt_meta_clear( fd_quic_pkt_meta_trackers_t * trackers,
                        uint                          enc_level );

FD_PROTOTYPES_END

#endif // HEADER_fd_src_waltz_quic_fd_quic_pkt_meta_h
