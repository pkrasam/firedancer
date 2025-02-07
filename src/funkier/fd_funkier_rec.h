#ifndef HEADER_fd_src_funk_fd_funkier_rec_h
#define HEADER_fd_src_funk_fd_funkier_rec_h

/* This provides APIs for managing funk records.  It is generally not
   meant to be included directly.  Use fd_funk.h instead. */

#include "fd_funkier_txn.h" /* Includes fd_funkier_base.h */

/* FD_FUNKIER_REC_{ALIGN,FOOTPRINT} describe the alignment and footprint of
   a fd_funkier_rec_t.  ALIGN will be a power of 2, footprint will be a
   multiple of align.  These are provided to facilitate compile time
   declarations. */

#define FD_FUNKIER_REC_ALIGN     (32UL)

/* FD_FUNKIER_REC_FLAG_* are flags that can be bit-ored together to specify
   how records are to be interpreted.  The 5 most significant bytes of a
   rec's flag are reserved to be used in conjunction with the ERASE flag.

   - ERASE indicates a record in an in-preparation transaction should be
   erased if and when the in-preparation transaction is published. If
   set on a published record, it serves as a tombstone.
   If set, there will be no value resources used by this record. */

#define FD_FUNKIER_REC_FLAG_ERASE (1UL<<0)

/* FD_FUNKIER_REC_IDX_NULL gives the map record idx value used to represent
   NULL.  This value also set a limit on how large rec_max can be. */

#define FD_FUNKIER_REC_IDX_NULL (ULONG_MAX)

/* FD_FUNKIER_PART_NULL is the partition number of records that are not
   in a partition */
#define FD_FUNKIER_PART_NULL (UINT_MAX)

/* A fd_funkier_rec_t describes a funk record. */

struct __attribute__((aligned(FD_FUNKIER_REC_ALIGN))) fd_funkier_rec {

  /* These fields are managed by the funk's rec_map */

  fd_funkier_xid_key_pair_t pair;     /* Transaction id and record key pair */
  ulong                  map_next; /* Internal use by map */
  ulong                  map_hash; /* Internal use by map */

  /* These fields are managed by funk.  TODO: Consider using record
     index compression here (much more debatable than in txn itself). */

  ulong prev_idx;  /* Record map index of previous record */
  ulong next_idx;  /* Record map index of next record */
  uint  txn_cidx;  /* Compressed transaction map index (or compressed FD_FUNKIER_TXN_IDX if this is in the last published) */
  uint  tag;       /* Internal use only */
  ulong flags;     /* Flags that indicate how to interpret a record */

  /* Note: use of uint here requires FD_FUNKIER_REC_VAL_MAX to be at most
     UINT_MAX. */

  uint  val_sz;    /* Num bytes in record value, in [0,val_max] */
  uint  val_max;   /* Max byte  in record value, in [0,FD_FUNKIER_REC_VAL_MAX], 0 if erase flag set or val_gaddr is 0 */
  ulong val_gaddr; /* Wksp gaddr on record value if any, 0 if erase flag set or val_max is 0
                      If non-zero, the region [val_gaddr,val_gaddr+val_max) will be a current fd_alloc allocation (such that it is
                      has tag wksp_tag) and the owner of the region will be the record.  IMPORTANT! HAS NO GUARANTEED ALIGNMENT! */

  /* Padding to FD_FUNKIER_REC_ALIGN here */
};

typedef struct fd_funkier_rec fd_funkier_rec_t;

FD_STATIC_ASSERT( sizeof(fd_funkier_rec_t) == 4U*32U, record size is wrong );

/* fd_funkier_rec_map allows for indexing records by their (xid,key) pair.
   It is used to store all records of the last published transaction and
   the records being updated for a transaction that is in-preparation.
   Published records are stored under the pair (root,key).  (This is
   done so that publishing a transaction doesn't require updating all
   transaction id of all the records that were not updated by the
   publish.) */

#define POOL_NAME          fd_funkier_rec_pool
#define POOL_ELE_T         fd_funkier_rec_t
#define POOL_IDX_T         uint
#define POOL_NEXT          map_next
#define POOL_IMPL_STYLE    1
#include "../util/tmpl/fd_pool_para.c"

#define MAP_NAME              fd_funkier_rec_map
#define MAP_ELE_T             fd_funkier_rec_t
#define MAP_KEY_T             fd_funkier_xid_key_pair_t
#define MAP_KEY               pair
#define MAP_KEY_EQ(k0,k1)     fd_funkier_xid_key_pair_eq((k0),(k1))
#define MAP_KEY_HASH(k0,seed) fd_funkier_xid_key_pair_hash((k0),(seed))
#define MAP_NEXT              map_next
#define MAP_MEMO              map_hash
#define MAP_MAGIC             (0xf173da2ce77ecdb0UL) /* Firedancer rec db version 0 */
#define MAP_MEMOIZE           1
#define MAP_IMPL_STYLE        1
#include "../util/tmpl/fd_map_para.c"

typedef fd_funkier_rec_map_query_t fd_funkier_rec_query_t;

struct _fd_funkier_rec_prepare {
  fd_funkier_rec_map_t rec_map;
  fd_funkier_rec_pool_t rec_pool;
  fd_funkier_txn_pool_t txn_pool;
  fd_funkier_rec_t * rec;
  ulong * rec_head_idx;
  ulong * rec_tail_idx;
};

typedef struct _fd_funkier_rec_prepare fd_funkier_rec_prepare_t;

FD_PROTOTYPES_BEGIN

/* fd_funkier_rec_idx_is_null returns 1 if idx is FD_FUNKIER_REC_IDX_NULL and
   0 otherwise. */

FD_FN_CONST static inline int fd_funkier_rec_idx_is_null( ulong idx ) { return idx==FD_FUNKIER_REC_IDX_NULL; }

/* Accessors */

/* fd_funkier_rec_query queries the in-preparation transaction pointed to
   by txn for the record whose key matches the key pointed to by key.
   If txn is NULL, the query will be done for the funk's last published
   transaction.  Returns a pointer to current record on success and NULL
   on failure.  Reasons for failure include txn is neither NULL nor a
   pointer to a in-preparation transaction, key is NULL or not a record
   in the given transaction.

   The returned pointer is in the caller's address space if the
   return value is non-NULL.

   Assumes funk is a current local join (NULL returns NULL), txn is NULL
   or points to an in-preparation transaction in the caller's address
   space, key points to a record key in the caller's address space (NULL
   returns NULL), and no concurrent operations on funk, txn or key.
   funk retains no interest in key.  The funk retains ownership of any
   returned record.  The record value metadata will be updated whenever
   the record value modified.

   This is reasonably fast O(1).

   Important safety tip!  This function can encounter records
   that have the ERASE flag set (i.e. are tombstones of erased
   records). fd_funkier_rec_query_try will still return the record in this
   case, and the application should check for the flag. */

fd_funkier_rec_t const *
fd_funkier_rec_query_try( fd_funkier_t *               funk,
                          fd_funkier_txn_t const *     txn,
                          fd_funkier_rec_key_t const * key,
                          fd_funkier_rec_query_t *     query );

int fd_funkier_rec_query_test( fd_funkier_rec_query_t * query );

/* fd_funkier_rec_query_global is the same as fd_funkier_rec_query but will
   query txn's ancestors for key from youngest to oldest if key is not
   part of txn.  As such, the txn of the returned record may not match
   txn but will be the txn of most recent ancestor with the key
   otherwise. *txn_out is set to the transaction where the record was
   found.

   This is reasonably fast O(in_prep_ancestor_cnt).

   Important safety tip!  This function can encounter records
   that have the ERASE flag set (i.e. are tombstones of erased
   records). fd_funkier_rec_query_global will return a NULL in this case
   but still set *txn_out to the relevant transaction. This behavior
   differs from fd_funkier_rec_query. */
fd_funkier_rec_t const *
fd_funkier_rec_query_try_global( fd_funkier_t *               funk,
                                 fd_funkier_txn_t const *     txn,
                                 fd_funkier_rec_key_t const * key,
                                 fd_funkier_txn_t const **    txn_out,
                                 fd_funkier_rec_query_t *     query );

/* fd_funkier_rec_{pair,xid,key} returns a pointer in the local address
   space of the {(transaction id,record key) pair,transaction id,record
   key} of a live record.  Assumes rec points to a live record in the
   caller's address space.  The lifetime of the returned pointer is the
   same as rec.  The value at the pointer will be constant for its
   lifetime. */

FD_FN_CONST static inline fd_funkier_xid_key_pair_t const * fd_funkier_rec_pair( fd_funkier_rec_t const * rec ) { return &rec->pair;    }
FD_FN_CONST static inline fd_funkier_txn_xid_t const *      fd_funkier_rec_xid ( fd_funkier_rec_t const * rec ) { return rec->pair.xid; }
FD_FN_CONST static inline fd_funkier_rec_key_t const *      fd_funkier_rec_key ( fd_funkier_rec_t const * rec ) { return rec->pair.key; }

/* Insert a record. insert_prepare just allocates
 * and initializes a record. The application should then fill in the
 * value. insert_publish actually does the insert,
 * provided the chain has not changed in the meantime. */

fd_funkier_rec_t *
fd_funkier_rec_prepare( fd_funkier_t *               funk,
                        fd_funkier_txn_t *           txn,
                        fd_funkier_rec_key_t const * key,
                        fd_funkier_rec_prepare_t *   prepare,
                        int *                        opt_err );

void
fd_funkier_rec_publish( fd_funkier_rec_prepare_t * prepare );

void
fd_funkier_rec_cancel( fd_funkier_rec_prepare_t * prepare );

int
fd_funkier_rec_is_full( fd_funkier_t * funk );

/* fd_funkier_rec_remove removes the live record pointed to by rec from
   the funk.  Returns FD_FUNKIER_SUCCESS (0) on success and a FD_FUNKIER_ERR_*
   (negative) on failure.  Reasons for failure include:

     FD_FUNKIER_ERR_INVAL - bad inputs (NULL funk, NULL rec, rec is
       obviously not from funk, etc)

     FD_FUNKIER_ERR_KEY - the record did not appear to be a live record.
       Specifically, a record query of funk for rec's (xid,key) pair did
       not return rec.

   The record will cease to exist in that transaction and any of
   transaction's subsequently created descendants (again, assuming no
   subsequent insert of key).  This type of remove can be done on a
   published record (assuming the last published transaction is
   unfrozen). A tombstone is left in funk to track removals as they
   are published or cancelled.

   Any information in an erased record is lost.

   Assumes funk is a current local join (NULL returns ERR_INVAL) and rec
   points to a record in the caller's address space (NULL returns
   ERR_INVAL).  As the funk still has ownership of rec before and after
   the call if live, the user doesn't need to, for example, match
   inserts with removes.

   This is a reasonably fast O(1) and fortified against memory corruption.

   IMPORTANT SAFETY TIP!  DO NOT CAST AWAY CONST FROM A FD_FUNKIER_REC_T TO
   USE THIS FUNCTION (E.G. PASS A RESULT DIRECTLY FROM QUERY).  USE A
   LIVE RESULT FROM FD_FUNKIER_REC_MODIFY! */

int
fd_funkier_rec_remove( fd_funkier_t *               funk,
                       fd_funkier_txn_t *           txn,
                       fd_funkier_rec_key_t const * key,
                       ulong                        erase_data );


/* When a record is erased there is metadata stored in the five most
   significant bytes of a record.  These are helpers to make setting
   and getting these values simple. The caller is responsible for doing
   a check on the flag of the record before using the value of the erase
   data. The 5 least significant bytes of the erase data parameter will
   be used and set into the erase flag. */

void
fd_funkier_rec_set_erase_data( fd_funkier_rec_t * rec, ulong erase_data );

ulong
fd_funkier_rec_get_erase_data( fd_funkier_rec_t const * rec );

/* Remove a list of tombstones from funk, thereby freeing up space in
   the main index. All the records must be removed and published
   beforehand. Reasons for failure include:

     FD_FUNKIER_ERR_INVAL - bad inputs (NULL funk, NULL rec, rec is
       obviously not from funk, etc)

     FD_FUNKIER_ERR_KEY - the record did not appear to be a removed record.
       Specifically, a record query of funk for rec's (xid,key) pair did
       not return rec. Also, the record was never published.
*/
int
fd_funkier_rec_forget( fd_funkier_t *      funk,
                       fd_funkier_rec_t ** recs,
                       ulong recs_cnt );

/* Iterator which walks all records in all transactions */

struct fd_funkier_all_iter {
  fd_funkier_rec_map_t rec_map;
  ulong chain_cnt;
  ulong chain_idx;
  fd_funkier_rec_map_iter_t rec_map_iter;
};

typedef struct fd_funkier_all_iter fd_funkier_all_iter_t;

void fd_funkier_all_iter_new( fd_funkier_t * funk, fd_funkier_all_iter_t * iter );

int fd_funkier_all_iter_done( fd_funkier_all_iter_t * iter );

void fd_funkier_all_iter_next( fd_funkier_all_iter_t * iter );

fd_funkier_rec_t const * fd_funkier_all_iter_ele_const( fd_funkier_all_iter_t * iter );

/* Misc */

#ifdef FD_FUNKIER_HANDHOLDING
/* fd_funkier_rec_verify verifies the record map.  Returns FD_FUNKIER_SUCCESS
   if the record map appears intact and FD_FUNKIER_ERR_INVAL if not (logs
   details).  Meant to be called as part of fd_funkier_verify.  As such, it
   assumes funk is non-NULL, fd_funkier_{wksp,txn_map,rec_map} have been
   verified to work and the txn_map has been verified. */

int
fd_funkier_rec_verify( fd_funkier_t * funk );
#endif

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_funk_fd_funkier_rec_h */
