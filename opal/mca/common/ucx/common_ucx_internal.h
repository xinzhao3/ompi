#ifndef COMMON_UCX_INTERNAL_H
#define COMMON_UCX_INTERNAL_H

#include "opal_config.h"
#include "common_ucx.h"

typedef struct  {
    opal_mutex_t mutex;
    ucp_worker_h worker;
    ucp_ep_h *endpoints;
    size_t comm_size;
} _worker_info_t;

typedef struct {
    int ctx_id;
    // TODO: make sure that this is being set by external thread
    int is_freed;
    opal_common_ucx_ctx_t *gctx;
    _worker_info_t *winfo;
} _tlocal_ctx_t;

typedef struct {
    _worker_info_t *worker;
    ucp_rkey_h *rkeys;
} _mem_info_t;

typedef struct {
    int mem_id;
    int is_freed;
    opal_common_ucx_mem_t *gmem;
    _mem_info_t *mem;
} _tlocal_mem_t;

typedef struct {
    opal_list_item_t super;
    _worker_info_t *ptr;
} _idle_list_item_t;
OBJ_CLASS_DECLARATION(_idle_list_item_t);


typedef struct {
    opal_list_item_t super;
    _tlocal_ctx_t *ptr;
} _worker_list_item_t;
OBJ_CLASS_DECLARATION(_worker_list_item_t);

typedef struct {
    opal_list_item_t super;
    _tlocal_mem_t *ptr;
} _mem_region_list_item_t;
OBJ_CLASS_DECLARATION(_mem_region_list_item_t);

/* thread-local table */
typedef struct {
    opal_list_item_t super;
    opal_common_ucx_wpool_t *wpool;
    _tlocal_ctx_t **ctx_tbl;
    size_t ctx_tbl_size;
    _tlocal_mem_t **mem_tbl;
    size_t mem_tbl_size;
} _tlocal_table_t;

OBJ_CLASS_DECLARATION(_tlocal_table_t);



static int _tlocal_tls_ctxtbl_extend(_tlocal_table_t *tbl, size_t append);
static int _tlocal_tls_memtbl_extend(_tlocal_table_t *tbl, size_t append);
static _tlocal_table_t* _common_ucx_tls_init(opal_common_ucx_wpool_t *wpool);
static void _common_ucx_tls_cleanup(_tlocal_table_t *tls);
static inline _tlocal_ctx_t *_tlocal_ctx_search(_tlocal_table_t *tls, int ctx_id);
static int _tlocal_ctx_record_cleanup(_tlocal_ctx_t *ctx_rec);
static _tlocal_ctx_t *_tlocal_add_ctx(_tlocal_table_t *tls, opal_common_ucx_ctx_t *ctx);
static int _tlocal_ctx_connect(_tlocal_ctx_t *ctx, int target);
static int _tlocal_ctx_release(opal_common_ucx_ctx_t *ctx);
static inline _tlocal_mem_t *_tlocal_search_mem(_tlocal_table_t *tls, int mem_id);
static _tlocal_mem_t *_tlocal_add_mem(_tlocal_table_t *tls, opal_common_ucx_mem_t *mem);
static int _tlocal_mem_create_rkey(_tlocal_mem_t *mem_rec, ucp_ep_h ep, int target);
// TOD: Return the error from it
static void _tlocal_mem_record_cleanup(_tlocal_mem_t *mem_rec);

static ucp_worker_h _create_ctx_worker(opal_common_ucx_wpool_t *wpool);
static int _wpool_idle_put(opal_common_ucx_wpool_t *wpool,
                           _worker_info_t *winfo);
static void _cleanup_tlocal(void *arg);



#endif // COMMON_UCX_INTERNAL_H
