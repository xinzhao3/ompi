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


#endif // COMMON_UCX_INTERNAL_H
