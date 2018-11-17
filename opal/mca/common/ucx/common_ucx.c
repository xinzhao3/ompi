/*
 * Copyright (C) Mellanox Technologies Ltd. 2018. ALL RIGHTS RESERVED.
 * $COPYRIGHT$
 *
 * Additional copyrights may follow
 *
 * $HEADER$
 */

#include "opal_config.h"

#include "common_ucx.h"
#include "opal/mca/base/mca_base_var.h"
#include "opal/mca/base/mca_base_framework.h"
#include "opal/mca/pmix/pmix.h"
#include "opal/memoryhooks/memory.h"

#include <ucm/api/ucm.h>
#include <pthread.h>

/***********************************************************************/

typedef struct  {
    opal_mutex_t mutex;
    ucp_worker_h worker;
    ucp_ep_h *endpoints;
    size_t comm_size;
} _worker_info_t;


typedef struct {
    int ctx_id;
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
OBJ_CLASS_INSTANCE(_idle_list_item_t, opal_list_item_t, NULL, NULL);

typedef struct {
    opal_list_item_t super;
    _tlocal_ctx_t *ptr;
} _worker_list_item_t;

OBJ_CLASS_DECLARATION(_worker_list_item_t);
OBJ_CLASS_INSTANCE(_worker_list_item_t, opal_list_item_t, NULL, NULL);

typedef struct {
    opal_list_item_t super;
    _tlocal_mem_t *ptr;
} _mem_region_list_item_t;

OBJ_CLASS_DECLARATION(_mem_region_list_item_t);
OBJ_CLASS_INSTANCE(_mem_region_list_item_t, opal_list_item_t, NULL, NULL);

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
OBJ_CLASS_INSTANCE(_tlocal_table_t, opal_list_item_t, NULL, NULL);

static pthread_key_t _tlocal_key = {0};


#define FDBG
#ifdef FDBG
__thread FILE *tls_pf = NULL;
__thread int initialized = 0;

#include <sys/syscall.h>

void init_tls_dbg(void)
{
    if( !initialized ) {
        int tid = syscall(__NR_gettid);
        char hname[128];
        gethostname(hname, 127);
        char fname[128];

        sprintf(fname, "%s.%d.log", hname, tid);
        tls_pf = fopen(fname, "w");
        initialized = 1;
    }
}

#define DBG_OUT(...)                \
{                                   \
    init_tls_dbg();                 \
    fprintf(tls_pf, __VA_ARGS__);    \
}

#else
#define DBG_OUT(...)
#endif


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



/***********************************************************************/

extern mca_base_framework_t opal_memory_base_framework;

opal_common_ucx_module_t opal_common_ucx = {
    .verbose             = 0,
    .progress_iterations = 100,
    .registered          = 0,
    .opal_mem_hooks      = 0
};

static void opal_common_ucx_mem_release_cb(void *buf, size_t length,
                                           void *cbdata, bool from_alloc)
{
    ucm_vm_munmap(buf, length);
}

OPAL_DECLSPEC void opal_common_ucx_mca_var_register(const mca_base_component_t *component)
{
    static int registered = 0;
    static int hook_index;
    static int verbose_index;
    static int progress_index;
    if (!registered) {
        verbose_index = mca_base_var_register("opal", "opal_common", "ucx", "verbose",
                                              "Verbose level of the UCX components",
                                              MCA_BASE_VAR_TYPE_INT, NULL, 0,
                                              MCA_BASE_VAR_FLAG_SETTABLE, OPAL_INFO_LVL_3,
                                              MCA_BASE_VAR_SCOPE_LOCAL,
                                              &opal_common_ucx.verbose);
        progress_index = mca_base_var_register("opal", "opal_common", "ucx", "progress_iterations",
                                               "Set number of calls of internal UCX progress "
                                               "calls per opal_progress call",
                                               MCA_BASE_VAR_TYPE_INT, NULL, 0,
                                               MCA_BASE_VAR_FLAG_SETTABLE, OPAL_INFO_LVL_3,
                                               MCA_BASE_VAR_SCOPE_LOCAL,
                                               &opal_common_ucx.progress_iterations);
        hook_index = mca_base_var_register("opal", "opal_common", "ucx", "opal_mem_hooks",
                                           "Use OPAL memory hooks, instead of UCX internal "
                                           "memory hooks", MCA_BASE_VAR_TYPE_BOOL, NULL, 0, 0,
                                           OPAL_INFO_LVL_3,
                                           MCA_BASE_VAR_SCOPE_LOCAL,
                                           &opal_common_ucx.opal_mem_hooks);
        registered = 1;
    }
    if (component) {
        mca_base_var_register_synonym(verbose_index, component->mca_project_name,
                                      component->mca_type_name,
                                      component->mca_component_name,
                                      "verbose", 0);
        mca_base_var_register_synonym(progress_index, component->mca_project_name,
                                      component->mca_type_name,
                                      component->mca_component_name,
                                      "progress_iterations", 0);
        mca_base_var_register_synonym(hook_index, component->mca_project_name,
                                      component->mca_type_name,
                                      component->mca_component_name,
                                      "opal_mem_hooks", 0);
    }
}

OPAL_DECLSPEC void opal_common_ucx_mca_register(void)
{
    int ret;

    opal_common_ucx.registered++;
    if (opal_common_ucx.registered > 1) {
        /* process once */
        return;
    }

    opal_common_ucx.output = opal_output_open(NULL);
    opal_output_set_verbosity(opal_common_ucx.output, opal_common_ucx.verbose);

    ret = mca_base_framework_open(&opal_memory_base_framework, 0);
    if (OPAL_SUCCESS != ret) {
        /* failed to initialize memory framework - just exit */
        MCA_COMMON_UCX_VERBOSE(1, "failed to initialize memory base framework: %d, "
                                  "memory hooks will not be used", ret);
        return;
    }

    /* Set memory hooks */
    if (opal_common_ucx.opal_mem_hooks &&
        (OPAL_MEMORY_FREE_SUPPORT | OPAL_MEMORY_MUNMAP_SUPPORT) ==
        ((OPAL_MEMORY_FREE_SUPPORT | OPAL_MEMORY_MUNMAP_SUPPORT) &
         opal_mem_hooks_support_level()))
    {
        MCA_COMMON_UCX_VERBOSE(1, "%s", "using OPAL memory hooks as external events");
        ucm_set_external_event(UCM_EVENT_VM_UNMAPPED);
        opal_mem_hooks_register_release(opal_common_ucx_mem_release_cb, NULL);
    }
}

OPAL_DECLSPEC void opal_common_ucx_mca_deregister(void)
{
    /* unregister only on last deregister */
    opal_common_ucx.registered--;
    assert(opal_common_ucx.registered >= 0);
    if (opal_common_ucx.registered) {
        return;
    }
    opal_mem_hooks_unregister_release(opal_common_ucx_mem_release_cb);
    opal_output_close(opal_common_ucx.output);
}

void opal_common_ucx_empty_complete_cb(void *request, ucs_status_t status)
{
}

static void opal_common_ucx_mca_fence_complete_cb(int status, void *fenced)
{
    *(int*)fenced = 1;
}

OPAL_DECLSPEC int opal_common_ucx_mca_pmix_fence(ucp_worker_h worker)
{
    volatile int fenced = 0;
    int ret = OPAL_SUCCESS;

    if (OPAL_SUCCESS != (ret = opal_pmix.fence_nb(NULL, 0,
                    opal_common_ucx_mca_fence_complete_cb, (void*)&fenced))){
        return ret;
    }

    while (!fenced) {
        ucp_worker_progress(worker);
    }

    return ret;
}


static void opal_common_ucx_wait_all_requests(void **reqs, int count, ucp_worker_h worker)
{
    int i;

    MCA_COMMON_UCX_VERBOSE(2, "waiting for %d disconnect requests", count);
    for (i = 0; i < count; ++i) {
        opal_common_ucx_wait_request(reqs[i], worker, "ucp_disconnect_nb");
        reqs[i] = NULL;
    }
}

OPAL_DECLSPEC int opal_common_ucx_del_procs(opal_common_ucx_del_proc_t *procs, size_t count,
                                            size_t my_rank, size_t max_disconnect, ucp_worker_h worker)
{
    size_t num_reqs;
    size_t max_reqs;
    void *dreq, **dreqs;
    size_t i;
    size_t n;
    int ret = OPAL_SUCCESS;

    MCA_COMMON_UCX_ASSERT(procs || !count);
    MCA_COMMON_UCX_ASSERT(max_disconnect > 0);

    max_reqs = (max_disconnect > count) ? count : max_disconnect;

    dreqs = malloc(sizeof(*dreqs) * max_reqs);
    if (dreqs == NULL) {
        return OPAL_ERR_OUT_OF_RESOURCE;
    }

    num_reqs = 0;

    for (i = 0; i < count; ++i) {
        n = (i + my_rank) % count;
        if (procs[n].ep == NULL) {
            continue;
        }

        MCA_COMMON_UCX_VERBOSE(2, "disconnecting from rank %zu", procs[n].vpid);
        dreq = ucp_disconnect_nb(procs[n].ep);
        if (dreq != NULL) {
            if (UCS_PTR_IS_ERR(dreq)) {
                MCA_COMMON_UCX_ERROR("ucp_disconnect_nb(%zu) failed: %s", procs[n].vpid,
                                     ucs_status_string(UCS_PTR_STATUS(dreq)));
                continue;
            } else {
                dreqs[num_reqs++] = dreq;
                if (num_reqs >= max_disconnect) {
                    opal_common_ucx_wait_all_requests(dreqs, num_reqs, worker);
                    num_reqs = 0;
                }
            }
        }
    }
    /* num_reqs == 0 is processed by opal_common_ucx_wait_all_requests routine,
     * so suppress coverity warning */
    /* coverity[uninit_use_in_call] */
    opal_common_ucx_wait_all_requests(dreqs, num_reqs, worker);
    free(dreqs);

    if (OPAL_SUCCESS != (ret = opal_common_ucx_mca_pmix_fence(worker))) {
        return ret;
    }

    return OPAL_SUCCESS;
}

/***********************************************************************/

static inline void _cleanup_tlocal(void *arg)
{
    _tlocal_table_t *item = NULL, *next;
    _tlocal_table_t *tls = (_tlocal_table_t *)arg;
    opal_common_ucx_wpool_t *wpool = NULL;

    DBG_OUT("_cleanup_tlocal: start\n");

    if (NULL == tls) {
        return;
    }

    wpool = tls->wpool;
    /* 1. Remove us from tls_list */
    tls->wpool = wpool;
    opal_mutex_lock(&wpool->mutex);
    OPAL_LIST_FOREACH_SAFE(item, next, &wpool->tls_list, _tlocal_table_t) {
        if (item == tls) {
            opal_list_remove_item(&wpool->tls_list, &item->super);
            _common_ucx_tls_cleanup(tls);
            break;
        }
    }
    opal_mutex_unlock(&wpool->mutex);
}

static
ucp_worker_h _create_ctx_worker(opal_common_ucx_wpool_t *wpool)
{
    ucp_worker_params_t worker_params;
    ucp_worker_h worker;
    ucs_status_t status;

    memset(&worker_params, 0, sizeof(worker_params));
    worker_params.field_mask = UCP_WORKER_PARAM_FIELD_THREAD_MODE;
    worker_params.thread_mode = UCS_THREAD_MODE_SINGLE;
    status = ucp_worker_create(wpool->ucp_ctx, &worker_params, &worker);
    if (UCS_OK != status) {
    	MCA_COMMON_UCX_VERBOSE(1, "ucp_worker_create failed: %d", status);
        return NULL;
    }

    DBG_OUT("_create_ctx_worker: worker = %p\n", (void *)worker);

    return worker;
}

static
int _wpool_add_to_idle(opal_common_ucx_wpool_t *wpool, _worker_info_t *winfo)
{
    _idle_list_item_t *item;

    if(winfo->comm_size != 0) {
        size_t i;
        for (i = 0; i < winfo->comm_size; i++) {
            ucp_ep_destroy(winfo->endpoints[i]);
        }
        free(winfo->endpoints);
        winfo->endpoints = NULL;
        winfo->comm_size = 0;
    }

    item = OBJ_NEW(_idle_list_item_t);
    if (NULL == item) {
        return OPAL_ERR_OUT_OF_RESOURCE;
    }
    item->ptr = winfo;

    opal_mutex_lock(&wpool->mutex);
    opal_list_append(&wpool->idle_workers, &item->super);
    opal_mutex_unlock(&wpool->mutex);

    DBG_OUT("_wpool_add_to_idle: wpool = %p winfo = %p\n", (void *)wpool, (void *)winfo);
    return OPAL_SUCCESS;
}

static
_worker_info_t* _wpool_remove_from_idle(opal_common_ucx_wpool_t *wpool)
{
    _worker_info_t *wkr = NULL;
    _idle_list_item_t *item = NULL;

    opal_mutex_lock(&wpool->mutex);
    if (!opal_list_is_empty(&wpool->idle_workers)) {
        item = (_idle_list_item_t *)opal_list_get_first(&wpool->idle_workers);
        opal_list_remove_item(&wpool->idle_workers, &item->super);
    }
    opal_mutex_unlock(&wpool->mutex);

    if (item != NULL) {
        wkr = item->ptr;
        OBJ_RELEASE(item);
    }

    DBG_OUT("_wpool_remove_from_idle: wpool = %p\n", (void *)wpool);
    return wkr;
}

OPAL_DECLSPEC
opal_common_ucx_wpool_t * opal_common_ucx_wpool_allocate(void)
{
    opal_common_ucx_wpool_t *ptr = calloc(1, sizeof(opal_common_ucx_wpool_t));
    ptr->refcnt = 0;

    DBG_OUT("opal_common_ucx_wpool_allocate: wpool = %p\n", (void *)ptr);
    return ptr;
}

OPAL_DECLSPEC
void opal_common_ucx_wpool_free(opal_common_ucx_wpool_t *wpool)
{
    assert(wpool->refcnt == 0);

    DBG_OUT("opal_common_ucx_wpool_free: wpool = %p\n", (void *)wpool);

    free(wpool);
}

OPAL_DECLSPEC
int opal_common_ucx_wpool_init(opal_common_ucx_wpool_t *wpool,
                               int proc_world_size,
                               ucp_request_init_callback_t req_init_ptr,
                               size_t req_size, bool enable_mt)
{
    ucp_config_t *config = NULL;
    ucp_params_t context_params;
    _worker_info_t *wkr;
    ucs_status_t status;
    int rc = OPAL_SUCCESS;

    if (wpool->refcnt > 0) {
        wpool->refcnt++;
        return rc;
    }

    wpool->refcnt++;
    wpool->cur_ctxid = wpool->cur_memid = 0;
    OBJ_CONSTRUCT(&wpool->mutex, opal_mutex_t);
    OBJ_CONSTRUCT(&wpool->tls_list, opal_list_t);

    status = ucp_config_read("MPI", NULL, &config);
    if (UCS_OK != status) {
        MCA_COMMON_UCX_VERBOSE(1, "ucp_config_read failed: %d", status);
        return OPAL_ERROR;
    }

    /* initialize UCP context */
    memset(&context_params, 0, sizeof(context_params));
    context_params.field_mask = UCP_PARAM_FIELD_FEATURES |
                                UCP_PARAM_FIELD_MT_WORKERS_SHARED |
                                UCP_PARAM_FIELD_ESTIMATED_NUM_EPS |
                                UCP_PARAM_FIELD_REQUEST_INIT |
                                UCP_PARAM_FIELD_REQUEST_SIZE;
    context_params.features = UCP_FEATURE_RMA | UCP_FEATURE_AMO32 | UCP_FEATURE_AMO64;
    context_params.mt_workers_shared = (enable_mt ? 1 : 0);
    context_params.estimated_num_eps = proc_world_size;
    context_params.request_init = req_init_ptr;
    context_params.request_size = req_size;

    status = ucp_init(&context_params, config, &wpool->ucp_ctx);
    ucp_config_release(config);
    if (UCS_OK != status) {
        MCA_COMMON_UCX_VERBOSE(1, "ucp_init failed: %d", status);
        rc = OPAL_ERROR;
        goto err_ucp_init;
    }

    /* create recv worker and add to idle pool */
    OBJ_CONSTRUCT(&wpool->idle_workers, opal_list_t);
    wpool->recv_worker = _create_ctx_worker(wpool);
    if (wpool->recv_worker == NULL) {
        MCA_COMMON_UCX_VERBOSE(1, "_create_ctx_worker failed");
        rc = OPAL_ERROR;
        goto err_worker_create;
    }

    wkr = calloc(1, sizeof(_worker_info_t));
    OBJ_CONSTRUCT(&wkr->mutex, opal_mutex_t);

    wkr->worker = wpool->recv_worker;
    wkr->endpoints = NULL;
    wkr->comm_size = 0;

    status = ucp_worker_get_address(wpool->recv_worker,
                                    &wpool->recv_waddr, &wpool->recv_waddr_len);
    if (status != UCS_OK) {
        MCA_COMMON_UCX_VERBOSE(1, "ucp_worker_get_address failed: %d", status);
        rc = OPAL_ERROR;
        goto err_get_addr;
    }

    rc = _wpool_add_to_idle(wpool, wkr);
    if (rc) {
        goto err_wpool_add;
    }

    pthread_key_create(&_tlocal_key, _cleanup_tlocal);

    DBG_OUT("opal_common_ucx_wpool_init: wpool = %p\n", (void *)wpool);
    return rc;

err_wpool_add:
    free(wpool->recv_waddr);
err_get_addr:
    if (NULL != wpool->recv_worker) {
        ucp_worker_destroy(wpool->recv_worker);
    }
 err_worker_create:
    ucp_cleanup(wpool->ucp_ctx);
 err_ucp_init:
    return rc;
}

OPAL_DECLSPEC
void opal_common_ucx_wpool_finalize(opal_common_ucx_wpool_t *wpool)
{
    _tlocal_table_t *tls_item = NULL, *tls_next;

    wpool->refcnt--;
    if (wpool->refcnt > 0) {
        DBG_OUT("opal_common_ucx_wpool_finalize: wpool = %p\n", (void *)wpool);
        return;
    }

    pthread_key_delete(_tlocal_key);

    opal_mutex_lock(&wpool->mutex);
    OPAL_LIST_FOREACH_SAFE(tls_item, tls_next, &wpool->tls_list, _tlocal_table_t) {
        opal_list_remove_item(&wpool->tls_list, &tls_item->super);
        _common_ucx_tls_cleanup(tls_item);
    }

    /* Go over the list, free idle list items */
    if (!opal_list_is_empty(&wpool->idle_workers)) {
        _idle_list_item_t *item, *next;
        OPAL_LIST_FOREACH_SAFE(item, next, &wpool->idle_workers, _idle_list_item_t) {
            _worker_info_t *curr_worker;
            opal_list_remove_item(&wpool->idle_workers, &item->super);
            curr_worker = item->ptr;
            OBJ_DESTRUCT(&curr_worker->mutex);
            ucp_worker_destroy(curr_worker->worker);
            OBJ_RELEASE(curr_worker);
            OBJ_RELEASE(item);
        }
    }
    opal_mutex_unlock(&wpool->mutex);

    OBJ_DESTRUCT(&wpool->idle_workers);
    OBJ_DESTRUCT(&wpool->tls_list);
    OBJ_DESTRUCT(&wpool->mutex);
    ucp_worker_release_address(wpool->recv_worker, wpool->recv_waddr);
    ucp_worker_destroy(wpool->recv_worker);
    ucp_cleanup(wpool->ucp_ctx);
    DBG_OUT("opal_common_ucx_wpool_finalize: wpool = %p\n", (void *)wpool);
    return;
}

OPAL_DECLSPEC
int opal_common_ucx_ctx_create(opal_common_ucx_wpool_t *wpool, int comm_size,
                               opal_common_ucx_exchange_func_t exchange_func,
                               void *exchange_metadata,
                               opal_common_ucx_ctx_t **ctx_ptr)
{
    opal_common_ucx_ctx_t *ctx = calloc(1, sizeof(*ctx));
    int ret = OPAL_SUCCESS;

    ctx->ctx_id = OPAL_ATOMIC_ADD_FETCH32(&ctx->ctx_id, 1);

    OBJ_CONSTRUCT(&ctx->mutex, opal_mutex_t);
    OBJ_CONSTRUCT(&ctx->workers, opal_list_t);
    ctx->wpool = wpool;
    ctx->comm_size = comm_size;

    ctx->recv_worker_addrs = NULL;
    ctx->recv_worker_displs = NULL;
    ret = exchange_func(wpool->recv_waddr, wpool->recv_waddr_len,
                        &ctx->recv_worker_addrs,
                        &ctx->recv_worker_displs, exchange_metadata);
    if (ret != OPAL_SUCCESS) {
        goto error;
    }

    (*ctx_ptr) = ctx;
    DBG_OUT("opal_common_ucx_ctx_create: wpool = %p, (*ctx_ptr) = %p\n", (void *)wpool, (void *)(*ctx_ptr));
    return ret;

 error:
    OBJ_DESTRUCT(&ctx->mutex);
    OBJ_DESTRUCT(&ctx->workers);
    free(ctx);
    (*ctx_ptr) = NULL;
    return ret;
}

static void _common_ucx_ctx_free(opal_common_ucx_ctx_t *ctx)
{
    free(ctx->recv_worker_addrs);
    free(ctx->recv_worker_displs);
    OBJ_DESTRUCT(&ctx->mutex);
    OBJ_DESTRUCT(&ctx->workers);
    DBG_OUT("_common_ucx_ctx_free: ctx = %p\n", (void *)ctx);
    free(ctx);
}

OPAL_DECLSPEC void
opal_common_ucx_ctx_release(opal_common_ucx_ctx_t *ctx)
{
    // TODO: implement
    DBG_OUT("opal_common_ucx_ctx_release: ctx = %p\n", (void *)ctx);
    _tlocal_ctx_release(ctx);
}

static int
_common_ucx_ctx_append(opal_common_ucx_ctx_t *ctx, _tlocal_ctx_t *ctx_rec)
{
    _worker_list_item_t *item = OBJ_NEW(_worker_list_item_t);
    if (NULL == item) {
        return OPAL_ERR_OUT_OF_RESOURCE;
    }
    item->ptr = ctx_rec;
    opal_mutex_lock(&ctx->mutex);
    opal_list_append(&ctx->workers, &item->super);
    opal_mutex_unlock(&ctx->mutex);
    DBG_OUT("_common_ucx_ctx_append: ctx = %p, ctx_rec = %p\n", (void *)ctx, (void *)ctx_rec);
    return OPAL_SUCCESS;
}

static void
_common_ucx_ctx_remove(opal_common_ucx_ctx_t *ctx, _tlocal_ctx_t *ctx_rec)
{
    int can_free = 0;
    _worker_list_item_t *item = NULL, *next;

    opal_mutex_lock(&ctx->mutex);
    OPAL_LIST_FOREACH_SAFE(item, next, &ctx->workers, _worker_list_item_t) {
        if (ctx_rec == item->ptr) {
            opal_list_remove_item(&ctx->workers, &item->super);
            OBJ_RELEASE(item);
            break;
        }
    }
    if (0 == opal_list_get_size(&ctx->workers)) {
        can_free = 1;
    }
    opal_mutex_unlock(&ctx->mutex);

    if (can_free) {
        /* All references to this data structure are removed
         * we can safely release communication context structure */
        _common_ucx_ctx_free(ctx);
    }
    DBG_OUT("_common_ucx_ctx_remove: ctx = %p, ctx_rec = %p\n", (void *)ctx, (void *)ctx_rec);
    return;
}

static int _comm_ucx_mem_map(opal_common_ucx_wpool_t *wpool,
                             void **base, size_t size, ucp_mem_h *memh_ptr,
                             opal_common_ucx_mem_type_t mem_type)
{
    ucp_mem_map_params_t mem_params;
    ucp_mem_attr_t mem_attrs;
    ucs_status_t status;
    int ret = OPAL_SUCCESS;

    memset(&mem_params, 0, sizeof(ucp_mem_map_params_t));
    mem_params.field_mask = UCP_MEM_MAP_PARAM_FIELD_ADDRESS |
                            UCP_MEM_MAP_PARAM_FIELD_LENGTH |
                            UCP_MEM_MAP_PARAM_FIELD_FLAGS;
    mem_params.length = size;
    if (mem_type == OPAL_COMMON_UCX_MEM_ALLOCATE_MAP) {
        mem_params.address = NULL;
        mem_params.flags = UCP_MEM_MAP_ALLOCATE;
    } else {
        mem_params.address = (*base);
    }

    status = ucp_mem_map(wpool->ucp_ctx, &mem_params, memh_ptr);
    if (status != UCS_OK) {
        MCA_COMMON_UCX_VERBOSE(1, "ucp_mem_map failed: %d", status);
        ret = OPAL_ERROR;
        return ret;
    }
    DBG_OUT("_comm_ucx_mem_map(after ucp_mem_map): memh = %p\n", (void *)(*memh_ptr));

    mem_attrs.field_mask = UCP_MEM_ATTR_FIELD_ADDRESS | UCP_MEM_ATTR_FIELD_LENGTH;
    status = ucp_mem_query((*memh_ptr), &mem_attrs);
    if (status != UCS_OK) {
        MCA_COMMON_UCX_VERBOSE(1, "ucp_mem_query failed: %d", status);
        ret = OPAL_ERROR;
        goto error;
    }
    DBG_OUT("_comm_ucx_mem_map(after ucp_mem_query): memh = %p\n", (void *)(*memh_ptr));

    assert(mem_attrs.length >= size);
    if (mem_type != OPAL_COMMON_UCX_MEM_ALLOCATE_MAP) {
        assert(mem_attrs.address == (*base));
    } else {
        (*base) = mem_attrs.address;
    }

    DBG_OUT("_comm_ucx_mem_map(end): wpool = %p, addr = %p size = %d memh = %p\n",
    	   (void *)wpool, (void *)(*base), (int)size, (void *)(*memh_ptr));
    return ret;
 error:
    ucp_mem_unmap(wpool->ucp_ctx, (*memh_ptr));
    return ret;
}


OPAL_DECLSPEC
int opal_common_ucx_mem_create(opal_common_ucx_ctx_t *ctx, int comm_size,
                               void **mem_base, size_t mem_size,
                               opal_common_ucx_mem_type_t mem_type,
                               opal_common_ucx_exchange_func_t exchange_func,
                               void *exchange_metadata,
                               opal_common_ucx_mem_t **mem_ptr)
{
    opal_common_ucx_mem_t *mem = calloc(1, sizeof(*mem));
    void *rkey_addr = NULL;
    size_t rkey_addr_len;
    ucs_status_t status;
    int ret = OPAL_SUCCESS;

    mem->mem_id = OPAL_ATOMIC_ADD_FETCH32(&mem->mem_id, 1);
    OBJ_CONSTRUCT(&mem->mutex, opal_mutex_t);
    OBJ_CONSTRUCT(&mem->registrations, opal_list_t);
    mem->ctx = ctx;
    mem->mem_addrs = NULL;
    mem->mem_displs = NULL;

    ret = _comm_ucx_mem_map(ctx->wpool, mem_base, mem_size, &mem->memh, mem_type);
    if (ret != OPAL_SUCCESS) {
        MCA_COMMON_UCX_VERBOSE(1, "_comm_ucx_mem_map failed: %d", ret);
        goto error_mem_map;
    }
    DBG_OUT("opal_common_ucx_mem_create(after _comm_ucx_mem_map): base = %p, memh = %p\n",
    		(void *)(*mem_base), (void *)(mem->memh));

    status = ucp_rkey_pack(ctx->wpool->ucp_ctx, mem->memh,
                           &rkey_addr, &rkey_addr_len);
    if (status != UCS_OK) {
        MCA_COMMON_UCX_VERBOSE(1, "ucp_rkey_pack failed: %d", status);
        ret = OPAL_ERROR;
        goto error_rkey_pack;
    }
    DBG_OUT("opal_common_ucx_mem_create(after ucp_rkey_pack): rkey_addr = %p, rkey_addr_len = %d\n",
    		(void *)rkey_addr, (int)rkey_addr_len);

    ret = exchange_func(rkey_addr, rkey_addr_len,
                        &mem->mem_addrs, &mem->mem_displs, exchange_metadata);
    DBG_OUT("opal_common_ucx_mem_create(after exchange_func): rkey_addr = %p, rkey_addr_len = %d mem_addrs = %p mem_displs = %p\n",
    		(void *)rkey_addr, (int)rkey_addr_len, (void *)mem->mem_addrs, (void *)mem->mem_displs);

    ucp_rkey_buffer_release(rkey_addr);
    if (ret != OPAL_SUCCESS) {
        goto error_rkey_pack;
    }

    (*mem_ptr) = mem;

    DBG_OUT("opal_common_ucx_mem_create(end): mem = %p\n", (void *)mem);
    return ret;

 error_rkey_pack:
    ucp_mem_unmap(ctx->wpool->ucp_ctx, mem->memh);
 error_mem_map:
    OBJ_DESTRUCT(&mem->mutex);
    OBJ_DESTRUCT(&mem->registrations);
    free(mem);
    (*mem_ptr) = NULL;
    return ret;
}

static void _common_ucx_mem_free(opal_common_ucx_mem_t *mem)
{
    free(mem->mem_addrs);
    free(mem->mem_displs);
    ucp_mem_unmap(mem->ctx->wpool->ucp_ctx, mem->memh);
    OBJ_DESTRUCT(&mem->mutex);
    OBJ_DESTRUCT(&mem->registrations);
    DBG_OUT("_common_ucx_mem_free: mem = %p\n", (void *)mem);
    free(mem);
}

static int
_common_ucx_mem_append(opal_common_ucx_mem_t *mem,
                       _tlocal_mem_t *mem_rec)
{
    _mem_region_list_item_t *item = OBJ_NEW(_mem_region_list_item_t);
    if (NULL == item) {
        return OPAL_ERR_OUT_OF_RESOURCE;
    }
    item->ptr = mem_rec;
    opal_mutex_lock(&mem->mutex);
    opal_list_append(&mem->registrations, &item->super);
    opal_mutex_unlock(&mem->mutex);
    DBG_OUT("_common_ucx_mem_append: mem = %p, mem_rec = %p\n", (void *)mem, (void *)mem_rec);
    return OPAL_SUCCESS;
}

static void
_common_ucx_mem_remove(opal_common_ucx_mem_t *mem, _tlocal_mem_t *mem_rec)
{
    int can_free = 0;
    _mem_region_list_item_t *item = NULL, *next;

    opal_mutex_lock(&mem->mutex);
    OPAL_LIST_FOREACH_SAFE(item, next, &mem->registrations, _mem_region_list_item_t) {
        if (mem_rec == item->ptr) {
            opal_list_remove_item(&mem->registrations, &item->super);
            OBJ_RELEASE(item);
            break;
        }
    }
    if (0 == opal_list_get_size(&mem->registrations)) {
        can_free = 1;
    }
    opal_mutex_unlock(&mem->mutex);

    if (can_free) {
        /* All references to this data structure are removed
         * we can safely release communication context structure */
        _common_ucx_mem_free(mem);
    }
    DBG_OUT("_common_ucx_mem_remove(end): mem = %p mem_rec = %p\n", (void *)mem, (void *)mem_rec);
    return;
}


// TODO: don't want to inline this function
static _tlocal_table_t* _common_ucx_tls_init(opal_common_ucx_wpool_t *wpool)
{
    _tlocal_table_t *tls = OBJ_NEW(_tlocal_table_t);

    if (tls == NULL) {
        // return OPAL_ERR_OUT_OF_RESOURCE
        return NULL;
    }

    memset(tls, 0, sizeof(*tls));

    /* Add this TLS to the global wpool structure for future
     * cleanup purposes */
    tls->wpool = wpool;
    opal_mutex_lock(&wpool->mutex);
    opal_list_append(&wpool->tls_list, &tls->super);
    opal_mutex_unlock(&wpool->mutex);

    if(_tlocal_tls_ctxtbl_extend(tls, 4)){
        DBG_OUT("_tlocal_tls_ctxtbl_extend failed\n");
        // TODO: handle error
    }
    if(_tlocal_tls_memtbl_extend(tls, 4)) {
        DBG_OUT("_tlocal_tls_memtbl_extend failed\n");
        // TODO: handle error
    }

    pthread_setspecific(_tlocal_key, tls);
    DBG_OUT("_common_ucx_tls_init(end): wpool = %p\n", (void *)wpool);
    return tls;
}

static inline _tlocal_table_t *
_tlocal_get_tls(opal_common_ucx_wpool_t *wpool){
    _tlocal_table_t *tls = pthread_getspecific(_tlocal_key);
    if( OPAL_UNLIKELY(NULL == tls) ) {
        tls = _common_ucx_tls_init(wpool);
    }
    DBG_OUT("_tlocal_get_tls(end): wpool = %p tls = %p\n", (void *)wpool, (void *)tls);
    return tls;
}

_worker_list_item_t *item = NULL, *next;

// TODO: don't want to inline this function
static void _common_ucx_tls_cleanup(_tlocal_table_t *tls)
{
    size_t i, size;

    // Cleanup memory table
    size = tls->mem_tbl_size;
    for (i = 0; i < size; i++) {

        if (!tls->mem_tbl[i]->mem_id){
            continue;
        }
        _tlocal_mem_record_cleanup(tls->mem_tbl[i]);
        free(tls->mem_tbl[i]);
    }

    // Cleanup ctx table
    size = tls->ctx_tbl_size;
    for (i = 0; i < size; i++) {
        _tlocal_ctx_record_cleanup(tls->ctx_tbl[i]);
        free(tls->ctx_tbl[i]);
    }

    pthread_setspecific(_tlocal_key, NULL);
    DBG_OUT("_common_ucx_tls_cleanup(end): tls = %p\n", (void *)tls);

    OBJ_RELEASE(tls);

    return;
}



static int
_tlocal_tls_get_worker(_tlocal_table_t *tls, _worker_info_t **_winfo)
{
    _worker_info_t *winfo;
    *_winfo = NULL;
    winfo = _wpool_remove_from_idle(tls->wpool);
    if (!winfo) {
        winfo = calloc(1, sizeof(*winfo));
        if (!winfo) {
            return OPAL_ERR_OUT_OF_RESOURCE;
        }
        OBJ_CONSTRUCT(&winfo->mutex, opal_mutex_t);
        winfo->worker = _create_ctx_worker(tls->wpool);
        winfo->endpoints = NULL;
        winfo->comm_size = 0;
    }
    *_winfo = winfo;
    DBG_OUT("_tlocal_tls_get_worker(end): tls = %p winfo = %p\n", (void *)tls, (void *)winfo);

    return OPAL_SUCCESS;
}

static int
_tlocal_tls_ctxtbl_extend(_tlocal_table_t *tbl, size_t append)
{
    size_t i;
    size_t newsize = (tbl->ctx_tbl_size + append);
    tbl->ctx_tbl = realloc(tbl->ctx_tbl, newsize * sizeof(*tbl->ctx_tbl));
    for (i = tbl->ctx_tbl_size; i < newsize; i++) {
        tbl->ctx_tbl[i] = calloc(1, sizeof(*tbl->ctx_tbl[i]));
        if (NULL == tbl->ctx_tbl[i]) {
            return OPAL_ERR_OUT_OF_RESOURCE;
        }

    }
    tbl->ctx_tbl_size = newsize;
    DBG_OUT("_tlocal_tls_ctxtbl_extend(end): tbl = %p\n", (void *)tbl);
    return OPAL_SUCCESS;
}
static int
_tlocal_tls_memtbl_extend(_tlocal_table_t *tbl, size_t append)
{
    size_t i;
    size_t newsize = (tbl->mem_tbl_size + append);

    tbl->mem_tbl = realloc(tbl->mem_tbl, newsize * sizeof(*tbl->mem_tbl));
    for (i = tbl->mem_tbl_size; i < tbl->mem_tbl_size + append; i++) {
        tbl->mem_tbl[i] = calloc(1, sizeof(*tbl->mem_tbl[i]));
        if (NULL == tbl->mem_tbl[i]) {
            return OPAL_ERR_OUT_OF_RESOURCE;
        }
    }
    tbl->mem_tbl_size = newsize;
    DBG_OUT("_tlocal_tls_memtbl_extend(end): tbl = %p\n", (void *)tbl);
    return OPAL_SUCCESS;
}


static inline _tlocal_ctx_t *
_tlocal_ctx_search(_tlocal_table_t *tls, int ctx_id)
{
    size_t i;
    for(i=0; i<tls->ctx_tbl_size; i++) {
        if( tls->ctx_tbl[i]->ctx_id == ctx_id){
            return tls->ctx_tbl[i];
        }
    }
    DBG_OUT("_tlocal_ctx_search: tls = %p ctx_id = %d\n", (void *)tls, ctx_id);
    return NULL;
}

static int
_tlocal_ctx_record_cleanup(_tlocal_ctx_t *ctx_rec)
{
    int rc;
    if (!ctx_rec->is_freed) {
        return OPAL_SUCCESS;
    }
    /* Remove myself from the communication context structure
     * This may result in context release as we are using
     * delayed cleanup */
    _common_ucx_ctx_remove(ctx_rec->gctx, ctx_rec);

    /* Return the worker back to the
     * This may result in context release as we are using
     * delayed cleanup */
    rc = _wpool_add_to_idle(ctx_rec->gctx->wpool, ctx_rec->winfo);
    if (rc) {
        return rc;
    }
    memset(ctx_rec, 0, sizeof(*ctx_rec));
    DBG_OUT("_tlocal_cleanup_ctx_record(end): ctx_rec = %p\n", (void *)ctx_rec);
    return OPAL_SUCCESS;
}

// TODO: Don't want to inline this (slow path)
static _tlocal_ctx_t *
_tlocal_add_ctx(_tlocal_table_t *tls, opal_common_ucx_ctx_t *ctx)
{
    size_t i;
    int rc;

    /* Try to find available spot in the table */
    for (i=0; i<tls->ctx_tbl_size; i++) {
        if (0 == tls->ctx_tbl[i]->ctx_id) {
            /* Found clean record */
            break;
        }
        if (tls->ctx_tbl[i]->is_freed ) {
            /* Found dirty record, need to clean first */
            _tlocal_ctx_record_cleanup(tls->ctx_tbl[i]);
            break;
        }
    }

    if( tls->ctx_tbl_size >= i ){
        i = tls->ctx_tbl_size;
        rc = _tlocal_tls_ctxtbl_extend(tls, 4);
        if (rc) {
            //TODO: error out
            return NULL;
        }
    }
    tls->ctx_tbl[i]->ctx_id = ctx->ctx_id;
    tls->ctx_tbl[i]->gctx = ctx;
    rc = _tlocal_tls_get_worker(tls, &tls->ctx_tbl[i]->winfo);
    if (rc) {
        //TODO: error out
        return NULL;
    }
    DBG_OUT("_tlocal_add_ctx(after _tlocal_tls_get_worker): tls = %p winfo = %p\n",
    		(void *)tls, (void *)tls->ctx_tbl[i]->winfo);
    tls->ctx_tbl[i]->winfo->endpoints = calloc(ctx->comm_size, sizeof(ucp_ep_h));
    tls->ctx_tbl[i]->winfo->comm_size = ctx->comm_size;


    /* Make sure that we completed all the data structures before
             * placing the item to the list
             * NOTE: essentially we don't need this as list append is an
             * operation protected by mutex
             */
    opal_atomic_wmb();

    /* add this worker into the context list */
    rc = _common_ucx_ctx_append(ctx, tls->ctx_tbl[i]);
    if (rc) {
        //TODO: error out
        return NULL;
    }
    DBG_OUT("_tlocal_add_ctx(after _common_ucx_ctx_append): ctx = %p tls->ctx_tbl = %p\n",
    		(void *)ctx, (void *)tls->ctx_tbl);

    /* All good - return the record */
    return tls->ctx_tbl[i];
}

static int _tlocal_ctx_connect(_tlocal_ctx_t *ctx_rec, int target)
{
    ucp_ep_params_t ep_params;
    _worker_info_t *winfo = ctx_rec->winfo;
    opal_common_ucx_ctx_t *gctx = ctx_rec->gctx;
    ucs_status_t status;
    int displ;

    memset(&ep_params, 0, sizeof(ucp_ep_params_t));
    ep_params.field_mask = UCP_EP_PARAM_FIELD_REMOTE_ADDRESS;

    opal_mutex_lock(&winfo->mutex);
    displ = gctx->recv_worker_displs[target];
    ep_params.address = (ucp_address_t *)&(gctx->recv_worker_addrs[displ]);
    status = ucp_ep_create(winfo->worker, &ep_params, &winfo->endpoints[target]);
    if (status != UCS_OK) {
        opal_mutex_unlock(&winfo->mutex);
    	MCA_COMMON_UCX_VERBOSE(1, "ucp_ep_create failed: %d", status);
        return OPAL_ERROR;
    }
    DBG_OUT("_tlocal_ctx_connect(after ucp_ep_create): worker = %p ep = %p\n",
    		(void *)winfo->worker, (void *)winfo->endpoints[target]);
    opal_mutex_unlock(&winfo->mutex);
    return OPAL_SUCCESS;
}

static int _tlocal_ctx_release(opal_common_ucx_ctx_t *ctx)
{
    _tlocal_table_t * tls = _tlocal_get_tls(ctx->wpool);
    _tlocal_ctx_t *ctx_rec = _tlocal_ctx_search(tls, ctx->ctx_id);
    int rc = OPAL_SUCCESS;

    if (NULL == ctx_rec) {
        /* we haven't participated in this context */
        return OPAL_SUCCESS;
    }

    /* May free the ctx structure. Do not use it */
    _common_ucx_ctx_remove(ctx, ctx_rec);
    DBG_OUT("_tlocal_ctx_release(after _common_ucx_ctx_remove): ctx = %p ctx_rec = %p\n",
    		(void *)ctx, (void *)ctx_rec);
    rc = _wpool_add_to_idle(tls->wpool, ctx_rec->winfo);
    DBG_OUT("_tlocal_ctx_release(after _wpool_add_to_idle): wpool = %p winfo = %p\n",
    		(void *)tls->wpool, (void *)ctx_rec->winfo);

    ctx_rec->ctx_id = 0;
    ctx_rec->is_freed = 0;
    ctx_rec->gctx = NULL;
    ctx_rec->winfo = NULL;

    return rc;
}

static inline _tlocal_mem_t *
_tlocal_search_mem(_tlocal_table_t *tls, int mem_id)
{
    size_t i;
    DBG_OUT("_tlocal_search_mem(begin): tls = %p mem_id = %d\n",
    		(void *)tls, (int)mem_id);
    for(i=0; i<tls->mem_tbl_size; i++) {
        if( tls->mem_tbl[i]->mem_id == mem_id){
            return tls->mem_tbl[i];
        }
    }
    return NULL;
}


static void
_tlocal_mem_record_cleanup(_tlocal_mem_t *mem_rec)
{
    size_t i;
    if (!mem_rec->is_freed) {
        return;
    }
    /* Remove myself from the memory context structure
     * This may result in context release as we are using
     * delayed cleanup */
    _common_ucx_mem_remove(mem_rec->gmem, mem_rec);
    DBG_OUT("_tlocal_mem_record_cleanup(_common_ucx_mem_remove): gmem = %p mem_rec = %p\n",
    		(void *)mem_rec->gmem, (void *)mem_rec);

    for(i = 0; i < mem_rec->gmem->ctx->comm_size; i++) {
        if (mem_rec->mem->rkeys[i]) {
            ucp_rkey_destroy(mem_rec->mem->rkeys[i]);
            DBG_OUT("_tlocal_mem_record_cleanup(after ucp_rkey_destroy): rkey_entry = %p\n",
            		(void *)mem_rec->mem->rkeys[i]);
        }
    }

    free(mem_rec->mem->rkeys);
    free(mem_rec->mem);

    memset(mem_rec, 0, sizeof(*mem_rec));
}


// TODO: Don't want to inline this (slow path)
static _tlocal_mem_t *_tlocal_add_mem(_tlocal_table_t *tls,
                                       opal_common_ucx_mem_t *mem)
{
    size_t i;
    _tlocal_ctx_t *ctx_rec = NULL;
    int rc = OPAL_SUCCESS;

    /* Try to find available spot in the table */
    for (i=0; i<tls->mem_tbl_size; i++) {
        if (0 == tls->mem_tbl[i]->mem_id) {
            /* Found a clear record */
        }
        if (tls->mem_tbl[i]->is_freed) {
            /* Found a dirty record. Need to clean it first */
            _tlocal_mem_record_cleanup(tls->mem_tbl[i]);
            DBG_OUT("_tlocal_add_mem(after _tlocal_mem_record_cleanup): tls = %p mem_tbl_entry = %p\n",
            		(void *)tls, (void *)tls->mem_tbl[i]);
            break;
        }
    }

    if( tls->mem_tbl_size >= i ){
        i = tls->mem_tbl_size;
        rc = _tlocal_tls_memtbl_extend(tls, 4);
        if (rc != OPAL_SUCCESS) {
            //TODO: error out
            return NULL;
        }
        DBG_OUT("_tlocal_add_mem(after _tlocal_tls_memtbl_extend): tls = %p\n",
        		(void *)tls);
    }
    tls->mem_tbl[i]->mem_id = mem->mem_id;
    tls->mem_tbl[i]->gmem = mem;
    tls->mem_tbl[i]->is_freed = 0;
    tls->mem_tbl[i]->mem = calloc(1, sizeof(*tls->mem_tbl[i]->mem));
    ctx_rec = _tlocal_ctx_search(tls, mem->ctx->ctx_id);
    if (NULL == ctx_rec) {
        // TODO: act accordingly - cleanup
        return NULL;
    }
    DBG_OUT("_tlocal_add_mem(after _tlocal_ctx_search): tls = %p, ctx_id = %d\n",
    		(void *)tls, (int)mem->ctx->ctx_id);

    tls->mem_tbl[i]->mem->worker = ctx_rec->winfo;
    tls->mem_tbl[i]->mem->rkeys = calloc(mem->ctx->comm_size,
                                         sizeof(*tls->mem_tbl[i]->mem->rkeys));


    /* Make sure that we completed all the data structures before
     * placing the item to the list
     * NOTE: essentially we don't need this as list append is an
     * operation protected by mutex
     */
    opal_atomic_wmb();

    rc = _common_ucx_mem_append(mem, tls->mem_tbl[i]);
    if (rc) {
        // TODO: error handling
        return NULL;
    }
    DBG_OUT("_tlocal_add_mem(after _common_ucx_mem_append): mem = %p, mem_tbl_entry = %p\n",
    		(void *)mem, (void *)tls->mem_tbl[i]);

    return tls->mem_tbl[i];
}

static int _tlocal_mem_create_rkey(_tlocal_mem_t *mem_rec, ucp_ep_h ep, int target)
{
    _mem_info_t *minfo = mem_rec->mem;
    opal_common_ucx_mem_t *gmem = mem_rec->gmem;
    int displ = gmem->mem_displs[target];
    ucs_status_t status;

    status = ucp_ep_rkey_unpack(ep, &gmem->mem_addrs[displ],
                                &minfo->rkeys[target]);
    if (status != UCS_OK) {
        MCA_COMMON_UCX_VERBOSE(1, "ucp_ep_rkey_unpack failed: %d", status);
        return OPAL_ERROR;
    }
    DBG_OUT("_tlocal_mem_create_rkey(after ucp_ep_rkey_unpack): mem_rec = %p ep = %p target = %d\n",
    		(void *)mem_rec, (void *)ep, target);
    return OPAL_SUCCESS;
}

static inline int _tlocal_fetch(opal_common_ucx_mem_t *mem, int target,
                                ucp_ep_h *_ep, ucp_rkey_h *_rkey,
                                _worker_info_t **_winfo)
{
    _tlocal_table_t *tls = NULL;
    _tlocal_ctx_t *ctx_rec = NULL;
    _worker_info_t *winfo = NULL;
    _tlocal_mem_t *mem_rec = NULL;
    _mem_info_t *mem_info = NULL;
    ucp_ep_h ep;
    ucp_rkey_h rkey;
    int rc = OPAL_SUCCESS;

    DBG_OUT("_tlocal_fetch: starttls \n");

    tls = _tlocal_get_tls(mem->ctx->wpool);

    DBG_OUT("_tlocal_fetch: tls = %p\n",(void*)tls);

    /* Obtain the worker structure */
    ctx_rec = _tlocal_ctx_search(tls, mem->ctx->ctx_id);

    DBG_OUT("_tlocal_fetch(after _tlocal_ctx_search): ctx_id = %d, ctx_rec=%p\n",
            (int)mem->ctx->ctx_id, (void *)ctx_rec);
    if (OPAL_UNLIKELY(NULL == ctx_rec)) {
        ctx_rec = _tlocal_add_ctx(tls, mem->ctx);
        if (NULL == ctx_rec) {
            return OPAL_ERR_OUT_OF_RESOURCE;
        }
        DBG_OUT("_tlocal_fetch(after _tlocal_add_ctx): tls = %p ctx = %p\n", (void *)tls, (void *)mem->ctx);
    }
    winfo = ctx_rec->winfo;
    DBG_OUT("_tlocal_fetch: winfo = %p ctx=%p\n", (void *)winfo, (void *)mem->ctx);

    /* Obtain the endpoint */
    if (OPAL_UNLIKELY(NULL == winfo->endpoints[target])) {
        rc = _tlocal_ctx_connect(ctx_rec, target);
        if (rc != OPAL_SUCCESS) {
            return rc;
        }
        DBG_OUT("_tlocal_fetch(after _tlocal_ctx_connect): ctx_rec = %p target = %d\n", (void *)ctx_rec, target);
    }
    ep = winfo->endpoints[target];
    DBG_OUT("_tlocal_fetch: ep = %p\n", (void *)ep);

    /* Obtain the memory region info */
    mem_rec = _tlocal_search_mem(tls, mem->mem_id);
    DBG_OUT("_tlocal_fetch: tls = %p mem_rec = %p mem_id = %d\n", (void *)tls, (void *)mem_rec, (int)mem->mem_id);
    if (OPAL_UNLIKELY(mem_rec == NULL)) {
        mem_rec = _tlocal_add_mem(tls, mem);
        DBG_OUT("_tlocal_fetch(after _tlocal_add_mem): tls = %p mem = %p\n", (void *)tls, (void *)mem);
        if (NULL == mem_rec) {
            return OPAL_ERR_OUT_OF_RESOURCE;
        }
    }
    mem_info = mem_rec->mem;
    DBG_OUT("_tlocal_fetch: mem_info = %p\n", (void *)mem_info);

    /* Obtain the rkey */
    if (OPAL_UNLIKELY(NULL == mem_info->rkeys[target])) {
        /* Create the rkey */
        rc = _tlocal_mem_create_rkey(mem_rec, ep, target);
        if (rc) {
            return rc;
        }
        DBG_OUT("_tlocal_fetch: creating rkey ...\n");
    }
    DBG_OUT("_tlocal_fetch: rkey = %p\n", (void *)rkey);

    *_ep = ep;
    *_rkey = rkey = mem_info->rkeys[target];
    *_winfo = winfo;

    DBG_OUT("_tlocal_fetch(end): ep = %p, rkey = %p, winfo = %p\n",
    		(void *)ep, (void *)rkey, (void *)winfo);

    return OPAL_SUCCESS;
}



OPAL_DECLSPEC int
opal_common_ucx_mem_putget(opal_common_ucx_mem_t *mem,
                           opal_common_ucx_op_t op,
                           int target, void *buffer, size_t len,
                           uint64_t rem_addr)
{
    ucp_ep_h ep;
    ucp_rkey_h rkey;
    ucs_status_t status;
    _worker_info_t *winfo;
    int rc = OPAL_SUCCESS;

    rc =_tlocal_fetch(mem, target, &ep, &rkey, &winfo);
    if(OPAL_SUCCESS != rc){
    	MCA_COMMON_UCX_VERBOSE(1, "tlocal_fetch failed: %d", rc);
        return rc;
    }
    DBG_OUT("opal_common_ucx_mem_putget(after _tlocal_fetch): mem = %p, ep = %p, rkey = %p, winfo = %p\n",
    		(void *)mem, (void *)ep, (void *)rkey, (void *)winfo);

    /* Perform the operation */
    opal_mutex_lock(&winfo->mutex);
    switch(op){
    case OPAL_COMMON_UCX_PUT:
        status = ucp_put_nbi(ep, buffer,len, rem_addr, rkey);
        if (status != UCS_OK && status != UCS_INPROGRESS) {
        	MCA_COMMON_UCX_VERBOSE(1, "ucp_put_nbi failed: %d", status);
            opal_mutex_unlock(&winfo->mutex);
            return OPAL_ERROR;
        }
        DBG_OUT("opal_common_ucx_mem_putget(after ucp_put_nbi): ep = %p, rkey = %p\n",
        	   (void *)ep, (void *)rkey);
        break;
    case OPAL_COMMON_UCX_GET:
        status = ucp_get_nbi(ep, buffer,len, rem_addr, rkey);
        if (status != UCS_OK && status != UCS_INPROGRESS) {
        	MCA_COMMON_UCX_VERBOSE(1, "ucp_get_nbi failed: %d", status);
            opal_mutex_unlock(&winfo->mutex);
            return OPAL_ERROR;
        }
        DBG_OUT("opal_common_ucx_mem_putget(after ucp_get_nbi): ep = %p, rkey = %p\n",
        	   (void *)ep, (void *)rkey);
        break;
    }
    opal_mutex_unlock(&winfo->mutex);
    return OPAL_SUCCESS;
}


OPAL_DECLSPEC
int opal_common_ucx_mem_cmpswp(opal_common_ucx_mem_t *mem,
		                       uint64_t compare, uint64_t value,
							   int target, void *buffer, size_t len,
							   uint64_t rem_addr)
{
    ucp_ep_h ep;
    ucp_rkey_h rkey;
    _worker_info_t *winfo = NULL;
    ucs_status_t status;
    int rc = OPAL_SUCCESS;

    rc =_tlocal_fetch(mem, target, &ep, &rkey, &winfo);
    if(OPAL_SUCCESS != rc){
    	MCA_COMMON_UCX_VERBOSE(1, "tlocal_fetch failed: %d", rc);
        return rc;
    }
    DBG_OUT("opal_common_ucx_mem_cmpswp(after _tlocal_fetch): mem = %p, ep = %p, rkey = %p, winfo = %p\n",
    		(void *)mem, (void *)ep, (void *)rkey, (void *)winfo);

    /* Perform the operation */
    opal_mutex_lock(&winfo->mutex);
    status = opal_common_ucx_atomic_cswap(ep, compare, value,
                                          buffer, len,
                                          rem_addr, rkey,
                                          winfo->worker);
    if (status != UCS_OK) {
    	MCA_COMMON_UCX_VERBOSE(1, "opal_common_ucx_atomic_cswap failed: %d", status);
        opal_mutex_unlock(&winfo->mutex);
        return OPAL_ERROR;
    }
    DBG_OUT("opal_common_ucx_mem_cmpswp(after opal_common_ucx_atomic_cswap): ep = %p, rkey = %p\n",
    	   (void *)ep, (void *)rkey);

    opal_mutex_unlock(&winfo->mutex);
    return OPAL_SUCCESS;
}

OPAL_DECLSPEC
int opal_common_ucx_mem_fetch(opal_common_ucx_mem_t *mem,
                              ucp_atomic_fetch_op_t opcode, uint64_t value,
                              int target, void *buffer, size_t len,
                              uint64_t rem_addr)
{
    ucp_ep_h ep = NULL;
    ucp_rkey_h rkey = NULL;
    _worker_info_t *winfo = NULL;
    ucs_status_t status;
    int rc = OPAL_SUCCESS;

    rc =_tlocal_fetch(mem, target, &ep, &rkey, &winfo);
    if(OPAL_SUCCESS != rc){
    	MCA_COMMON_UCX_VERBOSE(1, "tlocal_fetch failed: %d", rc);
        return rc;
    }
    DBG_OUT("opal_common_ucx_mem_fetch(after _tlocal_fetch): mem = %p, ep = %p, rkey = %p, winfo = %p\n",
    		(void *)mem, (void *)ep, (void *)rkey, (void *)winfo);

    /* Perform the operation */
    opal_mutex_lock(&winfo->mutex);
    status = opal_common_ucx_atomic_fetch(ep, opcode, value,
                                          buffer, len,
                                          rem_addr, rkey,
                                          winfo->worker);
    if (status != UCS_OK) {
    	opal_mutex_unlock(&winfo->mutex);
    	MCA_COMMON_UCX_VERBOSE(1, "ucp_atomic_cswap64 failed: %d", status);
        return OPAL_ERROR;
    }
    DBG_OUT("opal_common_ucx_mem_fetch(after opal_common_ucx_atomic_fetch): ep = %p, rkey = %p\n",
    	   (void *)ep, (void *)rkey);

    opal_mutex_unlock(&winfo->mutex);

    return OPAL_SUCCESS;
}


OPAL_DECLSPEC
int opal_common_ucx_mem_post(opal_common_ucx_mem_t *mem,
                             ucp_atomic_post_op_t opcode,
                             uint64_t value, int target, size_t len,
                             uint64_t rem_addr)
{
    ucp_ep_h ep;
    ucp_rkey_h rkey;
    _worker_info_t *winfo = NULL;
    ucs_status_t status;
    int rc = OPAL_SUCCESS;

    rc =_tlocal_fetch(mem, target, &ep, &rkey, &winfo);
    if(OPAL_SUCCESS != rc){
    	MCA_COMMON_UCX_VERBOSE(1, "tlocal_fetch failed: %d", rc);
        return rc;
    }
    DBG_OUT("opal_common_ucx_mem_post(after _tlocal_fetch): mem = %p, ep = %p, rkey = %p, winfo = %p\n",
    		(void *)mem, (void *)ep, (void *)rkey, (void *)winfo);

    /* Perform the operation */
    opal_mutex_lock(&winfo->mutex);
    status = ucp_atomic_post(ep, opcode, value,
                             len, rem_addr, rkey);
    if (status != UCS_OK) {
    	opal_mutex_unlock(&winfo->mutex);
        MCA_COMMON_UCX_VERBOSE(1, "ucp_atomic_cswap64 failed: %d", status);
        return OPAL_ERROR;
    }
    DBG_OUT("opal_common_ucx_mem_post(after ucp_atomic_post): ep = %p, rkey = %p\n", (void *)ep, (void *)rkey);
    opal_mutex_unlock(&winfo->mutex);

    return OPAL_SUCCESS;
}

OPAL_DECLSPEC int
opal_common_ucx_mem_flush(opal_common_ucx_mem_t *mem,
                          opal_common_ucx_flush_scope_t scope,
                          int target)
{
    _worker_list_item_t *item;
    opal_common_ucx_ctx_t *ctx = mem->ctx;
    int rc = OPAL_SUCCESS;

    DBG_OUT("opal_common_ucx_mem_flush: mem = %p, target = %d\n", (void *)mem, target);

    opal_mutex_lock(&ctx->mutex);
    OPAL_LIST_FOREACH(item, &ctx->workers, _worker_list_item_t) {
        switch (scope) {
        case OPAL_COMMON_UCX_SCOPE_WORKER:
            opal_mutex_lock(&item->ptr->winfo->mutex);
            rc = opal_common_ucx_worker_flush(item->ptr->winfo->worker);
            if (rc != OPAL_SUCCESS) {
            	opal_mutex_unlock(&item->ptr->winfo->mutex);
            	opal_mutex_unlock(&ctx->mutex);
                MCA_COMMON_UCX_VERBOSE(1, "opal_common_ucx_worker_flush failed: %d", rc);
                return OPAL_ERROR;
            }
            DBG_OUT("opal_common_ucx_mem_flush(after opal_common_ucx_worker_flush): worker = %p\n",
            		(void *)item->ptr->winfo->worker);
            opal_mutex_unlock(&item->ptr->winfo->mutex);
            break;
        case OPAL_COMMON_UCX_SCOPE_EP:
            if (NULL != item->ptr->winfo->endpoints[target] ) {
                opal_mutex_lock(&item->ptr->winfo->mutex);
                rc = opal_common_ucx_ep_flush(item->ptr->winfo->endpoints[target],
                                              item->ptr->winfo->worker);
                if (rc != OPAL_SUCCESS) {
                	opal_mutex_unlock(&item->ptr->winfo->mutex);
                	opal_mutex_unlock(&ctx->mutex);
                    MCA_COMMON_UCX_VERBOSE(1, "opal_common_ucx_ep_flush failed: %d", rc);
                    return OPAL_ERROR;
                }
                DBG_OUT("opal_common_ucx_mem_flush(after opal_common_ucx_worker_flush): ep = %p worker = %p\n",
                		(void *)item->ptr->winfo->endpoints[target],
                		(void *)item->ptr->winfo->worker);
                opal_mutex_unlock(&item->ptr->winfo->mutex);
            }
        }
    }
    opal_mutex_unlock(&ctx->mutex);

    return rc;
}

OPAL_DECLSPEC
int opal_common_ucx_workers_progress(opal_common_ucx_wpool_t *wpool) {
    // TODO
    static int enter = 0;
    if (enter == 0) {
        DBG_OUT("opal_common_ucx_workres_progress: wpool = %p\n", (void *)wpool);
    }

    enter++;
    return OPAL_SUCCESS;
}

