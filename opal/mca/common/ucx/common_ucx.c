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

/***********************************************************************/

typedef struct  {
    opal_mutex_t mutex;
    ucp_worker_h worker;
    ucp_ep_h *endpoints;
    int comm_size;
} _worker_info_t;

OBJ_CLASS_DECLARATION(_worker_info_t);

typedef struct {
    int ctx_id;
    int is_freed;
    opal_common_ucx_ctx_t *gctx;
    _worker_info_t *worker;
} _tlocal_ctx_t;

OBJ_CLASS_DECLARATION(_tlocal_ctx_t);

typedef struct {
    _worker_info_t *worker;
    ucp_rkey_h *rkeys;
} _mem_info_t;

OBJ_CLASS_DECLARATION(_mem_info_t);

typedef struct {
    int mem_id;
    opal_common_ucx_mem_t *gmem;
    _mem_info_t *mem;
} _tlocal_mem_t;

OBJ_CLASS_DECLARATION(_tlocal_mem_t);

typedef struct {
    opal_list_item_t super;
    _worker_info_t *ptr;
} _idle_list_item_t;

OBJ_CLASS_DECLARATION(_idle_list_item_t);
OBJ_CLASS_INSTANCE(_idle_list_item_t, opal_list_item_t, NULL, NULL);

typedef struct {
    opal_list_item_t super;
    _worker_info_t *ptr;
} _worker_list_item_t;

OBJ_CLASS_DECLARATION(_worker_list_item_t);
OBJ_CLASS_INSTANCE(_worker_list_item_t, opal_list_item_t, NULL, NULL);

typedef struct {
    opal_list_item_t super;
    _mem_info_t *ptr;
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
    // 1. Cleanup all rkeys in the window table
    // 2. Return all workers into the idle pool
}

static ucp_worker_h _create_ctx_worker(opal_common_ucx_wpool_t *wpool)
{
    ucp_worker_params_t worker_params;
    ucp_worker_h worker;
    ucs_status_t status;

    memset(&worker_params, 0, sizeof(worker_params));
    worker_params.field_mask = UCP_WORKER_PARAM_FIELD_THREAD_MODE;
    worker_params.thread_mode = UCS_THREAD_MODE_SINGLE;
    status = ucp_worker_create(wpool->ucp_ctx, &worker_params, &worker);
    if (UCS_OK != status) {
        return NULL;
    }

    return worker;
}

static void _wpool_add_to_idle(opal_common_ucx_wpool_t *wpool,
                               _worker_info_t *wkr)
{
    _idle_list_item_t *item;

    if(wkr->comm_size != 0) {
        int i;
        for (i = 0; i < wkr->comm_size; i++) {
            ucp_ep_destroy(wkr->endpoints[i]);
        }
        free(wkr->endpoints);
        wkr->endpoints = NULL;
        wkr->comm_size = 0;
    }

    item = OBJ_NEW(_idle_list_item_t);
    item->ptr = wkr;

    opal_mutex_lock(&wpool->mutex);
    opal_list_append(&wpool->idle_workers, &item->super);
    opal_mutex_unlock(&wpool->mutex);
}

static _worker_info_t* _wpool_remove_from_idle(opal_common_ucx_wpool_t *wpool)
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

    return wkr;
}


OPAL_DECLSPEC int opal_common_ucx_wpool_init(opal_common_ucx_wpool_t *wpool,
                                             int proc_world_size,
                                             ucp_request_init_callback_t req_init_ptr,
                                             size_t req_size)
{
    ucp_config_t *config = NULL;
    ucp_params_t context_params;
    _worker_info_t *wkr;
    ucs_status_t status;
    int ret = OPAL_SUCCESS;

    wpool->cur_ctxid = wpool->cur_memid = 0;
    OBJ_CONSTRUCT(&wpool->mutex, opal_mutex_t);

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
    context_params.mt_workers_shared = 1;
    context_params.estimated_num_eps = proc_world_size;
    context_params.request_init = req_init_ptr;
    context_params.request_size = req_size;

    status = ucp_init(&context_params, config, &wpool->ucp_ctx);
    ucp_config_release(config);
    if (UCS_OK != status) {
        MCA_COMMON_UCX_VERBOSE(1, "ucp_init failed: %d", status);
        ret = OPAL_ERROR;
        goto err_ucp_init;
    }

    /* create recv worker and add to idle pool */
    OBJ_CONSTRUCT(&wpool->idle_workers, opal_list_t);
    wpool->recv_worker = _create_ctx_worker(wpool);
    if (wpool->recv_worker == NULL) {
        MCA_COMMON_UCX_VERBOSE(1, "_create_ctx_worker failed");
        ret = OPAL_ERROR;
        goto err_worker_create;
    }

    wkr = OBJ_NEW(_worker_info_t);
    OBJ_CONSTRUCT(&wkr->mutex, opal_mutex_t);
    wkr->worker = wpool->recv_worker;
    wkr->endpoints = NULL;
    wkr->comm_size = 0;

    _wpool_add_to_idle(wpool, wkr);

    status = ucp_worker_get_address(wpool->recv_worker,
                                    &wpool->recv_waddr, &wpool->recv_waddr_len);
    if (status != UCS_OK) {
        MCA_COMMON_UCX_VERBOSE(1, "ucp_worker_get_address failed: %d", status);
        ret = OPAL_ERROR;
        goto err_get_addr;
    }

    pthread_key_create(&_tlocal_key, _cleanup_tlocal);

    return ret;

 err_get_addr:
    if (NULL != wpool->recv_worker) {
        ucp_worker_destroy(wpool->recv_worker);
    }
 err_worker_create:
    ucp_cleanup(wpool->ucp_ctx);
 err_ucp_init:
    return ret;
}
