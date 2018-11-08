/*
 * Copyright (c) 2018      Mellanox Technologies.  All rights reserved.
 *                         All rights reserved.
 * Copyright (c) 2018      Research Organization for Information Science
 *                         and Technology (RIST).  All rights reserved.
 * $COPYRIGHT$
 *
 * Additional copyrights may follow
 *
 * $HEADER$
 */

#ifndef _COMMON_UCX_H_
#define _COMMON_UCX_H_

#include "opal_config.h"

#include <stdint.h>
#include <string.h>

#include <ucp/api/ucp.h>

#include "opal/mca/mca.h"
#include "opal/util/output.h"
#include "opal/runtime/opal_progress.h"
#include "opal/include/opal/constants.h"
#include "opal/class/opal_list.h"

BEGIN_C_DECLS

#define MCA_COMMON_UCX_ENABLE_DEBUG   OPAL_ENABLE_DEBUG
#if MCA_COMMON_UCX_ENABLE_DEBUG
#  define MCA_COMMON_UCX_MAX_VERBOSE  100
#  define MCA_COMMON_UCX_ASSERT(_x)   assert(_x)
#else
#  define MCA_COMMON_UCX_MAX_VERBOSE  2
#  define MCA_COMMON_UCX_ASSERT(_x)
#endif

#define _MCA_COMMON_UCX_QUOTE(_x) \
    # _x
#define MCA_COMMON_UCX_QUOTE(_x) \
    _MCA_COMMON_UCX_QUOTE(_x)

#define MCA_COMMON_UCX_ERROR(...)                                   \
    opal_output_verbose(0, opal_common_ucx.output,                  \
                        __FILE__ ":" MCA_COMMON_UCX_QUOTE(__LINE__) \
                        " Error: " __VA_ARGS__)

#define MCA_COMMON_UCX_VERBOSE(_level, ... )                                \
    if (((_level) <= MCA_COMMON_UCX_MAX_VERBOSE) &&                         \
        ((_level) <= opal_common_ucx.verbose)) {                            \
        opal_output_verbose(_level, opal_common_ucx.output,                 \
                            __FILE__ ":" MCA_COMMON_UCX_QUOTE(__LINE__) " " \
                            __VA_ARGS__);                                   \
    }

/* progress loop to allow call UCX/opal progress */
/* used C99 for-statement variable initialization */
#define MCA_COMMON_UCX_PROGRESS_LOOP(_worker)                                 \
    for (unsigned iter = 0;; (++iter % opal_common_ucx.progress_iterations) ? \
                        (void)ucp_worker_progress(_worker) : opal_progress())

#define MCA_COMMON_UCX_WAIT_LOOP(_request, _worker, _msg, _completed)                    \
    do {                                                                                 \
        ucs_status_t status;                                                             \
        /* call UCX progress */                                                          \
        MCA_COMMON_UCX_PROGRESS_LOOP(_worker) {                                          \
            status = opal_common_ucx_request_status(_request);                           \
            if (UCS_INPROGRESS != status) {                                              \
                _completed;                                                              \
                if (OPAL_LIKELY(UCS_OK == status)) {                                     \
                    return OPAL_SUCCESS;                                                 \
                } else {                                                                 \
                    MCA_COMMON_UCX_VERBOSE(1, "%s failed: %d, %s",                       \
                                           (_msg) ? (_msg) : __func__,                   \
                                           UCS_PTR_STATUS(_request),                     \
                                           ucs_status_string(UCS_PTR_STATUS(_request))); \
                    return OPAL_ERROR;                                                   \
                }                                                                        \
            }                                                                            \
        }                                                                                \
    } while (0)

typedef struct opal_common_ucx_module {
    int  output;
    int  verbose;
    int  progress_iterations;
    int  registered;
    bool opal_mem_hooks;
} opal_common_ucx_module_t;

typedef struct opal_common_ucx_del_proc {
    ucp_ep_h ep;
    size_t   vpid;
} opal_common_ucx_del_proc_t;

extern opal_common_ucx_module_t opal_common_ucx;

typedef struct thread_local_info {
    opal_list_item_t super;
    ucp_worker_h worker;
    ucp_ep_h *eps;
    ucp_rkey_h *rkeys;
    int comm_size;
    pthread_mutex_t lock;
} thread_local_info_t;

OBJ_CLASS_DECLARATION(thread_local_info_t);

extern pthread_key_t my_thread_key;

extern opal_list_t active_workers, idle_workers;
extern pthread_mutex_t active_workers_mutex, idle_workers_mutex;

OPAL_DECLSPEC void opal_common_ucx_mca_register(void);
OPAL_DECLSPEC void opal_common_ucx_mca_deregister(void);
OPAL_DECLSPEC void opal_common_ucx_empty_complete_cb(void *request, ucs_status_t status);
OPAL_DECLSPEC int opal_common_ucx_mca_pmix_fence(ucp_worker_h worker);
OPAL_DECLSPEC int opal_common_ucx_del_procs(opal_common_ucx_del_proc_t *procs, size_t count,
                                            size_t my_rank, size_t max_disconnect, ucp_worker_h worker);
OPAL_DECLSPEC void opal_common_ucx_mca_var_register(const mca_base_component_t *component);

static inline
ucs_status_t opal_common_ucx_request_status(ucs_status_ptr_t request)
{
#if !HAVE_DECL_UCP_REQUEST_CHECK_STATUS
    ucp_tag_recv_info_t info;

    return ucp_request_test(request, &info);
#else
    return ucp_request_check_status(request);
#endif
}

static inline
int opal_common_ucx_wait_request(ucs_status_ptr_t request, ucp_worker_h worker,
                                 const char *msg)
{
    /* check for request completed or failed */
    if (OPAL_LIKELY(UCS_OK == request)) {
        return OPAL_SUCCESS;
    } else if (OPAL_UNLIKELY(UCS_PTR_IS_ERR(request))) {
        MCA_COMMON_UCX_VERBOSE(1, "%s failed: %d, %s", msg ? msg : __func__,
                               UCS_PTR_STATUS(request),
                               ucs_status_string(UCS_PTR_STATUS(request)));
        return OPAL_ERROR;
    }

    MCA_COMMON_UCX_WAIT_LOOP(request, worker, msg, ucp_request_free(request));
}

static inline
int opal_common_ucx_ep_flush(ucp_ep_h ep, ucp_worker_h worker)
{
#if HAVE_DECL_UCP_EP_FLUSH_NB
    ucs_status_ptr_t request;

    request = ucp_ep_flush_nb(ep, 0, opal_common_ucx_empty_complete_cb);
    return opal_common_ucx_wait_request(request, worker, "ucp_ep_flush_nb");
#else
    ucs_status_t status;

    status = ucp_ep_flush(ep);
    return (status == UCS_OK) ? OPAL_SUCCESS : OPAL_ERROR;
#endif
}

static inline
int opal_common_ucx_worker_flush(ucp_worker_h worker)
{
#if HAVE_DECL_UCP_WORKER_FLUSH_NB
    ucs_status_ptr_t request;

    request = ucp_worker_flush_nb(worker, 0, opal_common_ucx_empty_complete_cb);
    return opal_common_ucx_wait_request(request, worker, "ucp_worker_flush_nb");
#else
    ucs_status_t status;

    status = ucp_worker_flush(worker);
    return (status == UCS_OK) ? OPAL_SUCCESS : OPAL_ERROR;
#endif
}

static inline
int opal_common_ucx_atomic_fetch(ucp_ep_h ep, ucp_atomic_fetch_op_t opcode,
                                 uint64_t value, void *result, size_t op_size,
                                 uint64_t remote_addr, ucp_rkey_h rkey,
                                 ucp_worker_h worker)
{
    ucs_status_ptr_t request;

    request = ucp_atomic_fetch_nb(ep, opcode, value, result, op_size,
                                  remote_addr, rkey, opal_common_ucx_empty_complete_cb);
    return opal_common_ucx_wait_request(request, worker, "ucp_atomic_fetch_nb");
}

static inline
int opal_common_ucx_atomic_cswap(ucp_ep_h ep, uint64_t compare,
                                 uint64_t value, void *result, size_t op_size,
                                 uint64_t remote_addr, ucp_rkey_h rkey,
                                 ucp_worker_h worker)
{
    uint64_t tmp = value;
    int ret;

    ret = opal_common_ucx_atomic_fetch(ep, UCP_ATOMIC_FETCH_OP_CSWAP, compare, &tmp,
                                       op_size, remote_addr, rkey, worker);
    if (OPAL_LIKELY(OPAL_SUCCESS == ret)) {
        /* in case if op_size is constant (like sizeof(type)) then this condition
         * is evaluated in compile time */
        if (op_size == sizeof(uint64_t)) {
            *(uint64_t*)result = tmp;
        } else {
            assert(op_size == sizeof(uint32_t));
            *(uint32_t*)result = tmp;
        }
    }
    return ret;
}

static inline void opal_common_ucx_cleanup_local_worker(void *arg) {
    thread_local_info_t *my_thread_info = (thread_local_info_t *)arg;

    assert(my_thread_info != NULL);

    pthread_mutex_lock(&active_workers_mutex);
    opal_list_remove_item(&active_workers, &my_thread_info->super);
    pthread_mutex_unlock(&active_workers_mutex);

    pthread_mutex_lock(&idle_workers_mutex);
    opal_list_append(&idle_workers, &my_thread_info->super);
    pthread_mutex_unlock(&idle_workers_mutex);
}

static inline int opal_common_ucx_create_local_worker(ucp_context_h context, int comm_size,
                                                      char *worker_buf, int *worker_disps,
                                                      char *mem_buf, int *mem_disps)
{
    ucp_worker_params_t worker_params;
    ucs_status_t status;
    thread_local_info_t *my_thread_info;
    int i, ret = OPAL_SUCCESS;

    if (!opal_list_is_empty(&idle_workers)) {
        pthread_mutex_lock(&idle_workers_mutex);
        my_thread_info = (thread_local_info_t *)opal_list_get_first(&idle_workers);
        opal_list_remove_item(&idle_workers, &my_thread_info->super);
        pthread_mutex_unlock(&idle_workers_mutex);
    } else {
        my_thread_info = OBJ_NEW(thread_local_info_t);
        memset(my_thread_info, 0, sizeof(thread_local_info_t));
        pthread_mutex_init(&(my_thread_info->lock), NULL);

        my_thread_info->comm_size = comm_size;

        memset(&worker_params, 0, sizeof(worker_params));
        worker_params.field_mask = UCP_WORKER_PARAM_FIELD_THREAD_MODE;
        worker_params.thread_mode = UCS_THREAD_MODE_SINGLE;
        status = ucp_worker_create(context, &worker_params,
                                   &(my_thread_info->worker));
        if (UCS_OK != status) {
            ret = OPAL_ERROR;
        }

        my_thread_info->eps = calloc(comm_size, sizeof(ucp_ep_h));
        my_thread_info->rkeys = calloc(comm_size, sizeof(ucp_rkey_h));

        for (i = 0; i < comm_size; i++) {
            ucp_ep_params_t ep_params;

            memset(&ep_params, 0, sizeof(ucp_ep_params_t));
            ep_params.field_mask = UCP_EP_PARAM_FIELD_REMOTE_ADDRESS;
            ep_params.address = (ucp_address_t *)&(worker_buf[worker_disps[i]]);
            status = ucp_ep_create(my_thread_info->worker, &ep_params,
                                   &my_thread_info->eps[i]);
            if (status != UCS_OK) {
                ret = OPAL_ERROR;
            }

            status = ucp_ep_rkey_unpack(my_thread_info->eps[i],
                                        &(mem_buf[mem_disps[i] + 3 * sizeof(uint64_t)]),
                                        &(my_thread_info->rkeys[i]));
            if (status != UCS_OK) {
                ret = OPAL_ERROR;
            }
        }
    }

    pthread_mutex_lock(&active_workers_mutex);
    opal_list_append(&active_workers, &my_thread_info->super);
    pthread_mutex_unlock(&active_workers_mutex);

    pthread_setspecific(my_thread_key, my_thread_info);

    return ret;
}

END_C_DECLS

#endif
