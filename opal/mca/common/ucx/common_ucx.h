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

#include <ucp/api/ucp.h>
#include <pthread.h>

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

typedef struct {

    /* Ref counting & locking*/
    int refcnt;
    opal_mutex_t mutex;

    /* UCX data */
    ucp_context_h ucp_ctx;
    ucp_worker_h recv_worker;
    ucp_address_t *recv_waddr;
    size_t recv_waddr_len;

    /* Thread-local key to allow each thread to have
     * local information assisiated with this wpool */
    pthread_key_t tls_key;

    /* Bookkeeping information */
    opal_list_t idle_workers;
    opal_list_t active_workers;

    opal_atomic_int32_t cur_ctxid, cur_memid;
    opal_list_t tls_list;
} opal_common_ucx_wpool_t;

typedef struct {
    int ctx_id;
    opal_mutex_t mutex;
    opal_common_ucx_wpool_t *wpool; /* which wpool this ctx belongs to */
    opal_list_t workers; /* active worker lists */
    char *recv_worker_addrs;
    int *recv_worker_displs;
    size_t comm_size;
} opal_common_ucx_ctx_t;

typedef struct {
    int mem_id;
    opal_mutex_t mutex;
    opal_common_ucx_ctx_t *ctx; /* which ctx this mem_reg belongs to */
    ucp_mem_h memh;
    opal_list_t registrations; /* mem region lists */
    char *mem_addrs;
    int *mem_displs;
} opal_common_ucx_mem_t;

typedef enum {
    OPAL_COMMON_UCX_PUT,
    OPAL_COMMON_UCX_GET
} opal_common_ucx_op_t;

typedef enum {
    OPAL_COMMON_UCX_SCOPE_EP,
    OPAL_COMMON_UCX_SCOPE_WORKER
} opal_common_ucx_flush_scope_t;

typedef enum {
    OPAL_COMMON_UCX_MEM_ALLOCATE_MAP,
    OPAL_COMMON_UCX_MEM_MAP
} opal_common_ucx_mem_type_t;

typedef int (*opal_common_ucx_exchange_func_t)(void *my_info, size_t my_info_len,
                                               char **recv_info, int **disps,
                                               void *metadata);

/* Manage Worker Pool (wpool) */
OPAL_DECLSPEC opal_common_ucx_wpool_t * opal_common_ucx_wpool_allocate(void);
OPAL_DECLSPEC void opal_common_ucx_wpool_free(opal_common_ucx_wpool_t *wpool);
OPAL_DECLSPEC int opal_common_ucx_wpool_init(opal_common_ucx_wpool_t *wpool,
                                             int proc_world_size,
                                             ucp_request_init_callback_t req_init_ptr,
                                             size_t req_size, bool enable_mt);
OPAL_DECLSPEC void opal_common_ucx_wpool_finalize(opal_common_ucx_wpool_t *wpool);
OPAL_DECLSPEC void opal_common_ucx_wpool_progress(opal_common_ucx_wpool_t *wpool);

/* Manage Communication context */
OPAL_DECLSPEC int opal_common_ucx_ctx_create(opal_common_ucx_wpool_t *wpool, int comm_size,
                                             opal_common_ucx_exchange_func_t exchange_func,
                                             void *exchange_metadata,
                                             opal_common_ucx_ctx_t **ctx_ptr);
OPAL_DECLSPEC void opal_common_ucx_ctx_release(opal_common_ucx_ctx_t *ctx);

/* Manage Memory registrations */
OPAL_DECLSPEC int opal_common_ucx_mem_create(opal_common_ucx_ctx_t *ctx, int comm_size,
                                             void **mem_base, size_t mem_size,
                                             opal_common_ucx_mem_type_t mem_type,
                                             opal_common_ucx_exchange_func_t exchange_func,
                                             void *exchange_metadata,
                                             opal_common_ucx_mem_t **mem_ptr);
OPAL_DECLSPEC int opal_common_ucx_mem_flush(opal_common_ucx_mem_t *mem,
                                            opal_common_ucx_flush_scope_t scope,
                                            int target);

OPAL_DECLSPEC int opal_common_ucx_mem_fetch_nb(opal_common_ucx_mem_t *mem,
                                               ucp_atomic_fetch_op_t opcode,
                                               uint64_t value,
                                               int target, void *buffer, size_t len,
                                               uint64_t rem_addr, ucs_status_ptr_t *ptr);
OPAL_DECLSPEC int opal_common_ucx_mem_fence(opal_common_ucx_mem_t *mem);

OPAL_DECLSPEC int opal_common_ucx_mem_cmpswp(opal_common_ucx_mem_t *mem,
                                             uint64_t compare, uint64_t value,
                                             int target,
                                             void *buffer, size_t len,
                                             uint64_t rem_addr);
OPAL_DECLSPEC int opal_common_ucx_mem_putget(opal_common_ucx_mem_t *mem,
                                         opal_common_ucx_op_t op,
                                         int target,
                                         void *buffer, size_t len,
                                         uint64_t rem_addr);
OPAL_DECLSPEC int opal_common_ucx_mem_fetch(opal_common_ucx_mem_t *mem,
                                            ucp_atomic_fetch_op_t opcode, uint64_t value,
                                            int target,
                                            void *buffer, size_t len,
                                            uint64_t rem_addr);
OPAL_DECLSPEC int opal_common_ucx_mem_post(opal_common_ucx_mem_t *mem,
                                            ucp_atomic_post_op_t opcode,
                                           uint64_t value,
                                            int target,
                                            size_t len,
                                            uint64_t rem_addr);

#define FDBG
#ifdef FDBG
extern __thread FILE *tls_pf;
extern __thread int initialized;

#include  <unistd.h>
#include <sys/syscall.h>
#include <time.h>
#include <sys/time.h>

static inline void init_tls_dbg(void)
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
    struct timeval start_;          \
    time_t nowtime_;                \
    struct tm *nowtm_;              \
    char tmbuf_[64];                \
    gettimeofday(&start_, NULL);    \
    nowtime_ = start_.tv_sec;       \
    nowtm_ = localtime(&nowtime_);  \
    strftime(tmbuf_, sizeof(tmbuf_), "%H:%M:%S", nowtm_); \
    init_tls_dbg();                 \
    fprintf(tls_pf, "[%s.%06ld] ", tmbuf_, start_.tv_usec);\
    fprintf(tls_pf, __VA_ARGS__);    \
}

#else
#define DBG_OUT(...)
#endif

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
ucs_status_ptr_t opal_common_ucx_atomic_fetch_nb(ucp_ep_h ep, ucp_atomic_fetch_op_t opcode,
                                                 uint64_t value, void *result, size_t op_size,
                                                 uint64_t remote_addr, ucp_rkey_h rkey,
                                                 ucp_worker_h worker)
{
    return ucp_atomic_fetch_nb(ep, opcode, value, result, op_size,
                               remote_addr, rkey, opal_common_ucx_empty_complete_cb);
}

static inline
int opal_common_ucx_atomic_fetch(ucp_ep_h ep, ucp_atomic_fetch_op_t opcode,
                                 uint64_t value, void *result, size_t op_size,
                                 uint64_t remote_addr, ucp_rkey_h rkey,
                                 ucp_worker_h worker)
{
    ucs_status_ptr_t request;

    request = opal_common_ucx_atomic_fetch_nb(ep, opcode, value, result, op_size,
                                              remote_addr, rkey, worker);
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

END_C_DECLS

#endif
