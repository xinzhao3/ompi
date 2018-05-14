/*
 * Copyright (c) 2013      Mellanox Technologies, Inc.
 *                         All rights reserved.
 * $COPYRIGHT$
 *
 * Additional copyrights may follow
 *
 * $HEADER$
 */
#include "oshmem_config.h"

#include "oshmem/constants.h"
#include "oshmem/include/shmem.h"

#include "oshmem/runtime/runtime.h"

#include "oshmem/op/op.h"
#include "oshmem/mca/atomic/atomic.h"

/*
 * These routines perform an atomic fetch-and-add operation.
 * The fetch and add routines retrieve the value at address target on PE pe, and update
 * target with the result of adding value to the retrieved value. The operation must be completed
 * without the possibility of another process updating target between the time of the
 * fetch and the update.
 */
#define DO_SHMEM_TYPE_ATOMIC_FADD(ctx, type_name, type, target, value, pe, out_value) do { \
        int rc = OSHMEM_SUCCESS;                                    \
        size_t size = 0;                                            \
        oshmem_op_t* op = oshmem_op_sum##type_name;                 \
                                                                    \
        RUNTIME_CHECK_INIT();                                       \
        RUNTIME_CHECK_PE(pe);                                       \
        RUNTIME_CHECK_ADDR(target);                                 \
                                                                    \
        size = sizeof(out_value);                                   \
        rc = MCA_ATOMIC_CALL(fadd(                                  \
            ctx,                                                    \
            (void*)target,                                          \
            (void*)&out_value,                                      \
            (const void*)&value,                                    \
            size,                                                   \
            pe,                                                     \
            op));                                                   \
        RUNTIME_CHECK_RC(rc);                                       \
    } while (0)

#define SHMEM_CTX_TYPE_ATOMIC_FADD(type_name, type, prefix)         \
    type prefix##_ctx##type_name##_atomic_fadd(shmem_ctx_t ctx, type *target, type value, int pe) \
    {                                                               \
        type out_value;                                             \
        DO_SHMEM_TYPE_ATOMIC_FADD(ctx, type_name, type, target,     \
                                  value, pe, out_value);            \
        return out_value;                                           \
    }

#define SHMEM_TYPE_ATOMIC_FADD(type_name, type, prefix)             \
    type prefix##type_name##_atomic_fadd(type *target, type value, int pe)\
    {                                                               \
        type out_value;                                             \
        DO_SHMEM_TYPE_ATOMIC_FADD(SHMEM_CTX_DEFAULT, type_name,     \
                                  type, target, value, pe, out_value); \
        return out_value;                                           \
    }

#if OSHMEM_PROFILING
#include "oshmem/include/pshmem.h"
#pragma weak shmem_ctx_int_atomic_fadd = pshmem_ctx_int_atomic_fadd
#pragma weak shmem_ctx_long_atomic_fadd = pshmem_ctx_long_atomic_fadd
#pragma weak shmem_ctx_longlong_atomic_fadd = pshmem_ctx_longlong_atomic_fadd
#pragma weak shmem_int_atomic_fadd = pshmem_int_atomic_fadd
#pragma weak shmem_long_atomic_fadd = pshmem_long_atomic_fadd
#pragma weak shmem_longlong_atomic_fadd = pshmem_longlong_atomic_fadd
#pragma weak shmem_int_fadd = pshmem_int_fadd
#pragma weak shmem_long_fadd = pshmem_long_fadd
#pragma weak shmem_longlong_fadd = pshmem_longlong_fadd
#pragma weak shmemx_int32_fadd = pshmemx_int32_fadd
#pragma weak shmemx_int64_fadd = pshmemx_int64_fadd
#include "oshmem/shmem/c/profile/defines.h"
#endif

SHMEM_CTX_TYPE_ATOMIC_FADD(_int, int, shmem)
SHMEM_CTX_TYPE_ATOMIC_FADD(_long, long, shmem)
SHMEM_CTX_TYPE_ATOMIC_FADD(_longlong, long long, shmem)
SHMEM_TYPE_ATOMIC_FADD(_int, int, shmem)
SHMEM_TYPE_ATOMIC_FADD(_long, long, shmem)
SHMEM_TYPE_ATOMIC_FADD(_longlong, long long, shmem)

/* deprecated APIs */
#define SHMEM_TYPE_FADD(type_name, type, prefix)                    \
    type prefix##type_name##_fadd(type *target, type value, int pe) \
    {                                                               \
        type out_value;                                             \
        DO_SHMEM_TYPE_ATOMIC_FADD(SHMEM_CTX_DEFAULT, type_name,     \
                                  type, target, value, pe, out_value); \
        return out_value;                                           \
    }

SHMEM_TYPE_FADD(_int, int, shmem)
SHMEM_TYPE_FADD(_long, long, shmem)
SHMEM_TYPE_FADD(_longlong, long long, shmem)
SHMEM_TYPE_FADD(_int32, int32_t, shmemx)
SHMEM_TYPE_FADD(_int64, int64_t, shmemx)
