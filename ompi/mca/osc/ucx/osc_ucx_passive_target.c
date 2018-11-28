/*
 * Copyright (C) Mellanox Technologies Ltd. 2001-2017. ALL RIGHTS RESERVED.
 * $COPYRIGHT$
 *
 * Additional copyrights may follow
 *
 * $HEADER$
 */

#include "ompi_config.h"

#include "ompi/mca/osc/osc.h"
#include "ompi/mca/osc/base/base.h"
#include "ompi/mca/osc/base/osc_base_obj_convert.h"
#include "opal/mca/common/ucx/common_ucx.h"

#include "osc_ucx.h"

OBJ_CLASS_INSTANCE(ompi_osc_ucx_lock_t, opal_object_t, NULL, NULL);

static int dbg_level = 0;

static inline int start_shared(ompi_osc_ucx_module_t *module, int target) {
    uint64_t result_value = -1;
    uint64_t remote_addr = (module->state_addrs)[target] + OSC_UCX_STATE_LOCK_OFFSET;
    int ret = OMPI_SUCCESS;

    while (true) {
        ret = opal_common_ucx_wpmem_fetch(module->state_mem, UCP_ATOMIC_FETCH_OP_FADD, 1,
                                        target, &result_value, sizeof(result_value),
                                        remote_addr);
        if (OMPI_SUCCESS != ret) {
            return ret;
        }

        DBG_OUT(dbg_level, "start_shared: after fadd, result_value = %d", (int)result_value);

        assert((int64_t)result_value >= 0);
        if (result_value >= TARGET_LOCK_EXCLUSIVE) {
            ret = opal_common_ucx_wpmem_post(module->state_mem,
                                           UCP_ATOMIC_POST_OP_ADD, (-1), target,
                                           sizeof(uint64_t), remote_addr);
            if (OMPI_SUCCESS != ret) {
                return ret;
            }
        } else {
            break;
        }
    }

    return ret;
}

static inline int end_shared(ompi_osc_ucx_module_t *module, int target) {
    uint64_t remote_addr = (module->state_addrs)[target] + OSC_UCX_STATE_LOCK_OFFSET;
    return opal_common_ucx_wpmem_post(module->state_mem, UCP_ATOMIC_POST_OP_ADD,
                                    (-1), target, sizeof(uint64_t), remote_addr);
}

static inline int start_exclusive(ompi_osc_ucx_module_t *module, int target) {
    uint64_t result_value = -1;
    uint64_t remote_addr = (module->state_addrs)[target] + OSC_UCX_STATE_LOCK_OFFSET;
    int ret = OMPI_SUCCESS;

    while (result_value != TARGET_LOCK_UNLOCKED) {
        ret = opal_common_ucx_wpmem_cmpswp(module->state_mem,
                                         TARGET_LOCK_UNLOCKED, TARGET_LOCK_EXCLUSIVE,
                                         target, &result_value, sizeof(result_value),
                                         remote_addr);
        if (OMPI_SUCCESS != ret) {
            return ret;
        }
    }

    return ret;
}

static inline int end_exclusive(ompi_osc_ucx_module_t *module, int target) {
    uint64_t result_value = 0;
    uint64_t remote_addr = (module->state_addrs)[target] + OSC_UCX_STATE_LOCK_OFFSET;
    int ret = OMPI_SUCCESS;

    ret = opal_common_ucx_wpmem_fetch(module->state_mem,
                                    UCP_ATOMIC_FETCH_OP_SWAP, TARGET_LOCK_UNLOCKED,
                                    target, &result_value, sizeof(result_value),
                                    remote_addr);
    if (OMPI_SUCCESS != ret) {
        return ret;
    }

    assert(result_value >= TARGET_LOCK_EXCLUSIVE);

    return ret;
}

int ompi_osc_ucx_lock(int lock_type, int target, int assert, struct ompi_win_t *win) {
    ompi_osc_ucx_module_t *module = (ompi_osc_ucx_module_t *)win->w_osc_module;
    ompi_osc_ucx_lock_t *lock = NULL;
    ompi_osc_ucx_epoch_t original_epoch = module->epoch_type.access;
    int ret = OMPI_SUCCESS;

    if (module->lock_count == 0) {
        if (module->epoch_type.access != NONE_EPOCH &&
            module->epoch_type.access != FENCE_EPOCH) {
            return OMPI_ERR_RMA_SYNC;
        }
    } else {
        ompi_osc_ucx_lock_t *item = NULL;
        assert(module->epoch_type.access == PASSIVE_EPOCH);
        opal_hash_table_get_value_uint32(&module->outstanding_locks, (uint32_t) target, (void **) &item);
        if (item != NULL) {
            return OMPI_ERR_RMA_SYNC;
        }
    }

    module->epoch_type.access = PASSIVE_EPOCH;
    module->lock_count++;
    assert(module->lock_count <= ompi_comm_size(module->comm));

    lock = OBJ_NEW(ompi_osc_ucx_lock_t);
    lock->target_rank = target;

    if ((assert & MPI_MODE_NOCHECK) == 0) {
        lock->is_nocheck = false;
        if (lock_type == MPI_LOCK_EXCLUSIVE) {
            ret = start_exclusive(module, target);
            lock->type = LOCK_EXCLUSIVE;
        } else {
            ret = start_shared(module, target);
            lock->type = LOCK_SHARED;
        }
    } else {
        lock->is_nocheck = true;
    }

    if (ret == OMPI_SUCCESS) {
        opal_hash_table_set_value_uint32(&module->outstanding_locks, (uint32_t)target, (void *)lock);
    } else {
        OBJ_RELEASE(lock);
        module->epoch_type.access = original_epoch;
    }

    return ret;
}

int ompi_osc_ucx_unlock(int target, struct ompi_win_t *win) {
    ompi_osc_ucx_module_t *module = (ompi_osc_ucx_module_t *)win->w_osc_module;
    ompi_osc_ucx_lock_t *lock = NULL;
    int ret = OMPI_SUCCESS;

    if (module->epoch_type.access != PASSIVE_EPOCH) {
        return OMPI_ERR_RMA_SYNC;
    }

    opal_hash_table_get_value_uint32(&module->outstanding_locks, (uint32_t) target, (void **) &lock);
    if (lock == NULL) {
        return OMPI_ERR_RMA_SYNC;
    }

    opal_hash_table_remove_value_uint32(&module->outstanding_locks,
                                        (uint32_t)target);

    ret = opal_common_ucx_wpmem_flush(module->mem, OPAL_COMMON_UCX_SCOPE_EP, target);
    if (ret != OMPI_SUCCESS) {
        return ret;
    }

    module->global_ops_num -= module->per_target_ops_nums[target];
    module->per_target_ops_nums[target] = 0;

    if (lock->is_nocheck == false) {
        if (lock->type == LOCK_EXCLUSIVE) {
            ret = end_exclusive(module, target);
        } else {
            ret = end_shared(module, target);
        }
    }

    OBJ_RELEASE(lock);

    module->lock_count--;
    assert(module->lock_count >= 0);
    if (module->lock_count == 0) {
        module->epoch_type.access = NONE_EPOCH;
        assert(module->global_ops_num == 0);
    }

    return ret;
}

int ompi_osc_ucx_lock_all(int assert, struct ompi_win_t *win) {
    ompi_osc_ucx_module_t *module = (ompi_osc_ucx_module_t*) win->w_osc_module;
    int ret = OMPI_SUCCESS;

    if (module->epoch_type.access != NONE_EPOCH &&
        module->epoch_type.access != FENCE_EPOCH) {
        return OMPI_ERR_RMA_SYNC;
    }

    module->epoch_type.access = PASSIVE_ALL_EPOCH;

    if (0 == (assert & MPI_MODE_NOCHECK)) {
        int i, comm_size;
        module->lock_all_is_nocheck = false;
        comm_size = ompi_comm_size(module->comm);
        for (i = 0; i < comm_size; i++) {
            ret = start_shared(module, i);
            if (ret != OMPI_SUCCESS) {
                int j;
                for (j = 0; j < i; j++) {
                    end_shared(module, j);
                }
                return ret;
            }
        }
    } else {
        module->lock_all_is_nocheck = true;
    }
    assert(OMPI_SUCCESS == ret);
    return OMPI_SUCCESS;
}

int ompi_osc_ucx_unlock_all(struct ompi_win_t *win) {
    ompi_osc_ucx_module_t *module = (ompi_osc_ucx_module_t*)win->w_osc_module;
    int comm_size = ompi_comm_size(module->comm);
    int ret = OMPI_SUCCESS;

    DBG_OUT(dbg_level, "start, mem = %p\n", (void *)module->mem);

    if (module->epoch_type.access != PASSIVE_ALL_EPOCH) {
        return OMPI_ERR_RMA_SYNC;
    }

    assert(module->lock_count == 0);

    ret = opal_common_ucx_wpmem_flush(module->mem, OPAL_COMMON_UCX_SCOPE_WORKER, 0);
    if (ret != OMPI_SUCCESS) {
        return ret;
    }

    DBG_OUT(dbg_level, "done flushing: mem = %p\n",
            (void *)module->mem);

    module->global_ops_num = 0;
    memset(module->per_target_ops_nums, 0, sizeof(int) * comm_size);

    if (!module->lock_all_is_nocheck) {
        int i;
        for (i = 0; i < comm_size; i++) {
            ret |= end_shared(module, i);
        }
    }

    module->epoch_type.access = NONE_EPOCH;

    DBG_OUT(dbg_level, "fini: mem = %p\n",
            (void *)module->mem);

    return ret;
}

int ompi_osc_ucx_sync(struct ompi_win_t *win) {
    ompi_osc_ucx_module_t *module = (ompi_osc_ucx_module_t *)win->w_osc_module;
    int ret = OMPI_SUCCESS;

    if (module->epoch_type.access != PASSIVE_EPOCH &&
        module->epoch_type.access != PASSIVE_ALL_EPOCH) {
        return OMPI_ERR_RMA_SYNC;
    }

    opal_atomic_mb();

    ret = opal_common_ucx_wpmem_fence(module->mem);
    if (ret != OMPI_SUCCESS) {
        OSC_UCX_VERBOSE(1, "opal_common_ucx_mem_fence failed: %d", ret);
    }

    return ret;
}

int ompi_osc_ucx_flush(int target, struct ompi_win_t *win) {
    ompi_osc_ucx_module_t *module = (ompi_osc_ucx_module_t*) win->w_osc_module;
    int ret = OMPI_SUCCESS;

    if (module->epoch_type.access != PASSIVE_EPOCH &&
        module->epoch_type.access != PASSIVE_ALL_EPOCH) {
        return OMPI_ERR_RMA_SYNC;
    }

    ret = opal_common_ucx_wpmem_flush(module->mem, OPAL_COMMON_UCX_SCOPE_EP, target);
    if (ret != OMPI_SUCCESS) {
        return ret;
    }

    module->global_ops_num -= module->per_target_ops_nums[target];
    module->per_target_ops_nums[target] = 0;

    return OMPI_SUCCESS;
}

int ompi_osc_ucx_flush_all(struct ompi_win_t *win) {
    ompi_osc_ucx_module_t *module = (ompi_osc_ucx_module_t *)win->w_osc_module;
    int ret = OMPI_SUCCESS;

    if (module->epoch_type.access != PASSIVE_EPOCH &&
        module->epoch_type.access != PASSIVE_ALL_EPOCH) {
        return OMPI_ERR_RMA_SYNC;
    }

    ret = opal_common_ucx_wpmem_flush(module->mem, OPAL_COMMON_UCX_SCOPE_WORKER, 0);
    if (ret != OMPI_SUCCESS) {
        return ret;
    }

    module->global_ops_num = 0;
    memset(module->per_target_ops_nums, 0,
           sizeof(int) * ompi_comm_size(module->comm));

    return OMPI_SUCCESS;
}

int ompi_osc_ucx_flush_local(int target, struct ompi_win_t *win) {
    /* TODO: currently euqals to ompi_osc_ucx_flush, should find a way
     * to implement local completion */
    return ompi_osc_ucx_flush(target, win);
}

int ompi_osc_ucx_flush_local_all(struct ompi_win_t *win) {
    /* TODO: currently euqals to ompi_osc_ucx_flush_all, should find a way
     * to implement local completion */
    return ompi_osc_ucx_flush_all(win);
}
