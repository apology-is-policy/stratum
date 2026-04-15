#ifndef STM_SNAPSHOT_H
#define STM_SNAPSHOT_H

#include "stratum/types.h"
#include "stratum/bptr.h"

/*
 * stm_snapshot — snapshot descriptor.
 *
 * Stored in the snapshot tree (secondary Bε-tree at ss_snap_root).
 * Each snapshot records the root bptr of the main tree at the
 * moment it was taken.
 */

struct __attribute__((packed)) stm_snapshot {
    le64            ssp_id;
    le64            ssp_parent_id;    /* 0 = root snapshot */
    le64            ssp_gen;
    struct stm_bptr ssp_root;        /* root of the snapshotted tree */
    le32            ssp_refcount;
    le16            ssp_tree_height;  /* main tree height at snapshot time */
    uint8_t         ssp_pad;
};

STM_STATIC_ASSERT(sizeof(struct stm_snapshot) == 88, stm_snapshot_size);

#endif /* STM_SNAPSHOT_H */
