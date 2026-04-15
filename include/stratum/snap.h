#ifndef STM_SNAP_H
#define STM_SNAP_H

#include "stratum/types.h"

struct stm_fs;

int stm_snap_create(struct stm_fs *fs, const char *name, uint64_t *out_id);
int stm_snap_delete(struct stm_fs *fs, uint64_t snap_id);
int stm_snap_list(struct stm_fs *fs,
                  int (*cb)(uint64_t snap_id, const char *name,
                            uint64_t gen, void *ctx),
                  void *ctx);
int stm_snap_rollback(struct stm_fs *fs, uint64_t snap_id);

#endif /* STM_SNAP_H */
