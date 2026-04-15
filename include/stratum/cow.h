#ifndef STM_COW_H
#define STM_COW_H

#include "stratum/types.h"
#include "stratum/block.h"
#include "stratum/btree.h"
#include "stratum/alloc.h"

struct stm_txn;

int  stm_txn_begin(struct stm_btree *tree, struct stm_alloc *alloc,
                   struct stm_txn **txn);
int  stm_txn_commit(struct stm_txn *txn);
void stm_txn_abort(struct stm_txn *txn);
uint64_t stm_txn_gen(struct stm_txn *txn);

#endif /* STM_COW_H */
