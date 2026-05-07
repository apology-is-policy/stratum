/* SPDX-License-Identifier: ISC */
/* stratum-mkfs standalone binary — thin wrapper over stm_cmd_mkfs_main. */
#include <stratum/cmds.h>

int main(int argc, char **argv)
{
    return stm_cmd_mkfs_main(argc, argv);
}
