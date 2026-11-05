/* SPDX-License-Identifier: ISC */
/* stratum-fs standalone binary — thin wrapper over stm_cmd_fs_main. */
#include <stratum/cmds.h>

int main(int argc, char **argv)
{
    return stm_cmd_fs_main(argc, argv);
}
