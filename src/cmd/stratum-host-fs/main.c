/* SPDX-License-Identifier: GPL-3.0-or-later */
/* stratum-host-fs standalone binary — thin wrapper over stm_cmd_host_fs_main. */
#include <stratum/cmds.h>

int main(int argc, char **argv)
{
    return stm_cmd_host_fs_main(argc, argv);
}
