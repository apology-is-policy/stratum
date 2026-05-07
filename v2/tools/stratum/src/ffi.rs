//! FFI bindings — libstratum-9p client + cmd run-main entry points.
//!
//! Two extern blocks:
//!   1. The 9P2000.L client surface (mirrors v2/include/stratum/9p_client.h).
//!      Used by src/slate.rs to dial slate / stratumd over Unix sockets.
//!   2. The cmd run-main entry points (declared in v2/include/stratum/cmds.h).
//!      Used by src/main.rs to dispatch subcommands to the same code
//!      paths the standalone C binaries use.

#![allow(dead_code)]
#![allow(non_camel_case_types)]

use std::os::raw::{c_char, c_int};

pub type stm_status = c_int;

pub const STM_OK: stm_status = 0;
pub const STM_EINVAL: stm_status = -22;
pub const STM_EIO: stm_status = -5;
pub const STM_ENOENT: stm_status = -2;
pub const STM_EACCES: stm_status = -13;
pub const STM_EBUSY: stm_status = -16;
pub const STM_EBACKEND: stm_status = -207;

pub const STM_9P_O_RDONLY: u32 = 0;
pub const STM_9P_O_WRONLY: u32 = 1;
pub const STM_9P_O_RDWR: u32 = 2;

pub const STM_9P_MAX_WALK: u16 = 16;
pub const STM_9P_MSIZE_DEFAULT: u32 = 128 * 1024;
pub const STM_9P_NOFID: u32 = 0xffffffff;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct stm_9p_qid {
    pub qtype: u8,
    pub version: u32,
    pub path: u64,
}

#[repr(C)]
pub struct stm_9p_dial_opts {
    pub msize: u32,
    pub uname: *const c_char,
    pub aname: *const c_char,
    pub n_uname: u32,
    pub root_fid: u32,
}

#[repr(C)]
pub struct stm_9p_client {
    _opaque: [u8; 0],
}

extern "C" {
    pub fn stm_9p_dial_unix(
        socket_path: *const c_char,
        opts: *const stm_9p_dial_opts,
        out: *mut *mut stm_9p_client,
    ) -> stm_status;

    pub fn stm_9p_close(c: *mut stm_9p_client);

    pub fn stm_9p_msize(c: *const stm_9p_client) -> u32;

    pub fn stm_9p_walk(
        c: *mut stm_9p_client,
        fid: u32,
        new_fid: u32,
        n_names: u16,
        names: *const *const c_char,
        out_qids: *mut stm_9p_qid,
        out_walked: *mut u16,
    ) -> stm_status;

    pub fn stm_9p_lopen(
        c: *mut stm_9p_client,
        fid: u32,
        flags: u32,
        out_qid: *mut stm_9p_qid,
        out_iounit: *mut u32,
    ) -> stm_status;

    pub fn stm_9p_read(
        c: *mut stm_9p_client,
        fid: u32,
        offset: u64,
        buf: *mut u8,
        count: u32,
        out_count: *mut u32,
    ) -> stm_status;

    pub fn stm_9p_write(
        c: *mut stm_9p_client,
        fid: u32,
        offset: u64,
        buf: *const u8,
        count: u32,
        out_written: *mut u32,
    ) -> stm_status;

    pub fn stm_9p_clunk(c: *mut stm_9p_client, fid: u32) -> stm_status;
}

// ── cmd run-main entry points (from v2/include/stratum/cmds.h) ────────

extern "C" {
    pub fn stm_cmd_stratumd_main(argc: c_int, argv: *const *const c_char) -> c_int;
    pub fn stm_cmd_slate_main   (argc: c_int, argv: *const *const c_char) -> c_int;
    pub fn stm_cmd_mkfs_main    (argc: c_int, argv: *const *const c_char) -> c_int;
    pub fn stm_cmd_fs_main      (argc: c_int, argv: *const *const c_char) -> c_int;
}
