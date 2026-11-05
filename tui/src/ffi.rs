//! FFI bindings to libstratum-9p.
//!
//! Hand-written rather than bindgen-generated — the surface is small
//! enough that maintaining the bindings explicitly is cheaper than the
//! bindgen toolchain dependency. Mirrors `<stratum/9p_client.h>`
//! exactly; if you add a primitive there, mirror it here.
//!
//! Trust-boundary discipline carry from R111: every count returned by
//! the C lib is already bound-checked against caller caps inside the
//! lib itself; the Rust wrapper just respects the documented status
//! semantics.

#![allow(dead_code)]
#![allow(non_camel_case_types)]

use std::os::raw::{c_char, c_int};

pub type stm_status = c_int;

// Status codes — values mirror v2 include/stratum/types.h. Don't
// mis-guess these; even an off-by-one breaks err mapping silently.
pub const STM_OK: stm_status = 0;
pub const STM_EINVAL: stm_status = -22;
pub const STM_ENOMEM: stm_status = -12;
pub const STM_EIO: stm_status = -5;
pub const STM_ENOENT: stm_status = -2;
pub const STM_EEXIST: stm_status = -17;
pub const STM_EACCES: stm_status = -13;
pub const STM_EBUSY: stm_status = -16;
pub const STM_EROFS: stm_status = -30;
pub const STM_EXDEV: stm_status = -18;
pub const STM_ENOTDIR: stm_status = -20;
pub const STM_EWEDGED: stm_status = -204;
pub const STM_ENOTSUPPORTED: stm_status = -205;
pub const STM_EBACKEND: stm_status = -207;

/// 9P qid type bits.
pub const STM_9P_QTDIR: u8 = 0x80;
pub const STM_9P_QTSYMLINK: u8 = 0x02;

/// Linux open flags accepted by stm_9p_lopen.
pub const STM_9P_O_RDONLY: u32 = 0;
pub const STM_9P_O_DIRECTORY: u32 = 0x10000;

/// Tgetattr request mask.
pub const STM_9P_GETATTR_BASIC: u64 = 0x000007ff;

pub const STM_9P_MAX_WALK: u16 = 16;
pub const STM_9P_MSIZE_DEFAULT: u32 = 64 * 1024;
pub const STM_9P_NOFID: u32 = 0xffffffff;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct stm_9p_qid {
    pub qtype: u8,
    pub version: u32,
    pub path: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct stm_9p_attr {
    pub valid: u64,
    pub qid: stm_9p_qid,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u64,
    pub rdev: u64,
    pub size: u64,
    pub blksize: u64,
    pub blocks: u64,
    pub atime_sec: u64,
    pub atime_nsec: u64,
    pub mtime_sec: u64,
    pub mtime_nsec: u64,
    pub ctime_sec: u64,
    pub ctime_nsec: u64,
    pub btime_sec: u64,
    pub btime_nsec: u64,
    pub gen: u64,
    pub data_version: u64,
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

pub type stm_9p_dirent_cb = extern "C" fn(
    qid: *const stm_9p_qid,
    cookie: u64,
    dt_type: u8,
    name: *const c_char,
    name_len: usize,
    ctx: *mut std::ffi::c_void,
) -> stm_status;

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

    pub fn stm_9p_lcreate(
        c: *mut stm_9p_client,
        fid: u32,
        name: *const c_char,
        flags: u32,
        mode: u32,
        gid: u32,
        out_qid: *mut stm_9p_qid,
        out_iounit: *mut u32,
    ) -> stm_status;

    pub fn stm_9p_mkdir(
        c: *mut stm_9p_client,
        dfid: u32,
        name: *const c_char,
        mode: u32,
        gid: u32,
        out_qid: *mut stm_9p_qid,
    ) -> stm_status;

    pub fn stm_9p_unlinkat(
        c: *mut stm_9p_client,
        dirfd: u32,
        name: *const c_char,
        flags: u32,
    ) -> stm_status;

    pub fn stm_9p_clunk(c: *mut stm_9p_client, fid: u32) -> stm_status;

    pub fn stm_9p_getattr(
        c: *mut stm_9p_client,
        fid: u32,
        request_mask: u64,
        out: *mut stm_9p_attr,
    ) -> stm_status;

    pub fn stm_9p_readdir(
        c: *mut stm_9p_client,
        fid: u32,
        offset: u64,
        count: u32,
        cb: stm_9p_dirent_cb,
        cb_ctx: *mut std::ffi::c_void,
        out_entries: *mut u32,
        out_next_offset: *mut u64,
    ) -> stm_status;
}
