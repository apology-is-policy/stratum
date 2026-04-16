//! 9P2000 client — wire protocol over Unix socket or TCP.

use anyhow::{bail, Context, Result};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::path::Path;

// 9P2000 message types
const TVERSION: u8 = 100;
const RVERSION: u8 = 101;
const TATTACH: u8 = 104;
const RATTACH: u8 = 105;
const RERROR: u8 = 107;
const TWALK: u8 = 110;
const RWALK: u8 = 111;
const TOPEN: u8 = 112;
const ROPEN: u8 = 113;
const TCREATE: u8 = 114;
const RCREATE: u8 = 115;
const TREAD: u8 = 116;
const RREAD: u8 = 117;
const TWRITE: u8 = 118;
const RWRITE: u8 = 119;
const TCLUNK: u8 = 120;
const RCLUNK: u8 = 121;
const TREMOVE: u8 = 122;
const TSTAT: u8 = 124;
const RSTAT: u8 = 125;

const NOTAG: u16 = 0xFFFF;
const NOFID: u32 = 0xFFFFFFFF;
const MSIZE: u32 = 1 << 20;  // 1 MiB — matches P9_MSIZE_DEFAULT

pub const OREAD: u8 = 0;
pub const OWRITE: u8 = 1;
pub const ORDWR: u8 = 2;
pub const OTRUNC: u8 = 0x10;
pub const DMDIR: u32 = 0x80000000;
pub const QTDIR: u8 = 0x80;

#[derive(Debug, Clone)]
pub struct Qid {
    pub qtype: u8,
    pub vers: u32,
    pub path: u64,
}

#[derive(Debug, Clone)]
pub struct Stat {
    pub qid: Qid,
    pub mode: u32,
    pub atime: u32,
    pub mtime: u32,
    pub length: u64,
    pub name: String,
    pub uid: String,
    pub gid: String,
}

impl Stat {
    pub fn is_dir(&self) -> bool {
        self.mode & DMDIR != 0
    }
}

enum Transport {
    Unix(UnixStream),
    Tcp(TcpStream),
}

impl Read for Transport {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Transport::Unix(s) => s.read(buf),
            Transport::Tcp(s) => s.read(buf),
        }
    }
}

impl Write for Transport {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Transport::Unix(s) => s.write(buf),
            Transport::Tcp(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Transport::Unix(s) => s.flush(),
            Transport::Tcp(s) => s.flush(),
        }
    }
}

pub struct P9Client {
    conn: Transport,
    msize: u32,
    tag: u16,
    next_fid: u32,
    buf: Vec<u8>,
}

impl P9Client {
    pub fn connect_unix(path: &Path) -> Result<Self> {
        let conn = UnixStream::connect(path).context("9P connect")?;
        let mut c = Self {
            conn: Transport::Unix(conn),
            msize: MSIZE,
            tag: 0,
            next_fid: 1,
            buf: vec![0u8; MSIZE as usize],
        };
        c.version()?;
        Ok(c)
    }

    pub fn connect_tcp(addr: &str) -> Result<Self> {
        let conn = TcpStream::connect(addr).context("9P TCP connect")?;
        let mut c = Self {
            conn: Transport::Tcp(conn),
            msize: MSIZE,
            tag: 0,
            next_fid: 1,
            buf: vec![0u8; MSIZE as usize],
        };
        c.version()?;
        Ok(c)
    }

    fn alloc_fid(&mut self) -> u32 {
        let f = self.next_fid;
        self.next_fid += 1;
        f
    }

    fn next_tag(&mut self) -> u16 {
        self.tag = self.tag.wrapping_add(1);
        if self.tag == NOTAG {
            self.tag = 0;
        }
        self.tag
    }

    // ── wire helpers ──────────────────────────────────────────────

    fn send(&mut self, msg: &[u8]) -> Result<()> {
        self.conn.write_all(msg)?;
        self.conn.flush()?;
        Ok(())
    }

    fn recv(&mut self) -> Result<&[u8]> {
        // read 4-byte size
        let mut hdr = [0u8; 4];
        self.conn.read_exact(&mut hdr)?;
        let size = u32::from_le_bytes(hdr) as usize;
        if size < 7 || size > self.msize as usize {
            bail!("bad 9P message size {size}");
        }
        self.buf[..4].copy_from_slice(&hdr);
        self.conn.read_exact(&mut self.buf[4..size])?;
        // check for Rerror
        if self.buf[4] == RERROR {
            let elen = u16::from_le_bytes([self.buf[7], self.buf[8]]) as usize;
            let msg = std::str::from_utf8(&self.buf[9..9 + elen]).unwrap_or("?");
            bail!("9P error: {msg}");
        }
        Ok(&self.buf[..size])
    }

    fn build_msg(&self, typ: u8, tag: u16, body: &[u8]) -> Vec<u8> {
        let size = (7 + body.len()) as u32;
        let mut m = Vec::with_capacity(size as usize);
        m.extend_from_slice(&size.to_le_bytes());
        m.push(typ);
        m.extend_from_slice(&tag.to_le_bytes());
        m.extend_from_slice(body);
        m
    }

    // ── protocol operations ───────────────────────────────────────

    fn version(&mut self) -> Result<()> {
        let mut body = Vec::new();
        body.extend_from_slice(&MSIZE.to_le_bytes());
        put_str(&mut body, "9P2000");
        let msg = self.build_msg(TVERSION, NOTAG, &body);
        self.send(&msg)?;
        let resp = self.recv()?;
        if resp[4] != RVERSION {
            bail!("version failed");
        }
        self.msize = u32::from_le_bytes(resp[7..11].try_into()?);
        Ok(())
    }

    pub fn attach(&mut self, uname: &str, aname: &str) -> Result<u32> {
        let fid = self.alloc_fid();
        let tag = self.next_tag();
        let mut body = Vec::new();
        body.extend_from_slice(&fid.to_le_bytes());
        body.extend_from_slice(&NOFID.to_le_bytes());
        put_str(&mut body, uname);
        put_str(&mut body, aname);
        let msg = self.build_msg(TATTACH, tag, &body);
        self.send(&msg)?;
        let resp = self.recv()?;
        if resp[4] != RATTACH {
            bail!("attach failed");
        }
        Ok(fid)
    }

    pub fn walk(&mut self, fid: u32, names: &[&str]) -> Result<u32> {
        let newfid = self.alloc_fid();
        let tag = self.next_tag();
        let mut body = Vec::new();
        body.extend_from_slice(&fid.to_le_bytes());
        body.extend_from_slice(&newfid.to_le_bytes());
        body.extend_from_slice(&(names.len() as u16).to_le_bytes());
        for n in names {
            put_str(&mut body, n);
        }
        let msg = self.build_msg(TWALK, tag, &body);
        self.send(&msg)?;
        let resp = self.recv()?;
        if resp[4] != RWALK {
            bail!("walk failed");
        }
        // Check for partial walk — server walked fewer names than requested.
        // The newfid is assigned to the partial path, which is wrong for us.
        let nwqid = u16::from_le_bytes([resp[7], resp[8]]);
        if !names.is_empty() && (nwqid as usize) < names.len() {
            // Partial walk — clunk the partial fid and report failure
            let _ = self.clunk(newfid);
            bail!("walk: path component not found");
        }
        Ok(newfid)
    }

    pub fn open(&mut self, fid: u32, mode: u8) -> Result<()> {
        let tag = self.next_tag();
        let mut body = Vec::new();
        body.extend_from_slice(&fid.to_le_bytes());
        body.push(mode);
        let msg = self.build_msg(TOPEN, tag, &body);
        self.send(&msg)?;
        let resp = self.recv()?;
        if resp[4] != ROPEN {
            bail!("open failed");
        }
        Ok(())
    }

    pub fn create(&mut self, fid: u32, name: &str, perm: u32, mode: u8) -> Result<()> {
        let tag = self.next_tag();
        let mut body = Vec::new();
        body.extend_from_slice(&fid.to_le_bytes());
        put_str(&mut body, name);
        body.extend_from_slice(&perm.to_le_bytes());
        body.push(mode);
        let msg = self.build_msg(TCREATE, tag, &body);
        self.send(&msg)?;
        let resp = self.recv()?;
        if resp[4] != RCREATE {
            bail!("create failed");
        }
        Ok(())
    }

    pub fn read(&mut self, fid: u32, offset: u64, count: u32) -> Result<Vec<u8>> {
        let tag = self.next_tag();
        let mut body = Vec::new();
        body.extend_from_slice(&fid.to_le_bytes());
        body.extend_from_slice(&offset.to_le_bytes());
        body.extend_from_slice(&count.to_le_bytes());
        let msg = self.build_msg(TREAD, tag, &body);
        self.send(&msg)?;
        let resp = self.recv()?;
        if resp[4] != RREAD {
            bail!("read failed");
        }
        let n = u32::from_le_bytes(resp[7..11].try_into()?) as usize;
        Ok(resp[11..11 + n].to_vec())
    }

    pub fn write_data(&mut self, fid: u32, offset: u64, data: &[u8]) -> Result<u32> {
        let tag = self.next_tag();
        let mut body = Vec::new();
        body.extend_from_slice(&fid.to_le_bytes());
        body.extend_from_slice(&offset.to_le_bytes());
        body.extend_from_slice(&(data.len() as u32).to_le_bytes());
        body.extend_from_slice(data);
        let msg = self.build_msg(TWRITE, tag, &body);
        self.send(&msg)?;
        let resp = self.recv()?;
        if resp[4] != RWRITE {
            bail!("write failed");
        }
        Ok(u32::from_le_bytes(resp[7..11].try_into()?))
    }

    pub fn clunk(&mut self, fid: u32) -> Result<()> {
        let tag = self.next_tag();
        let msg = self.build_msg(TCLUNK, tag, &fid.to_le_bytes());
        self.send(&msg)?;
        let resp = self.recv()?;
        if resp[4] != RCLUNK {
            bail!("clunk failed");
        }
        Ok(())
    }

    pub fn remove(&mut self, fid: u32) -> Result<()> {
        let tag = self.next_tag();
        let msg = self.build_msg(TREMOVE, tag, &fid.to_le_bytes());
        self.send(&msg)?;
        self.recv()?;
        Ok(())
    }

    pub fn stat(&mut self, fid: u32) -> Result<Stat> {
        let tag = self.next_tag();
        let msg = self.build_msg(TSTAT, tag, &fid.to_le_bytes());
        self.send(&msg)?;
        let resp = self.recv()?;
        if resp[4] != RSTAT {
            bail!("stat failed");
        }
        // Rstat: [hdr:7][outer_sz:2][stat...]
        parse_stat(&resp[9..])
    }

    /// Read a directory listing (stat entries).
    pub fn readdir(&mut self, fid: u32) -> Result<Vec<Stat>> {
        self.open(fid, OREAD)?;
        let mut entries = Vec::new();
        let mut offset: u64 = 0;
        loop {
            let data = self.read(fid, offset, self.msize - 24)?;
            if data.is_empty() {
                break;
            }
            let mut pos = 0;
            while pos + 2 <= data.len() {
                let stat_len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
                if pos + 2 + stat_len > data.len() {
                    break;
                }
                if let Ok(s) = parse_stat(&data[pos..]) {
                    entries.push(s);
                }
                pos += 2 + stat_len;
            }
            offset += data.len() as u64;
        }
        Ok(entries)
    }
}

// ── wire format helpers ──────────────────────────────────────────────

fn put_str(buf: &mut Vec<u8>, s: &str) {
    buf.extend_from_slice(&(s.len() as u16).to_le_bytes());
    buf.extend_from_slice(s.as_bytes());
}

fn get_str(data: &[u8], pos: &mut usize) -> Result<String> {
    if *pos + 2 > data.len() {
        bail!("truncated string");
    }
    let len = u16::from_le_bytes([data[*pos], data[*pos + 1]]) as usize;
    *pos += 2;
    if *pos + len > data.len() {
        bail!("truncated string data");
    }
    let s = std::str::from_utf8(&data[*pos..*pos + len])?.to_string();
    *pos += len;
    Ok(s)
}

fn parse_qid(data: &[u8], pos: &mut usize) -> Result<Qid> {
    if *pos + 13 > data.len() {
        bail!("truncated qid");
    }
    let qtype = data[*pos];
    let vers = u32::from_le_bytes(data[*pos + 1..*pos + 5].try_into()?);
    let path = u64::from_le_bytes(data[*pos + 5..*pos + 13].try_into()?);
    *pos += 13;
    Ok(Qid { qtype, vers, path })
}

fn parse_stat(data: &[u8]) -> Result<Stat> {
    if data.len() < 2 {
        bail!("truncated stat");
    }
    let _stat_len = u16::from_le_bytes([data[0], data[1]]) as usize;
    let mut pos = 2;
    // type(2) + dev(4)
    pos += 6;
    let qid = parse_qid(data, &mut pos)?;
    if pos + 20 > data.len() {
        bail!("truncated stat fields");
    }
    let mode = u32::from_le_bytes(data[pos..pos + 4].try_into()?);
    pos += 4;
    let atime = u32::from_le_bytes(data[pos..pos + 4].try_into()?);
    pos += 4;
    let mtime = u32::from_le_bytes(data[pos..pos + 4].try_into()?);
    pos += 4;
    let length = u64::from_le_bytes(data[pos..pos + 8].try_into()?);
    pos += 8;
    let name = get_str(data, &mut pos)?;
    let uid = get_str(data, &mut pos)?;
    let gid = get_str(data, &mut pos)?;
    Ok(Stat {
        qid,
        mode,
        atime,
        mtime,
        length,
        name,
        uid,
        gid,
    })
}
