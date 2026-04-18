#include "test_main.h"
#include "stratum/p9.h"
#include "stratum/fs.h"

#include <unistd.h>
#include <errno.h>

static const char *img = "/tmp/stratum_test_p9.img";
static void cleanup(void) { unlink(img); }

/* ── wire-format message builder ────────────────────────────────────── */

static uint8_t reqbuf[65536], rspbuf[65536];

static void w16(uint8_t **p, uint16_t v) { (*p)[0] = v; (*p)[1] = v >> 8; *p += 2; }
static void w32(uint8_t **p, uint32_t v) {
    (*p)[0]=v; (*p)[1]=v>>8; (*p)[2]=v>>16; (*p)[3]=v>>24; *p += 4;
}
static void w64(uint8_t **p, uint64_t v) { w32(p,(uint32_t)v); w32(p,(uint32_t)(v>>32)); }
static void wstr(uint8_t **p, const char *s) {
    uint16_t l = (uint16_t)strlen(s);
    w16(p, l); memcpy(*p, s, l); *p += l;
}
static void whdr(uint8_t **p, uint8_t type, uint16_t tag) {
    *p += 4; /* size placeholder */
    *(*p)++ = type;
    w16(p, tag);
}
static uint32_t wfinish(uint8_t *start, uint8_t *end) {
    uint32_t len = (uint32_t)(end - start);
    start[0]=len; start[1]=len>>8; start[2]=len>>16; start[3]=len>>24;
    return len;
}

/* read helpers on response */
static uint16_t r16(const uint8_t *p) { return (uint16_t)p[0] | ((uint16_t)p[1]<<8); }
static uint32_t r32(const uint8_t *p) {
    return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);
}
static uint64_t r64(const uint8_t *p) { return (uint64_t)r32(p)|((uint64_t)r32(p+4)<<32); }

static int p9call(struct stm_9p *srv, uint8_t *req, uint32_t reqlen,
                  uint8_t *rsp, uint32_t *rsplen)
{
    *rsplen = 65536;
    return stm_9p_handle(srv, req, reqlen, rsp, rsplen);
}

/* ── version + attach ───────────────────────────────────────────────── */

STM_TEST(test_p9_version_attach)
{
    stm_fs_create(img, 32 * 1024 * 1024, NULL);
    struct stm_fs *fs;
    stm_fs_open(img, NULL, &fs);

    struct stm_9p *srv;
    stm_9p_create(fs, &srv);

    /* Tversion */
    {
        uint8_t *wp = reqbuf;
        uint32_t rlen;
        whdr(&wp, P9_TVERSION, P9_NOTAG);
        w32(&wp, P9_MSIZE_DEFAULT);
        wstr(&wp, "9P2000");
        p9call(srv, reqbuf, wfinish(reqbuf, wp), rspbuf, &rlen);
        STM_ASSERT_EQ(rspbuf[4], P9_RVERSION);
    }

    /* Tattach */
    {
        uint8_t *wp = reqbuf;
        uint32_t rlen;
        whdr(&wp, P9_TATTACH, 1);
        w32(&wp, 0);           /* fid=0 */
        w32(&wp, P9_NOFID);   /* afid */
        wstr(&wp, "user");
        wstr(&wp, "");
        p9call(srv, reqbuf, wfinish(reqbuf, wp), rspbuf, &rlen);
        STM_ASSERT_EQ(rspbuf[4], P9_RATTACH);
        /* QID should be a directory */
        STM_ASSERT_EQ(rspbuf[P9_HDR_SIZE] & P9_QTDIR, P9_QTDIR);
    }

    stm_9p_destroy(srv);
    stm_fs_close(fs);
    cleanup();
}

/* ── full workflow: create dir + file, write, read, stat ────────────── */

STM_TEST(test_p9_create_write_read)
{
    stm_fs_create(img, 64 * 1024 * 1024, NULL);
    struct stm_fs *fs;
    stm_fs_open(img, NULL, &fs);
    struct stm_9p *srv;
    stm_9p_create(fs, &srv);

    /* version */
    { uint8_t *wp = reqbuf; uint32_t rl;
      whdr(&wp, P9_TVERSION, P9_NOTAG);
      w32(&wp, P9_MSIZE_DEFAULT); wstr(&wp, "9P2000");
      p9call(srv, reqbuf, wfinish(reqbuf, wp), rspbuf, &rl); }

    /* attach fid=0 → root */
    { uint8_t *wp = reqbuf; uint32_t rl;
      whdr(&wp, P9_TATTACH, 1);
      w32(&wp, 0); w32(&wp, P9_NOFID); wstr(&wp, "u"); wstr(&wp, "");
      p9call(srv, reqbuf, wfinish(reqbuf, wp), rspbuf, &rl);
      STM_ASSERT_EQ(rspbuf[4], P9_RATTACH); }

    /* walk fid=0 → fid=1 (clone, 0 names) to get a fresh fid for create */
    { uint8_t *wp = reqbuf; uint32_t rl;
      whdr(&wp, P9_TWALK, 2);
      w32(&wp, 0); w32(&wp, 1); w16(&wp, 0);
      p9call(srv, reqbuf, wfinish(reqbuf, wp), rspbuf, &rl);
      STM_ASSERT_EQ(rspbuf[4], P9_RWALK); }

    /* create file "hello.txt" on fid=1 (fid now points to the new file) */
    { uint8_t *wp = reqbuf; uint32_t rl;
      whdr(&wp, P9_TCREATE, 3);
      w32(&wp, 1);              /* fid */
      wstr(&wp, "hello.txt");   /* name */
      w32(&wp, 0644);           /* perm (no DMDIR → regular file) */
      *wp++ = P9_ORDWR;         /* mode */
      p9call(srv, reqbuf, wfinish(reqbuf, wp), rspbuf, &rl);
      STM_ASSERT_EQ(rspbuf[4], P9_RCREATE); }

    /* write "Hello, 9P!" to fid=1 */
    { uint8_t *wp = reqbuf; uint32_t rl;
      const char *data = "Hello, 9P!";
      whdr(&wp, P9_TWRITE, 4);
      w32(&wp, 1);              /* fid */
      w64(&wp, 0);              /* offset */
      w32(&wp, 10);             /* count */
      memcpy(wp, data, 10); wp += 10;
      p9call(srv, reqbuf, wfinish(reqbuf, wp), rspbuf, &rl);
      STM_ASSERT_EQ(rspbuf[4], P9_RWRITE);
      STM_ASSERT_EQ(r32(rspbuf + P9_HDR_SIZE), 10u); /* written count */
    }

    /* clunk fid=1 */
    { uint8_t *wp = reqbuf; uint32_t rl;
      whdr(&wp, P9_TCLUNK, 5);
      w32(&wp, 1);
      p9call(srv, reqbuf, wfinish(reqbuf, wp), rspbuf, &rl);
      STM_ASSERT_EQ(rspbuf[4], P9_RCLUNK); }

    /* walk fid=0 → fid=2, name "hello.txt" */
    { uint8_t *wp = reqbuf; uint32_t rl;
      whdr(&wp, P9_TWALK, 6);
      w32(&wp, 0); w32(&wp, 2); w16(&wp, 1); wstr(&wp, "hello.txt");
      p9call(srv, reqbuf, wfinish(reqbuf, wp), rspbuf, &rl);
      STM_ASSERT_EQ(rspbuf[4], P9_RWALK);
      STM_ASSERT_EQ(r16(rspbuf + P9_HDR_SIZE), 1u); /* 1 qid */
    }

    /* stat fid=2 */
    { uint8_t *wp = reqbuf; uint32_t rl;
      whdr(&wp, P9_TSTAT, 7);
      w32(&wp, 2);
      p9call(srv, reqbuf, wfinish(reqbuf, wp), rspbuf, &rl);
      STM_ASSERT_EQ(rspbuf[4], P9_RSTAT);
      /* Rstat: [hdr:7][outer_sz:2][inner_sz:2][type:2][dev:4][qid:13][mode:4][atime:4][mtime:4][length:8] */
      uint64_t fsize = r64(rspbuf + P9_HDR_SIZE + 2 + 2 + 2 + 4 + 13 + 4 + 4 + 4);
      STM_ASSERT_EQ(fsize, 10u);
    }

    /* open fid=2 for reading */
    { uint8_t *wp = reqbuf; uint32_t rl;
      whdr(&wp, P9_TOPEN, 8);
      w32(&wp, 2); *wp++ = P9_OREAD;
      p9call(srv, reqbuf, wfinish(reqbuf, wp), rspbuf, &rl);
      STM_ASSERT_EQ(rspbuf[4], P9_ROPEN); }

    /* read from fid=2 */
    { uint8_t *wp = reqbuf; uint32_t rl;
      whdr(&wp, P9_TREAD, 9);
      w32(&wp, 2); w64(&wp, 0); w32(&wp, 4096);
      p9call(srv, reqbuf, wfinish(reqbuf, wp), rspbuf, &rl);
      STM_ASSERT_EQ(rspbuf[4], P9_RREAD);
      uint32_t count = r32(rspbuf + P9_HDR_SIZE);
      STM_ASSERT_EQ(count, 10u);
      STM_ASSERT_MEM_EQ(rspbuf + P9_HDR_SIZE + 4, "Hello, 9P!", 10);
    }

    /* clunk fid=2 */
    { uint8_t *wp = reqbuf; uint32_t rl;
      whdr(&wp, P9_TCLUNK, 10);
      w32(&wp, 2);
      p9call(srv, reqbuf, wfinish(reqbuf, wp), rspbuf, &rl); }

    stm_9p_destroy(srv);
    stm_fs_close(fs);
    cleanup();
}

/* ── readdir ────────────────────────────────────────────────────────── */

STM_TEST(test_p9_readdir)
{
    stm_fs_create(img, 64 * 1024 * 1024, NULL);
    struct stm_fs *fs;
    stm_fs_open(img, NULL, &fs);

    /* pre-populate via fs API */
    uint64_t ino;
    stm_fs_mkdir(fs, STM_ROOT_INO, "docs", 0755, &ino);
    stm_fs_create_file(fs, STM_ROOT_INO, "readme.txt", 0644, &ino);

    struct stm_9p *srv;
    stm_9p_create(fs, &srv);

    /* version + attach */
    { uint8_t *wp = reqbuf; uint32_t rl;
      whdr(&wp, P9_TVERSION, P9_NOTAG);
      w32(&wp, P9_MSIZE_DEFAULT); wstr(&wp, "9P2000");
      p9call(srv, reqbuf, wfinish(reqbuf, wp), rspbuf, &rl); }
    { uint8_t *wp = reqbuf; uint32_t rl;
      whdr(&wp, P9_TATTACH, 1);
      w32(&wp, 0); w32(&wp, P9_NOFID); wstr(&wp, "u"); wstr(&wp, "");
      p9call(srv, reqbuf, wfinish(reqbuf, wp), rspbuf, &rl); }

    /* open root for reading */
    { uint8_t *wp = reqbuf; uint32_t rl;
      whdr(&wp, P9_TOPEN, 2);
      w32(&wp, 0); *wp++ = P9_OREAD;
      p9call(srv, reqbuf, wfinish(reqbuf, wp), rspbuf, &rl);
      STM_ASSERT_EQ(rspbuf[4], P9_ROPEN); }

    /* read directory */
    { uint8_t *wp = reqbuf; uint32_t rl;
      whdr(&wp, P9_TREAD, 3);
      w32(&wp, 0); w64(&wp, 0); w32(&wp, 65536);
      p9call(srv, reqbuf, wfinish(reqbuf, wp), rspbuf, &rl);
      STM_ASSERT_EQ(rspbuf[4], P9_RREAD);
      uint32_t count = r32(rspbuf + P9_HDR_SIZE);
      STM_ASSERT(count > 0);  /* should contain stat entries for docs + readme.txt */
    }

    stm_9p_destroy(srv);
    stm_fs_close(fs);
    cleanup();
}

/* R7-2 regressions: malformed wire inputs must not crash or leak. */
STM_TEST(test_p9_wire_validation)
{
    stm_fs_create(img, 32 * 1024 * 1024, NULL);
    struct stm_fs *fs;
    stm_fs_open(img, NULL, &fs);
    struct stm_9p *srv;
    stm_9p_create(fs, &srv);

    /* Attacker sends Tversion with msize=0. Must clamp to P9_MSIZE_MIN. */
    { uint8_t *wp = reqbuf; uint32_t rl;
      whdr(&wp, P9_TVERSION, P9_NOTAG);
      w32(&wp, 0);          /* client_msize = 0 */
      wstr(&wp, "9P2000");
      p9call(srv, reqbuf, wfinish(reqbuf, wp), rspbuf, &rl);
      STM_ASSERT_EQ(rspbuf[4], P9_RVERSION);
      uint32_t negotiated = r32(rspbuf + P9_HDR_SIZE);
      STM_ASSERT(negotiated >= 256);
    }

    /* Now attach so subsequent calls reach the real handlers. */
    { uint8_t *wp = reqbuf; uint32_t rl;
      whdr(&wp, P9_TATTACH, 1);
      w32(&wp, 0); w32(&wp, P9_NOFID); wstr(&wp, "u"); wstr(&wp, "");
      p9call(srv, reqbuf, wfinish(reqbuf, wp), rspbuf, &rl);
      STM_ASSERT_EQ(rspbuf[4], P9_RATTACH);
    }

    /* Create a file so we have an open fid to write to. */
    { uint8_t *wp = reqbuf; uint32_t rl;
      whdr(&wp, P9_TCREATE, 2);
      w32(&wp, 0); wstr(&wp, "victim.bin"); w32(&wp, 0644); *wp++ = P9_ORDWR;
      p9call(srv, reqbuf, wfinish(reqbuf, wp), rspbuf, &rl);
      STM_ASSERT_EQ(rspbuf[4], P9_RCREATE);
    }

    /* P1-2: Twrite with count > actual payload must Rerror, not crash. */
    { uint8_t *wp = reqbuf; uint32_t rl;
      whdr(&wp, P9_TWRITE, 3);
      w32(&wp, 0);                  /* fid */
      w64(&wp, 0);                  /* offset */
      w32(&wp, 1000000);            /* count wildly > payload */
      /* NO payload follows — just the header + 16 bytes */
      p9call(srv, reqbuf, wfinish(reqbuf, wp), rspbuf, &rl);
      STM_ASSERT_EQ(rspbuf[4], P9_RERROR);
    }

    /* P1-3: Twalk with nwname=5 but no name strings. Must Rerror. */
    { uint8_t *wp = reqbuf; uint32_t rl;
      whdr(&wp, P9_TWALK, 4);
      w32(&wp, 0);                  /* fid */
      w32(&wp, 99);                 /* newfid */
      w16(&wp, 5);                  /* nwname = 5, but no strings follow */
      p9call(srv, reqbuf, wfinish(reqbuf, wp), rspbuf, &rl);
      STM_ASSERT_EQ(rspbuf[4], P9_RERROR);
    }

    /* Truncated Tread header (only 8 bytes instead of 16). */
    { uint8_t *wp = reqbuf; uint32_t rl;
      whdr(&wp, P9_TREAD, 5);
      w32(&wp, 0); w32(&wp, 0);     /* only 8 bytes of body instead of 16 */
      p9call(srv, reqbuf, wfinish(reqbuf, wp), rspbuf, &rl);
      STM_ASSERT_EQ(rspbuf[4], P9_RERROR);
    }

    stm_9p_destroy(srv);
    stm_fs_close(fs);
    cleanup();
}

/* R7-5: (a) Creating a file while another fid caches the parent's listing
 * must invalidate the other fid's cache; (b) fid_alloc on an already-active
 * fid must refuse. */
STM_TEST(test_p9_fid_cache_and_dup)
{
    stm_fs_create(img, 32 * 1024 * 1024, NULL);
    struct stm_fs *fs;
    stm_fs_open(img, NULL, &fs);
    struct stm_9p *srv;
    stm_9p_create(fs, &srv);

    /* Tversion + Tattach */
    { uint8_t *wp = reqbuf; uint32_t rl;
      whdr(&wp, P9_TVERSION, P9_NOTAG);
      w32(&wp, P9_MSIZE_DEFAULT);
      wstr(&wp, "9P2000");
      p9call(srv, reqbuf, wfinish(reqbuf, wp), rspbuf, &rl); }
    { uint8_t *wp = reqbuf; uint32_t rl;
      whdr(&wp, P9_TATTACH, 1);
      w32(&wp, 0); w32(&wp, P9_NOFID); wstr(&wp, "u"); wstr(&wp, "");
      p9call(srv, reqbuf, wfinish(reqbuf, wp), rspbuf, &rl);
      STM_ASSERT_EQ(rspbuf[4], P9_RATTACH); }

    /* Walk fid 0 to a fresh fid 1 at root (nwname=0 → stays at root). */
    { uint8_t *wp = reqbuf; uint32_t rl;
      whdr(&wp, P9_TWALK, 2);
      w32(&wp, 0); w32(&wp, 1); w16(&wp, 0);
      p9call(srv, reqbuf, wfinish(reqbuf, wp), rspbuf, &rl);
      STM_ASSERT_EQ(rspbuf[4], P9_RWALK); }

    /* Open fid 1 for read. */
    { uint8_t *wp = reqbuf; uint32_t rl;
      whdr(&wp, P9_TOPEN, 3);
      w32(&wp, 1); *wp++ = P9_OREAD;
      p9call(srv, reqbuf, wfinish(reqbuf, wp), rspbuf, &rl);
      STM_ASSERT_EQ(rspbuf[4], P9_ROPEN); }

    /* First readdir populates fid 1's cache (possibly empty at this point). */
    { uint8_t *wp = reqbuf; uint32_t rl;
      whdr(&wp, P9_TREAD, 4);
      w32(&wp, 1); w64(&wp, 0); w32(&wp, 65000);
      p9call(srv, reqbuf, wfinish(reqbuf, wp), rspbuf, &rl);
      STM_ASSERT_EQ(rspbuf[4], P9_RREAD); }

    /* Now create a file via fid 0 (same dir as fid 1 — both at root). */
    { uint8_t *wp = reqbuf; uint32_t rl;
      whdr(&wp, P9_TCREATE, 5);
      w32(&wp, 0); wstr(&wp, "late_entry.txt"); w32(&wp, 0644); *wp++ = P9_ORDWR;
      p9call(srv, reqbuf, wfinish(reqbuf, wp), rspbuf, &rl);
      STM_ASSERT_EQ(rspbuf[4], P9_RCREATE); }

    /* fid 1's cache MUST have been invalidated. Re-read from offset 0 —
     * the listing should now include "late_entry.txt". */
    { uint8_t *wp = reqbuf; uint32_t rl;
      whdr(&wp, P9_TREAD, 6);
      w32(&wp, 1); w64(&wp, 0); w32(&wp, 65000);
      p9call(srv, reqbuf, wfinish(reqbuf, wp), rspbuf, &rl);
      STM_ASSERT_EQ(rspbuf[4], P9_RREAD);
      uint32_t count = r32(rspbuf + P9_HDR_SIZE);
      int found = 0;
      /* Scan the readdir buffer for our filename — simple substring search
       * suffices (the name is encoded as [u16 len][bytes]). */
      const uint8_t *p = rspbuf + P9_HDR_SIZE + 4;
      uint32_t i;
      for (i = 0; i + 14 <= count; i++) {
          if (memcmp(p + i, "late_entry.txt", 14) == 0) { found = 1; break; }
      }
      STM_ASSERT(found);
    }

    /* Duplicate fid_alloc: walking fid 0 to newfid 0 with nwname=0 is
     * the "same fid" case (clone, not alloc) — that one should succeed.
     * But TATTACH with fid=1 (already active) must refuse. */
    { uint8_t *wp = reqbuf; uint32_t rl;
      whdr(&wp, P9_TATTACH, 7);
      w32(&wp, 1);                   /* fid = 1, already bound */
      w32(&wp, P9_NOFID); wstr(&wp, "u"); wstr(&wp, "");
      p9call(srv, reqbuf, wfinish(reqbuf, wp), rspbuf, &rl);
      STM_ASSERT_EQ(rspbuf[4], P9_RERROR);
    }

    stm_9p_destroy(srv);
    stm_fs_close(fs);
    cleanup();
}

int main(void)
{
    STM_SUITE("p9");
    STM_RUN(test_p9_version_attach);
    STM_RUN(test_p9_create_write_read);
    STM_RUN(test_p9_readdir);
    STM_RUN(test_p9_wire_validation);
    STM_RUN(test_p9_fid_cache_and_dup);
    printf("all passed\n");
    return 0;
}
