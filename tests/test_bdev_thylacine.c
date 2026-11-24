/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * The Thylacine virtio-blk driver (src/block/bdev_thylacine.c) on the host,
 * against a scripted device.
 *
 * The driver is compiled into this file with THYLA_BDEV_FAKE_DEVICE: its
 * three fixed VAs become static buffers, its MMIO accessors call the fake
 * below, and syscall() is the fake kernel. Everything else is the
 * driver's own code.
 *
 * The fake answers one virtio-mmio slot (31) as a version-2 block device
 * offering VIRTIO_BLK_F_FLUSH, and completes a request the way QEMU does
 * (virtio_blk_req_complete, then virtio_notify): the status byte and the
 * used element, then used.idx, then the interrupt status bit, with one
 * edge for the kernel to count when the bit goes from clear to set
 * (virtio-mmio is EDGE on the GIC; an edge with no waiter is counted and
 * handed to the next wait, kernel/irqfwd.c). INTERRUPT_ACK clears bits;
 * a STATUS write of 0 is a reset, which completes a request still in
 * flight (QEMU's blk_drain) and then clears the status, the interrupt
 * status and the device's used counter. A wait with no edge to hand out
 * lets the scripted device act, then answers what it counted: 0 is a
 * timeout.
 */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "tharness.h"

static _Alignas(4096) uint8_t g_mmio[0x4000];
static _Alignas(4096) uint8_t g_ring[0x1000];
static _Alignas(4096) uint8_t g_data[1u << 20];

#define THYLA_BDEV_FAKE_DEVICE 1
#define THYLA_MMIO_USER_VA ((uint64_t)(uintptr_t)g_mmio)
#define THYLA_RING_USER_VA ((uint64_t)(uintptr_t)g_ring)
#define THYLA_DATA_USER_VA ((uint64_t)(uintptr_t)g_data)

#define __NR_mmio_create 2
#define __NR_mmio_map    3
#define __NR_irq_create  4
#define __NR_irq_wait    5
#define __NR_dma_create  6
#define __NR_dma_map     7

/* What the device does with a request while the driver waits on it. */
typedef enum {
    F_NOW,          /* completes during the first wait */
    F_SLOW,         /* completes during the wait after `k` timeouts */
    F_RACE,         /* the k-th wait times out; the device completes right
                     * after the driver's next interrupt-status read */
    F_LOST_EDGE,    /* completes during the k-th wait with no edge counted */
    F_NEEDS_RESET,  /* refuses it: DEVICE_NEEDS_RESET + a config interrupt */
    F_NR_NO_EDGE,   /* the same, and the interrupt's edge is lost */
    F_CONFIG_FIRST, /* a configuration change as QEMU raises it (status
                     * 0x3), then completes on the next wait */
    F_CONFIG_BIT1,  /* the same with bit 1 alone, the spec's (VIRTIO 1.2
                     * 4.2.2) */
    F_STORM,        /* configuration interrupts, one a wait, no answer */
    F_WAIT_FAILS,   /* the kernel fails the first wait; completes on the next */
    F_USED_TWO      /* completes twice over: used.idx moves by two */
} fake_mode;

#define FAKE_MAX_REQS 128u
/* Waits one request may block in before the fake kernel fails the wait:
 * a driver that never ends a request ends the test instead. */
#define FAKE_WAITS_MAX 100000u

static struct {
    uint32_t status;
    uint32_t isr;
    uint32_t feat_sel;
    uint32_t pending;           /* edges counted with no waiter */
    uint16_t used;              /* the device's used.idx */
    bool     inflight;
    uint32_t nreq;              /* QUEUE_NOTIFY writes since open */
    fake_mode mode[FAKE_MAX_REQS];
    uint32_t k[FAKE_MAX_REQS];
    uint32_t waits;             /* waits the device acted in, this request */
    uint32_t blocked;           /* waits with no edge to hand out, this request */
    bool     complete_after_isr_read;
    bool     wait_failed;       /* F_WAIT_FAILS has failed a wait, this request */
    uint32_t drained;
    uint32_t notifies;
} F;

#define FAKE_SLOT_OFF (31u * 0x200u)

static void fake_irq(uint32_t bits, bool edge)
{
    uint32_t old = F.isr;
    F.isr |= bits;
    if (old == 0 && edge) F.pending++;
}

static void fake_complete(bool edge)
{
    g_ring[0x310] = 0;                              /* VIRTIO_BLK_S_OK */
    uint32_t e = 0x200u + 4u + (uint32_t)(F.used % 16u) * 8u;
    memset(g_ring + e, 0, 8);                       /* id 0, len 0 */
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    F.used++;
    memcpy(g_ring + 0x202, &F.used, sizeof F.used);
    F.inflight = false;
    fake_irq(1u, edge);
}

static uint32_t fake_reg_read(uint32_t off)
{
    switch (off) {
    case 0x000: return 0x74726976u;                 /* "virt" */
    case 0x004: return 2u;                          /* version */
    case 0x008: return 2u;                          /* block device */
    case 0x010: return F.feat_sel == 0 ? (1u << 9) : 1u; /* FLUSH; VERSION_1 */
    case 0x034: return 256u;                        /* QUEUE_NUM_MAX */
    case 0x060: {
        uint32_t v = F.isr;
        if (F.complete_after_isr_read) {
            F.complete_after_isr_read = false;
            fake_complete(true);
        }
        return v;
    }
    case 0x070: return F.status;
    case 0x100: return 0x200000u;                   /* capacity, sectors */
    default:    return 0u;
    }
}

static void fake_reg_write(uint32_t off, uint32_t v)
{
    switch (off) {
    case 0x014: F.feat_sel = v; break;
    case 0x050:
        F.notifies++;
        if (F.nreq < FAKE_MAX_REQS - 1u) F.nreq++;
        F.inflight = true;
        F.waits = 0;
        F.blocked = 0;
        F.wait_failed = false;
        break;
    case 0x064: F.isr &= ~v; break;
    case 0x070:
        if (v == 0) {
            if (F.inflight) { fake_complete(true); F.drained++; }
            F.status = 0;
            F.isr = 0;
            F.used = 0;
        } else {
            F.status = v;
        }
        break;
    default: break;
    }
}

/* 1: a register of the fake's slot (*off set); 0: another slot of the
 * bank (reads 0, writes dropped); -1: memory (the ring, the data). */
static int fake_reg(uint64_t addr, uint32_t *off)
{
    uint64_t base = (uint64_t)(uintptr_t)g_mmio;
    if (addr < base || addr >= base + sizeof g_mmio) return -1;
    uint64_t o = addr - base;
    if (o < FAKE_SLOT_OFF || o >= FAKE_SLOT_OFF + 0x200u) return 0;
    *off = (uint32_t)(o - FAKE_SLOT_OFF);
    return 1;
}

static inline uint32_t mmio_read32(uint64_t addr)
{
    uint32_t off = 0;
    int w = fake_reg(addr, &off);
    if (w < 0) return *(volatile uint32_t *)(uintptr_t)addr;
    return w ? fake_reg_read(off) : 0u;
}
static inline void mmio_write32(uint64_t addr, uint32_t val)
{
    uint32_t off = 0;
    int w = fake_reg(addr, &off);
    if (w < 0) *(volatile uint32_t *)(uintptr_t)addr = val;
    else if (w) fake_reg_write(off, val);
}
static inline void mmio_write16(uint64_t addr, uint16_t val)
{
    *(volatile uint16_t *)(uintptr_t)addr = val;
}
static inline uint16_t mmio_read16(uint64_t addr)
{
    return *(volatile uint16_t *)(uintptr_t)addr;
}
static inline void mmio_write64(uint64_t addr, uint64_t val)
{
    *(volatile uint64_t *)(uintptr_t)addr = val;
}
static inline uint8_t mmio_read_u8(uint64_t addr)
{
    return *(volatile uint8_t *)(uintptr_t)addr;
}
static inline void dsb_sy(void)
{
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
}
static inline void virtio_rmb(void)
{
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
}

static uint32_t g_dma_maps;

static void fake_device_acts(void)
{
    uint32_t r = F.nreq;
    uint32_t k = F.k[r];
    F.waits++;
    switch (F.mode[r]) {
    case F_NOW:
        fake_complete(true);
        break;
    case F_SLOW:
        if (F.waits > k) fake_complete(true);
        break;
    case F_RACE:
        if (F.waits == k) F.complete_after_isr_read = true;
        else if (F.waits > k) fake_complete(true);
        break;
    case F_LOST_EDGE:
        if (F.waits >= k) fake_complete(F.waits > k);
        break;
    case F_NEEDS_RESET:
        F.inflight = false;
        F.status |= 64u;                            /* DEVICE_NEEDS_RESET */
        fake_irq(3u, true);                         /* virtio_notify_config */
        break;
    case F_NR_NO_EDGE:
        F.inflight = false;
        F.status |= 64u;
        fake_irq(3u, false);
        break;
    case F_CONFIG_FIRST:
        if (F.waits == 1) fake_irq(3u, true);       /* virtio_notify_config */
        else fake_complete(true);
        break;
    case F_CONFIG_BIT1:
        if (F.waits == 1) fake_irq(2u, true);
        else fake_complete(true);
        break;
    case F_STORM:
        fake_irq(3u, true);
        break;
    case F_WAIT_FAILS:
        fake_complete(true);
        break;
    case F_USED_TWO:
        fake_complete(true);
        fake_complete(true);
        break;
    }
}

static long fake_syscall(long nr, ...)
{
    switch (nr) {
    case __NR_mmio_create: return 100;
    case __NR_mmio_map:    return 0;
    case __NR_irq_create:  return 200;
    case __NR_dma_create:  return 300 + (long)g_dma_maps;
    case __NR_dma_map:
        return 0x40000000L + (long)(g_dma_maps++) * 0x100000L;
    case __NR_irq_wait: {
        if (F.inflight && F.mode[F.nreq] == F_WAIT_FAILS && !F.wait_failed) {
            F.wait_failed = true;
            return -1;
        }
        if (F.pending == 0) {
            if (++F.blocked > FAKE_WAITS_MAX) return -5;
            if (F.inflight) fake_device_acts();
        }
        long c = (long)F.pending;
        F.pending = 0;
        return c;
    }
    default:
        return -1;
    }
}
#include "bdev_internal.h"
/* bdev_internal.h declares it only for Thylacine. */
stm_status stm_bdev_open_thylacine(const char *path,
                                   const stm_bdev_open_opts *opts,
                                   stm_bdev **out);

#define syscall fake_syscall
#include "bdev_thylacine.c"

/* ------------------------------------------------------------------------- */

static stm_bdev *fake_open(void)
{
    memset(&F, 0, sizeof F);
    memset(g_ring, 0, sizeof g_ring);
    g_dma_maps = 0;
    stm_bdev *bd = NULL;
    STM_ASSERT_OK(stm_bdev_open_thylacine("/dev/fake", NULL, &bd));
    return bd;
}

/* Request n (1-based, counted by QUEUE_NOTIFY from the open) does `m`. */
static void fake_script(uint32_t n, fake_mode m, uint32_t k)
{
    F.mode[F.nreq + n] = m;
    F.k[F.nreq + n] = k;
}

/* The driver's BDEVDIAG lines go to fd 2: catch them in a file. */
static int  g_saved_stderr = -1;
static FILE *g_lines;

static void lines_begin(void)
{
    fflush(stderr);
    g_lines = tmpfile();
    STM_ASSERT(g_lines != NULL);
    g_saved_stderr = dup(2);
    STM_ASSERT(g_saved_stderr >= 0);
    STM_ASSERT(dup2(fileno(g_lines), 2) == 2);
}

static char g_text[1u << 16];

static const char *lines_end(void)
{
    fflush(stderr);
    STM_ASSERT(dup2(g_saved_stderr, 2) == 2);
    close(g_saved_stderr);
    rewind(g_lines);
    size_t n = fread(g_text, 1, sizeof g_text - 1u, g_lines);
    g_text[n] = '\0';
    fclose(g_lines);
    fputs(g_text, stderr);
    return g_text;
}

static uint32_t count_of(const char *text, const char *needle)
{
    uint32_t n = 0;
    size_t len = strlen(needle);
    for (const char *p = strstr(text, needle); p; p = strstr(p + len, needle))
        n++;
    return n;
}

static uint8_t g_buf[4096];

STM_TEST(bdev_thylacine_a_slow_request_completes_on_its_interrupt) {
    stm_bdev *bd = fake_open();
    if (!bd) return;
    thyla_bdev *d = (thyla_bdev *)bd;
    fake_script(1, F_SLOW, 2);
    lines_begin();
    STM_ASSERT_OK(stm_bdev_write(bd, 0, g_buf, sizeof g_buf));
    STM_ASSERT_OK(stm_bdev_fsync(bd));
    const char *t = lines_end();
    STM_ASSERT_EQ(F.notifies, 2u);
    STM_ASSERT_EQ(d->late_completions, 0u);
    STM_ASSERT_EQ(d->reinit_count, 0u);
    STM_ASSERT_EQ(count_of(t, "BDEVDIAG"), 0u);
    stm_bdev_close(bd);
}

/* A completion that lands between the driver's interrupt-status read and
 * its used-ring read, on a wait that timed out, leaves its status bit and
 * the kernel's count of its edge for the next request: the next wake is
 * that stale one, and must not fail the request it finds unanswered. */
STM_TEST(bdev_thylacine_a_stale_interrupt_does_not_fail_the_next_flush) {
    stm_bdev *bd = fake_open();
    if (!bd) return;
    thyla_bdev *d = (thyla_bdev *)bd;
    fake_script(1, F_RACE, 2);
    fake_script(2, F_NOW, 0);
    lines_begin();
    STM_ASSERT_OK(stm_bdev_write(bd, 0, g_buf, sizeof g_buf));
    STM_ASSERT_OK(stm_bdev_fsync(bd));
    const char *t = lines_end();
    STM_ASSERT_EQ(F.notifies, 2u);
    STM_ASSERT_EQ(d->late_completions, 1u);
    STM_ASSERT_EQ(d->reinit_count, 0u);
    STM_ASSERT_EQ(d->transport_fails, 0u);
    STM_ASSERT_EQ(F.drained, 0u);
    STM_ASSERT_EQ(count_of(t, "irq-late"), 1u);
    STM_ASSERT_EQ(count_of(t, "io-fail"), 0u);
    STM_ASSERT_EQ(count_of(t, "flush-lost"), 0u);
    stm_bdev_close(bd);
}

STM_TEST(bdev_thylacine_a_stale_interrupt_does_not_fail_the_next_write) {
    stm_bdev *bd = fake_open();
    if (!bd) return;
    thyla_bdev *d = (thyla_bdev *)bd;
    fake_script(1, F_RACE, 2);
    fake_script(2, F_NOW, 0);
    lines_begin();
    STM_ASSERT_OK(stm_bdev_write(bd, 0, g_buf, sizeof g_buf));
    STM_ASSERT_OK(stm_bdev_write(bd, 4096, g_buf, sizeof g_buf));
    const char *t = lines_end();
    STM_ASSERT_EQ(F.notifies, 2u);
    STM_ASSERT_EQ(d->reinit_count, 0u);
    STM_ASSERT_EQ(count_of(t, "io-fail"), 0u);
    stm_bdev_close(bd);
}

/* A completion whose edge never reached the kernel is found when a wait
 * times out, and counted. */
STM_TEST(bdev_thylacine_counts_a_completion_whose_edge_was_lost) {
    stm_bdev *bd = fake_open();
    if (!bd) return;
    thyla_bdev *d = (thyla_bdev *)bd;
    fake_script(1, F_LOST_EDGE, 2);
    lines_begin();
    STM_ASSERT_OK(stm_bdev_write(bd, 0, g_buf, sizeof g_buf));
    STM_ASSERT_OK(stm_bdev_fsync(bd));
    const char *t = lines_end();
    STM_ASSERT_EQ(d->late_completions, 1u);
    STM_ASSERT_EQ(count_of(t, "irq-late"), 1u);
    STM_ASSERT_EQ(d->reinit_count, 0u);
    stm_bdev_close(bd);
}

/* DEVICE_NEEDS_RESET (with QEMU's configuration interrupt, status 0x3)
 * takes the transport path: a write is re-submitted after the re-init, a
 * flush never is. */
STM_TEST(bdev_thylacine_a_device_that_needs_a_reset_is_reset) {
    stm_bdev *bd = fake_open();
    if (!bd) return;
    thyla_bdev *d = (thyla_bdev *)bd;
    fake_script(1, F_NEEDS_RESET, 0);
    fake_script(2, F_NOW, 0);
    lines_begin();
    STM_ASSERT_OK(stm_bdev_write(bd, 0, g_buf, sizeof g_buf));
    const char *t = lines_end();
    STM_ASSERT_EQ(F.notifies, 2u);
    STM_ASSERT_EQ(d->reinit_count, 1u);
    STM_ASSERT_EQ(count_of(t, "io-fail kind=W"), 1u);
    STM_ASSERT_EQ(count_of(t, "arm=needs-reset"), 1u);
    STM_ASSERT_FALSE(d->failed);

    fake_script(1, F_NEEDS_RESET, 0);
    lines_begin();
    STM_ASSERT_ERR(stm_bdev_fsync(bd), STM_EIO);
    t = lines_end();
    STM_ASSERT_EQ(F.notifies, 3u);
    STM_ASSERT_EQ(d->reinit_count, 2u);
    STM_ASSERT_EQ(count_of(t, "flush-lost"), 1u);
    STM_ASSERT_EQ(count_of(t, "arm=needs-reset"), 2u);
    stm_bdev_close(bd);
}

/* A configuration change with no answer is a spurious wake: as QEMU
 * raises it (virtio_notify_config sets status 0x3, the used-buffer bit
 * with it), and with bit 1 alone. */
STM_TEST(bdev_thylacine_a_configuration_change_is_not_an_answer) {
    static const fake_mode modes[] = { F_CONFIG_FIRST, F_CONFIG_BIT1 };
    for (size_t i = 0; i < sizeof modes / sizeof modes[0]; i++) {
        stm_bdev *bd = fake_open();
        if (!bd) return;
        thyla_bdev *d = (thyla_bdev *)bd;
        fake_script(1, modes[i], 0);
        lines_begin();
        STM_ASSERT_OK(stm_bdev_fsync(bd));
        const char *t = lines_end();
        STM_ASSERT_EQ(F.notifies, 1u);
        STM_ASSERT_EQ(F.waits, 2u);
        STM_ASSERT_EQ(d->reinit_count, 0u);
        STM_ASSERT_EQ(count_of(t, "BDEVDIAG"), 0u);
        stm_bdev_close(bd);
    }
}

/* DEVICE_NEEDS_RESET whose configuration interrupt never reached the
 * kernel is found by the wait that times out. */
STM_TEST(bdev_thylacine_needs_reset_with_a_lost_edge_is_reset) {
    stm_bdev *bd = fake_open();
    if (!bd) return;
    thyla_bdev *d = (thyla_bdev *)bd;
    fake_script(1, F_NR_NO_EDGE, 0);
    fake_script(2, F_NOW, 0);
    lines_begin();
    STM_ASSERT_OK(stm_bdev_write(bd, 0, g_buf, sizeof g_buf));
    const char *t = lines_end();
    STM_ASSERT_EQ(F.notifies, 2u);
    STM_ASSERT_EQ(d->reinit_count, 1u);
    STM_ASSERT_EQ(count_of(t, "arm=needs-reset"), 1u);
    STM_ASSERT_EQ(count_of(t, "still waiting"), 0u);
    STM_ASSERT_FALSE(d->failed);
    stm_bdev_close(bd);
}

/* Wakes that bring an interrupt and no answer are capped: then the
 * transport path (a write re-submitted, a flush lost). */
STM_TEST(bdev_thylacine_an_interrupt_storm_with_no_answer_is_capped) {
    stm_bdev *bd = fake_open();
    if (!bd) return;
    thyla_bdev *d = (thyla_bdev *)bd;
    fake_script(1, F_STORM, 0);
    fake_script(2, F_NOW, 0);
    lines_begin();
    STM_ASSERT_OK(stm_bdev_write(bd, 0, g_buf, sizeof g_buf));
    const char *t = lines_end();
    STM_ASSERT_EQ(F.notifies, 2u);
    STM_ASSERT_EQ(d->reinit_count, 1u);
    STM_ASSERT_EQ(count_of(t, "io-fail kind=W"), 1u);
    STM_ASSERT_EQ(count_of(t, "arm=spurious-wakes"), 1u);

    fake_script(1, F_STORM, 0);
    lines_begin();
    STM_ASSERT_ERR(stm_bdev_fsync(bd), STM_EIO);
    t = lines_end();
    STM_ASSERT_EQ(F.notifies, 3u);
    STM_ASSERT_EQ(d->reinit_count, 2u);
    STM_ASSERT_EQ(count_of(t, "flush-lost"), 1u);
    STM_ASSERT_EQ(count_of(t, "arm=spurious-wakes"), 2u);
    stm_bdev_close(bd);
}

/* A wait the kernel fails (a second waiter, a bad handle) takes the
 * transport path. */
STM_TEST(bdev_thylacine_a_failed_wait_is_a_transport_failure) {
    stm_bdev *bd = fake_open();
    if (!bd) return;
    thyla_bdev *d = (thyla_bdev *)bd;
    fake_script(1, F_WAIT_FAILS, 0);
    fake_script(2, F_NOW, 0);
    lines_begin();
    STM_ASSERT_OK(stm_bdev_write(bd, 0, g_buf, sizeof g_buf));
    const char *t = lines_end();
    STM_ASSERT_EQ(F.notifies, 2u);
    STM_ASSERT_EQ(d->reinit_count, 1u);
    STM_ASSERT_EQ(F.drained, 1u);
    STM_ASSERT_EQ(count_of(t, "arm=irq-wait"), 1u);
    stm_bdev_close(bd);
}

/* One request is in flight, so a used ring that moved by two was not
 * moved by its answer: the transport path. */
STM_TEST(bdev_thylacine_a_used_ring_moved_by_two_is_a_transport_failure) {
    stm_bdev *bd = fake_open();
    if (!bd) return;
    thyla_bdev *d = (thyla_bdev *)bd;
    fake_script(1, F_USED_TWO, 0);
    fake_script(2, F_NOW, 0);
    lines_begin();
    STM_ASSERT_OK(stm_bdev_write(bd, 0, g_buf, sizeof g_buf));
    const char *t = lines_end();
    STM_ASSERT_EQ(F.notifies, 2u);
    STM_ASSERT_EQ(d->reinit_count, 1u);
    STM_ASSERT_EQ(count_of(t, "arm=used-idx"), 1u);
    stm_bdev_close(bd);
}

/* The slow lines and the irq-late lines are capped apart: a long run of
 * one kind does not silence the other. */
STM_TEST(bdev_thylacine_irq_late_lines_do_not_silence_a_slow_line) {
    stm_bdev *bd = fake_open();
    if (!bd) return;
    thyla_bdev *d = (thyla_bdev *)bd;
    uint32_t many = BDEV_WAIT_LINES_MAX + 2u;
    for (uint32_t i = 1; i <= many; i++)
        fake_script(i, F_LOST_EDGE, 1);
    fake_script(many + 1u, F_SLOW, BDEV_SLOW_LINE_WAITS);
    lines_begin();
    for (uint32_t i = 0; i <= many; i++)
        STM_ASSERT_OK(stm_bdev_write(bd, 0, g_buf, sizeof g_buf));
    const char *t = lines_end();
    STM_ASSERT_EQ(d->late_completions, many);
    STM_ASSERT_EQ(count_of(t, "irq-late (completion"), BDEV_WAIT_LINES_MAX);
    STM_ASSERT_EQ(count_of(t, "irq-late lines (later"), 1u);
    STM_ASSERT_EQ(count_of(t, "slow (outstanding"), 1u);
    stm_bdev_close(bd);
}

/* After the slow lines go quiet, a request that never ends is still named
 * every BDEV_STILL_WAITING_WAITS waits. */
STM_TEST(bdev_thylacine_a_request_that_never_ends_is_still_named) {
    stm_bdev *bd = fake_open();
    if (!bd) return;
    uint32_t many = BDEV_WAIT_LINES_MAX + 2u;
    for (uint32_t i = 1; i <= many; i++)
        fake_script(i, F_SLOW, BDEV_SLOW_LINE_WAITS);
    uint32_t long_wait = 2u * BDEV_STILL_WAITING_WAITS + 10u;
    fake_script(many + 1u, F_SLOW, long_wait);
    lines_begin();
    for (uint32_t i = 0; i <= many; i++)
        STM_ASSERT_OK(stm_bdev_write(bd, 0, g_buf, sizeof g_buf));
    const char *t = lines_end();
    STM_ASSERT_EQ(count_of(t, "slow (outstanding"), BDEV_WAIT_LINES_MAX);
    STM_ASSERT_EQ(count_of(t, "slow lines (later"), 1u);
    STM_ASSERT_EQ(count_of(t, "still waiting (at least"), 2u);
    STM_ASSERT_EQ(count_of(t, "still waiting (at least 300 s)"), 1u);
    STM_ASSERT_EQ(count_of(t, "still waiting (at least 600 s)"), 1u);
    stm_bdev_close(bd);
}

/* A read past the device's end fails STM_EIO in bdev.c, as on every backend,
 * and sends the device no request (the driver's own sector bound answers
 * STM_EINVAL); one ending at the end reaches the device. */
STM_TEST(bdev_thylacine_a_read_past_the_end_fails_eio_with_no_request) {
    stm_bdev *bd = fake_open();
    if (!bd) return;
    const stm_bdev_caps *caps = stm_bdev_caps_of(bd);
    STM_ASSERT(caps != NULL);
    if (!caps) { stm_bdev_close(bd); return; }
    const uint64_t size = caps->size_bytes;
    STM_ASSERT_EQ(size, (uint64_t)0x200000u * 512u);
    uint32_t before = F.notifies;
    STM_ASSERT_ERR(stm_bdev_read(bd, size, g_buf, sizeof g_buf), STM_EIO);
    STM_ASSERT_ERR(stm_bdev_read(bd, size - 2048u, g_buf, sizeof g_buf), STM_EIO);
    STM_ASSERT_EQ(F.notifies, before);
    STM_ASSERT_OK(stm_bdev_read(bd, size - sizeof g_buf, g_buf, sizeof g_buf));
    STM_ASSERT_EQ(F.notifies, before + 1u);
    stm_bdev_close(bd);
}

STM_TEST_MAIN("bdev_thylacine")
