/* SPDX-License-Identifier: ISC */
/*
 * Thylacine block backend - in-process userspace virtio-blk driver.
 *
 * Lands as P6 sub-chunk 16b-beta of the Thylacine roadmap (the OS this
 * arm targets). Backs the "stratumd-as-driver" architectural choice
 * (delta of POUCH-DESIGN.md sec 14 row 16): stratumd holds CAP_HW_CREATE
 * granted by joey at spawn and drives the QEMU virt virtio-mmio block
 * device directly. No daemon protocol seam to virtio-blk; mount + I/O
 * proceed entirely in-process via the stm_bdev vtable.
 *
 * The C body ports the one-shot Rust test driver at
 *   thylacine/usr/virtio-blk-rw/src/main.rs
 * into a long-lived stm_bdev backend. Same VIRTIO 1.2 init recipe,
 * same descriptor-chain idiom (3 descriptors: req-header / data /
 * status), same IRQ-driven completion. Differences from the test
 * driver:
 *
 *   - We expose blocking read/write/fsync/fdatasync ops via the
 *     stm_bdev_ops vtable rather than a single 3-pass main().
 *   - We chop each public stm_bdev_read / stm_bdev_write into
 *     SECTORS_PER_REQUEST-sector chunks (1 MiB per virtqueue
 *     transaction) and serialise them through a per-bdev mutex.
 *   - One outstanding virtqueue request at a time. Multi-request
 *     pipelining is a future enhancement; v1.0 mount path is
 *     single-threaded so the bottleneck is far from here.
 *   - async submit_* and fsync wire to the sync path with a
 *     synchronous-completion stub: the callback fires inside submit
 *     before submit returns. This is sound because stm_bdev's public
 *     contract is "completions may fire on a thread other than the
 *     submitter" - the submitter-thread case satisfies that.
 *
 * Invariants:
 *   B-1  Offset + length passed to read/write are SECTOR_SIZE
 *        multiples; otherwise STM_EINVAL. (The mount path uses 4 KiB-
 *        aligned ops via the page allocator; this is a safe floor.)
 *   B-2  At most one virtqueue request in flight per bdev. The
 *        per-bdev mutex enforces.
 *   B-3  All kobj handles (mmio, irq, dma) acquired in open are
 *        released in close. Partial-init failures unwind cleanly.
 *   B-4  avail.idx is monotonic over the bdev's lifetime; the device
 *        sees a strictly-increasing sequence (no wrap before close).
 *   B-5  DSB SY at submission time guarantees all descriptor + ring
 *        writes are visible to the device before the virtqueue
 *        notification kicks the doorbell.
 *   B-6  The MMIO bank claim + map happens once at open; we do not
 *        re-claim across re-opens (single-bdev process model for the
 *        boot stratumd).
 *
 * The driver is intentionally minimal: no VIRTIO_BLK_T_FLUSH
 * negotiation (fsync is a no-op since QEMU's backing-file write-
 * through behaviour is the de-facto durability surface for v1.0); no
 * discard support; no resize. These are tracked as v1.x followups.
 *
 * See thylacine/docs/reference/86-pouch-stratumd-boot.md for the
 * cross-cut design rationale and the audit-trigger rows ("stratumd
 * HW-cap spawn" + "stratumd virtio-blk driver arm").
 */
#include "bdev_internal.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

/* Pouch musl exposes __NR_mmio_create..__NR_dma_map via the
 * 0008-pouch-hw-syscalls.patch in usr/lib/pouch/patches/.
 * The numbers match kernel/include/thylacine/syscall.h: 2-7. */
#ifndef __NR_mmio_create
#  error "pouch's bits/syscall.h.in must define the HW syscall numbers (sub-chunk 16b-beta)"
#endif

/* ------------------------------------------------------------------------- */
/* virtio-mmio bank constants.                                                */
/*                                                                            */
/* Mirror of usr/virtio-blk-rw/src/main.rs constants. Kept in lockstep with   */
/* the Rust driver - if QEMU's virt machine moves the bank, both files       */
/* update.                                                                    */
/* ------------------------------------------------------------------------- */

#define THYLA_PAGE_SIZE              0x1000ull

#define VIRTIO_MMIO_BASE_PA          0x0a000000ull
#define VIRTIO_MMIO_SLOT_STRIDE      0x200ull
#define VIRTIO_MMIO_NUM_SLOTS        32u
#define VIRTIO_MMIO_NUM_PAGES        ((uint64_t)VIRTIO_MMIO_NUM_SLOTS * VIRTIO_MMIO_SLOT_STRIDE / THYLA_PAGE_SIZE)
#define VIRTIO_MMIO_GIC_SPI_BASE     16u
#define VIRTIO_MMIO_GIC_INTID_BASE   (32u + VIRTIO_MMIO_GIC_SPI_BASE)

/* User-VA layout. Chosen disjoint from stratumd's other mappings:
 *   0x00500000.. 4 pages   MMIO bank          (R+W, no exec)
 *   0x00600000.. 1 page    ring DMA           (R+W)
 *   0x00700000.. 256 pages data DMA (1 MiB)   (R+W)
 *
 * The pouch musl heap (mallocng) requests anonymous mappings via
 * SYS_BURROW_ATTACH; the kernel chooses VA placement and never picks
 * <0x01000000 (it draws from BURROW_VA_BASE in mm/burrow.c). So these
 * fixed VAs are reservation-safe.
 */
#define THYLA_MMIO_USER_VA           0x00500000ull
#define THYLA_RING_USER_VA           0x00600000ull
#define THYLA_DATA_USER_VA           0x00700000ull

/* VirtIO MMIO register offsets. */
#define VREG_MAGIC_VALUE             0x000
#define VREG_VERSION                 0x004
#define VREG_DEVICE_ID               0x008
#define VREG_DEVICE_FEATURES         0x010
#define VREG_DEVICE_FEATURES_SEL     0x014
#define VREG_DRIVER_FEATURES         0x020
#define VREG_DRIVER_FEATURES_SEL     0x024
#define VREG_QUEUE_SEL               0x030
#define VREG_QUEUE_NUM_MAX           0x034
#define VREG_QUEUE_NUM               0x038
#define VREG_QUEUE_READY             0x044
#define VREG_QUEUE_NOTIFY            0x050
#define VREG_INTERRUPT_STATUS        0x060
#define VREG_INTERRUPT_ACK           0x064
#define VREG_STATUS                  0x070
#define VREG_QUEUE_DESC_LOW          0x080
#define VREG_QUEUE_DESC_HIGH         0x084
#define VREG_QUEUE_DRIVER_LOW        0x090
#define VREG_QUEUE_DRIVER_HIGH       0x094
#define VREG_QUEUE_DEVICE_LOW        0x0a0
#define VREG_QUEUE_DEVICE_HIGH       0x0a4
#define VREG_CONFIG                  0x100

#define VIRTIO_MMIO_MAGIC            0x74726976u
#define VIRTIO_MMIO_VERSION_MODERN   2u
#define VIRTIO_DEVICE_ID_BLK         2u

#define VSTATUS_ACKNOWLEDGE          1u
#define VSTATUS_DRIVER               2u
#define VSTATUS_DRIVER_OK            4u
#define VSTATUS_FEATURES_OK          8u
#define VSTATUS_FAILED               128u

#define VIRTIO_F_VERSION_1_BIT_BANK1 (1u << 0)

#define VIRTQ_DESC_F_NEXT            1u
#define VIRTQ_DESC_F_WRITE           2u

#define VIRTIO_BLK_T_IN              0u
#define VIRTIO_BLK_T_OUT             1u
#define VIRTIO_BLK_T_FLUSH           4u
#define VIRTIO_BLK_S_OK              0u

/* VIRTIO_BLK_F_FLUSH (feature bit 9, bank 0): the device has a writeback
 * cache and honors VIRTIO_BLK_T_FLUSH. Negotiating it lets op_fsync issue a
 * real durability barrier instead of relying on the launch cache mode. */
#define VIRTIO_BLK_F_FLUSH_BIT       (1u << 9)

/* Request kind for the single-virtqueue submit path. READ/WRITE carry a
 * data descriptor; FLUSH is a header->status chain with no data. */
typedef enum { REQ_READ, REQ_WRITE, REQ_FLUSH } req_kind;

#define VINT_USED_BUFFER             (1u << 0)

/* Virtqueue dimensions + ring DMA layout. */
#define VQ_QUEUE_SIZE                16u
#define VQ_RING_DMA_SIZE             THYLA_PAGE_SIZE

#define VQ_DESC_OFF                  0x000
#define VQ_AVAIL_OFF                 0x100
#define VQ_USED_OFF                  0x200
#define VQ_REQ_OFF                   0x300
#define VQ_STATUS_OFF                0x310

/* Data DMA = 1 MiB; 2048 sectors per virtqueue request. */
#define SECTOR_SIZE                  512ull
#define VQ_DATA_DMA_SIZE             (1ull << 20)
#define SECTORS_PER_REQUEST          (VQ_DATA_DMA_SIZE / SECTOR_SIZE)

/* Cap on spurious IRQ wakes (config-change without used-buffer). */
#define MAX_NON_USED_BUFFER_WAKES    16u

/* Bounded transient-fault recovery: a failed request triggers up to this
 * many (device re-init + re-submit) cycles before the bdev is latched
 * permanently. A transient virtio hiccup self-heals on the first re-init;
 * a genuinely dead device exhausts the budget + latches (Area F #2). */
#define DO_REQUEST_MAX_REINIT        2u

/* Thylacine kobj-rights bits. Mirror of kernel/include/thylacine/handle.h
 * (and libthyla_rs / libt). The kernel reserves (1u << 3) for
 * RIGHT_TRANSFER and (1u << 4) for RIGHT_DMA; do NOT collide. */
#define T_RIGHT_READ                 (1u << 0)
#define T_RIGHT_WRITE                (1u << 1)
#define T_RIGHT_MAP                  (1u << 2)
#define T_RIGHT_SIGNAL               (1u << 5)

/* Thylacine PROT bits for MMIO/DMA mapping. */
#define T_PROT_READ                  1u
#define T_PROT_WRITE                 2u

/* Compile-time pin on the ring layout. The descriptor-table region must
 * fit ahead of avail; avail before used; used before the inline request
 * header; status byte trails. Drift here would silently corrupt the
 * device's view of the rings. */
_Static_assert(VQ_DESC_OFF  + (VQ_QUEUE_SIZE * 16) <= VQ_AVAIL_OFF,  "desc/avail overlap");
_Static_assert(VQ_AVAIL_OFF + 4 + (VQ_QUEUE_SIZE * 2) <= VQ_USED_OFF, "avail/used overlap");
_Static_assert(VQ_USED_OFF  + 4 + (VQ_QUEUE_SIZE * 8) <= VQ_REQ_OFF,  "used/req overlap");
_Static_assert(VQ_REQ_OFF   + 16 <= VQ_STATUS_OFF,                    "req/status overlap");
_Static_assert(VQ_STATUS_OFF + 1 <= VQ_RING_DMA_SIZE,                 "status/end overlap");

/* ------------------------------------------------------------------------- */
/* Backing struct.                                                            */
/* ------------------------------------------------------------------------- */

typedef struct {
    stm_bdev         base;          /* MUST be first */

    /* The single descriptor chain is shared across all callers; this
     * mutex serialises every read/write/fsync request. Invariant B-2. */
    pthread_mutex_t  lock;
    bool             lock_inited;

    /* kobj handles. -1 sentinel = not yet allocated. */
    int64_t          irq_handle;
    int64_t          ring_handle;
    int64_t          data_handle;

    /* DMA bus addresses (kernel-stamped on SYS_DMA_MAP). */
    uint64_t         ring_pa;
    uint64_t         data_pa;

    /* MMIO bank state. mmio_pages_mapped tracks how many pages we
     * successfully mapped; close() unmaps only that prefix. */
    bool             mmio_bank_claimed;

    /* Selected virtio-blk slot. */
    uint64_t         slot_va;
    uint32_t         slot;
    uint32_t         intid;

    /* avail.idx counter. Monotonic across all requests; invariant B-4.
     * Reset to 0 by a device re-init (the recovery path), which also
     * resets the device's own idx via a VIRTIO reset. */
    uint16_t         avail_idx;
    /* Latched PERMANENTLY only after a request fails AND the bounded
     * re-init recovery (reinit_device_locked + retry) has been exhausted
     * -- i.e. a genuinely dead device, not a transient hiccup (R4-F1
     * recovery, Area F #2). Once true, every op short-circuits to
     * STM_EIO. */
    bool             failed;
    uint64_t         reinit_count;  /* diagnostics: device recoveries fired */

    /* VIRTIO_BLK_F_FLUSH negotiated at init -> op_fsync issues a real
     * VIRTIO_BLK_T_FLUSH barrier. When false (device offers no cache),
     * every completed write is already durable + op_fsync is a no-op.
     * Re-derived on every (re)init so a recovered device keeps it correct. */
    bool             flush_supported;
} thyla_bdev;

/* ------------------------------------------------------------------------- */
/* Thylacine syscall wrappers - raw __NR_ via pouch's bits/syscall.h.in.      */
/*                                                                            */
/* Each returns the kernel's raw return convention: non-negative on success;  */
/* a negative kernel errno-shaped value on failure. We treat any negative as  */
/* failure (the kernel HW path returns -1 today; future kernels may carry     */
/* errno detail).                                                             */
/* ------------------------------------------------------------------------- */

static inline int64_t t_mmio_create(uint64_t pa, uint64_t size, uint32_t rights)
{
    return syscall(__NR_mmio_create, pa, size, (long)rights);
}

static inline int64_t t_mmio_map(int64_t handle, uint64_t vaddr, uint32_t prot)
{
    return syscall(__NR_mmio_map, (long)handle, vaddr, (long)prot);
}

static inline int64_t t_irq_create(uint32_t intid, uint32_t rights)
{
    return syscall(__NR_irq_create, (long)intid, (long)rights);
}

static inline int64_t t_irq_wait(int64_t handle)
{
    return syscall(__NR_irq_wait, (long)handle);
}

static inline int64_t t_dma_create(uint64_t size, uint32_t rights)
{
    return syscall(__NR_dma_create, size, (long)rights);
}

static inline int64_t t_dma_map(int64_t handle, uint64_t vaddr, uint32_t prot)
{
    return syscall(__NR_dma_map, (long)handle, vaddr, (long)prot);
}

/* ------------------------------------------------------------------------- */
/* MMIO + DMA accessors.                                                      */
/*                                                                            */
/* volatile loads/stores at the requested width. dsb_sy() is the              */
/* descriptor-to-doorbell barrier (DMB OSHST would suffice but DSB SY         */
/* matches the Rust driver and is the strongest acceptable choice).           */
/* ------------------------------------------------------------------------- */

static inline uint32_t mmio_read32(uint64_t addr)
{
    return *(volatile uint32_t *)addr;
}
static inline void mmio_write32(uint64_t addr, uint32_t val)
{
    *(volatile uint32_t *)addr = val;
}
static inline void mmio_write16(uint64_t addr, uint16_t val)
{
    *(volatile uint16_t *)addr = val;
}
static inline uint16_t mmio_read16(uint64_t addr)
{
    return *(volatile uint16_t *)addr;
}
static inline void mmio_write64(uint64_t addr, uint64_t val)
{
    *(volatile uint64_t *)addr = val;
}
static inline uint8_t mmio_read_u8(uint64_t addr)
{
    return *(volatile uint8_t *)addr;
}
static inline void dsb_sy(void)
{
    __asm__ __volatile__("dsb sy" ::: "memory");
}
/* VIRTIO 1.2 sec 2.7.13.2 - reader-side barrier between observing used.idx
 * advance and reading used-ring entries / device-written data. DMB
 * ISHLD is strictly correct (inner-shareable, load-after) but DSB SY
 * is harmless and matches Rust's virtio_rmb. */
static inline void virtio_rmb(void)
{
    __asm__ __volatile__("dmb ishld" ::: "memory");
}

/* ------------------------------------------------------------------------- */
/* MMIO bank + slot location.                                                 */
/* ------------------------------------------------------------------------- */

static bool claim_virtio_mmio_bank(thyla_bdev *d)
{
    for (uint64_t i = 0; i < VIRTIO_MMIO_NUM_PAGES; i++) {
        uint64_t pa = VIRTIO_MMIO_BASE_PA + i * THYLA_PAGE_SIZE;
        uint64_t va = THYLA_MMIO_USER_VA + i * THYLA_PAGE_SIZE;
        int64_t h = t_mmio_create(pa, THYLA_PAGE_SIZE,
                                   T_RIGHT_READ | T_RIGHT_WRITE | T_RIGHT_MAP);
        if (h < 0) return false;
        if (t_mmio_map(h, va, T_PROT_READ | T_PROT_WRITE) < 0) return false;
    }
    d->mmio_bank_claimed = true;
    return true;
}

static bool find_blk_slot(thyla_bdev *d)
{
    /* Scan HIGH-to-LOW so we pick the "primary" virtio-blk-device on
     * the QEMU virt machine. QEMU assigns slots in REVERSE creation
     * order: the FIRST -device on the command line gets slot 31, the
     * SECOND gets slot 30, etc. tools/run-vm.sh lists pool_flags FIRST
     * so pool.img lands at slot 31; the legacy virtio-blk-probe /
     * virtio-blk-rw test binaries scan LOW-to-HIGH so they pick the
     * SECOND-listed disk.img at slot 30. Both directions coexist.
     *
     * When only one virtio-blk-device is present, this scan finds it
     * regardless of which slot it occupies. */
    for (uint32_t slot = VIRTIO_MMIO_NUM_SLOTS; slot-- > 0; ) {
        uint64_t sv = THYLA_MMIO_USER_VA + (uint64_t)slot * VIRTIO_MMIO_SLOT_STRIDE;
        if (mmio_read32(sv + VREG_MAGIC_VALUE) != VIRTIO_MMIO_MAGIC) continue;
        if (mmio_read32(sv + VREG_DEVICE_ID)   != VIRTIO_DEVICE_ID_BLK) continue;
        d->slot    = slot;
        d->slot_va = sv;
        d->intid   = VIRTIO_MMIO_GIC_INTID_BASE + slot;
        return true;
    }
    return false;
}

/* ------------------------------------------------------------------------- */
/* VirtIO 1.2 init (sec 3.1.1).                                               */
/* ------------------------------------------------------------------------- */

static bool init_device(uint64_t slot_va, uint64_t ring_pa,
                        bool *out_flush_supported)
{
    if (out_flush_supported) *out_flush_supported = false;

    /* Reset + ACKNOWLEDGE + DRIVER. */
    mmio_write32(slot_va + VREG_STATUS, 0);
    mmio_write32(slot_va + VREG_STATUS, VSTATUS_ACKNOWLEDGE);
    mmio_write32(slot_va + VREG_STATUS, VSTATUS_ACKNOWLEDGE | VSTATUS_DRIVER);

    /* Read both feature banks (per sec 3.1.1 step 4). Bank 0 carries the
     * blk feature bits (VIRTIO_BLK_F_FLUSH = bit 9); bank 1 carries
     * VIRTIO_F_VERSION_1. */
    mmio_write32(slot_va + VREG_DEVICE_FEATURES_SEL, 0);
    uint32_t dev_feat_lo = mmio_read32(slot_va + VREG_DEVICE_FEATURES);
    mmio_write32(slot_va + VREG_DEVICE_FEATURES_SEL, 1);
    uint32_t dev_feat_hi = mmio_read32(slot_va + VREG_DEVICE_FEATURES);
    if ((dev_feat_hi & VIRTIO_F_VERSION_1_BIT_BANK1) == 0) {
        mmio_write32(slot_va + VREG_STATUS, VSTATUS_FAILED);
        return false;
    }

    /* Negotiate VIRTIO_F_VERSION_1 (bank 1, mandatory) + VIRTIO_BLK_F_FLUSH
     * (bank 0) iff the device offers it. The flush is what makes op_fsync a
     * real durability barrier instead of relying on the launch cache mode.
     * We never request a feature the device did not offer, so FEATURES_OK
     * cannot be refused on our account. */
    bool flush = (dev_feat_lo & VIRTIO_BLK_F_FLUSH_BIT) != 0;
    mmio_write32(slot_va + VREG_DRIVER_FEATURES_SEL, 0);
    mmio_write32(slot_va + VREG_DRIVER_FEATURES, flush ? VIRTIO_BLK_F_FLUSH_BIT : 0u);
    mmio_write32(slot_va + VREG_DRIVER_FEATURES_SEL, 1);
    mmio_write32(slot_va + VREG_DRIVER_FEATURES, VIRTIO_F_VERSION_1_BIT_BANK1);

    /* FEATURES_OK readback. */
    mmio_write32(slot_va + VREG_STATUS,
                 VSTATUS_ACKNOWLEDGE | VSTATUS_DRIVER | VSTATUS_FEATURES_OK);
    uint32_t status = mmio_read32(slot_va + VREG_STATUS);
    if ((status & VSTATUS_FEATURES_OK) == 0) return false;

    /* QueueNumMax check. */
    mmio_write32(slot_va + VREG_QUEUE_SEL, 0);
    uint32_t num_max = mmio_read32(slot_va + VREG_QUEUE_NUM_MAX);
    if (num_max < VQ_QUEUE_SIZE) {
        mmio_write32(slot_va + VREG_STATUS, VSTATUS_FAILED);
        return false;
    }
    mmio_write32(slot_va + VREG_QUEUE_NUM, VQ_QUEUE_SIZE);

    /* Program the ring addresses. */
    uint64_t desc_pa  = ring_pa + VQ_DESC_OFF;
    uint64_t avail_pa = ring_pa + VQ_AVAIL_OFF;
    uint64_t used_pa  = ring_pa + VQ_USED_OFF;
    mmio_write32(slot_va + VREG_QUEUE_DESC_LOW,    (uint32_t)(desc_pa  & 0xFFFFFFFFu));
    mmio_write32(slot_va + VREG_QUEUE_DESC_HIGH,   (uint32_t)(desc_pa  >> 32));
    mmio_write32(slot_va + VREG_QUEUE_DRIVER_LOW,  (uint32_t)(avail_pa & 0xFFFFFFFFu));
    mmio_write32(slot_va + VREG_QUEUE_DRIVER_HIGH, (uint32_t)(avail_pa >> 32));
    mmio_write32(slot_va + VREG_QUEUE_DEVICE_LOW,  (uint32_t)(used_pa  & 0xFFFFFFFFu));
    mmio_write32(slot_va + VREG_QUEUE_DEVICE_HIGH, (uint32_t)(used_pa  >> 32));

    /* QueueReady = 1, DRIVER_OK. */
    mmio_write32(slot_va + VREG_QUEUE_READY, 1);
    mmio_write32(slot_va + VREG_STATUS,
                 VSTATUS_ACKNOWLEDGE | VSTATUS_DRIVER |
                 VSTATUS_FEATURES_OK | VSTATUS_DRIVER_OK);
    if (out_flush_supported) *out_flush_supported = flush;
    return true;
}

/* ------------------------------------------------------------------------- */
/* Descriptor table - 3-entry chain (req-header / data / status).             */
/*                                                                            */
/* desc[0] (req header) is OUT, addr/len/flags stable.                        */
/* desc[1] (data) addr/len stable; flags flips between NEXT and NEXT|WRITE    */
/*               depending on direction (set in do_request).                  */
/* desc[2] (status) is WRITE (device-writable), addr/len/flags stable.        */
/* ------------------------------------------------------------------------- */

static void init_descriptors(uint64_t ring_va, uint64_t ring_pa, uint64_t data_pa)
{
    uint64_t desc_va = ring_va + VQ_DESC_OFF;

    /* desc[0]: req header (OUT). */
    mmio_write64(desc_va +  0, ring_pa + VQ_REQ_OFF);
    mmio_write32(desc_va +  8, 16);
    mmio_write16(desc_va + 12, VIRTQ_DESC_F_NEXT);
    mmio_write16(desc_va + 14, 1);

    /* desc[1]: data; flags filled per request. */
    mmio_write64(desc_va + 16, data_pa);
    mmio_write32(desc_va + 24, (uint32_t)VQ_DATA_DMA_SIZE);
    /* desc[1].flags written in do_request(). */
    mmio_write16(desc_va + 30, 2);

    /* desc[2]: status (WRITE). */
    mmio_write64(desc_va + 32, ring_pa + VQ_STATUS_OFF);
    mmio_write32(desc_va + 40, 1);
    mmio_write16(desc_va + 44, VIRTQ_DESC_F_WRITE);
    mmio_write16(desc_va + 46, 0);
}

/* ------------------------------------------------------------------------- */
/* Single virtqueue request submit + complete.                                */
/*                                                                            */
/* Caller holds d->lock. lba is the sector number; sector_count is the        */
/* request size in sectors. The data DMA buffer at THYLA_DATA_USER_VA holds   */
/* the bytes to write (for OUT) or receives the bytes read (for IN).          */
/* ------------------------------------------------------------------------- */

/* Recover a failed virtio device IN PLACE. init_device writes STATUS=0
 * first -- a full VIRTIO 1.2 reset (sec 4.2.3.1 / 2.1: the device MUST
 * re-initialise all state, dropping any in-flight request and resetting
 * its avail/used idx to 0) -- then re-negotiates + re-programs the rings;
 * init_descriptors rebuilds the 3-entry chain; avail_idx resets to 0 to
 * match the freshly-reset device. The MMIO bank + DMA mappings persist
 * (claimed once at open; invariant B-6) -- only the device-side state
 * machine + the rings reset, so the data DMA buffer's contents survive
 * (a re-submit re-uses them). This is the recovery the R4-F1 latch always
 * assumed ("Stratum tears down + re-opens") but which no caller ever
 * drove -- done in place so a transient hiccup self-heals before the FS
 * sees EIO (Area F #2). Returns false iff the re-negotiation fails (an
 * unrecoverable device). Caller holds d->lock. */
static bool reinit_device_locked(thyla_bdev *d)
{
    if (!init_device(d->slot_va, d->ring_pa, &d->flush_supported)) return false;
    init_descriptors(THYLA_RING_USER_VA, d->ring_pa, d->data_pa);
    d->avail_idx = 0;
    d->reinit_count++;
    return true;
}

/* BDEVDIAG: which do_request_once check failed, for the recovery/latch
 * diagnostics in do_request. A bdev that silently latches dead is
 * undiagnosable in the field -- one line per recovery attempt + one on
 * the permanent latch names the failing arm. Emitted via raw write(2)
 * (no stdio: I/O runs on server worker threads; a bounded stack buffer
 * + one write syscall is thread-safe and allocation-free). */
typedef struct {
    uint8_t  arm;        /* 0=none 1=spurious 2=irqwait 3=used_idx 4=used_id 5=status */
    uint8_t  st;         /* device status byte (arm 5) */
    int64_t  irq_rc;     /* t_irq_wait return (arm 2) */
    uint16_t used_idx;   /* observed used.idx (arm 3) */
    uint16_t want_idx;   /* expected used.idx (arm 3) */
} bdev_fail_info;

static const char *bdev_fail_arm_str(uint8_t arm)
{
    switch (arm) {
    case 1:  return "spurious-wakes";
    case 2:  return "irq-wait";
    case 3:  return "used-idx";
    case 4:  return "used-id";
    case 5:  return "status";
    default: return "none";
    }
}

static void bdev_diag(thyla_bdev *d, const char *what, uint64_t lba,
                      uint32_t sector_count, req_kind kind,
                      uint32_t attempt, const bdev_fail_info *fi)
{
    char buf[192];
    int n = snprintf(buf, sizeof buf,
                     "BDEVDIAG: %s kind=%c lba=%llu n=%u attempt=%u "
                     "arm=%s st=%u irq_rc=%lld used=%u want=%u reinits=%llu\n",
                     what,
                     (kind == REQ_WRITE) ? 'W' : (kind == REQ_FLUSH) ? 'F' : 'R',
                     (unsigned long long)lba, sector_count, attempt,
                     bdev_fail_arm_str(fi->arm), fi->st,
                     (long long)fi->irq_rc, fi->used_idx, fi->want_idx,
                     (unsigned long long)d->reinit_count);
    if (n > 0) {
        ssize_t w = write(2, buf, (size_t)n);
        (void)w;
    }
}

/* Submit one virtqueue request + wait for completion. STM_OK on a clean
 * completion; STM_EIO on any failure WITHOUT latching -- the recovery /
 * latch decision is do_request()'s. On failure `fi` names the failing
 * arm (BDEVDIAG). Caller holds d->lock. */
static stm_status do_request_once(thyla_bdev *d, uint64_t lba,
                                   uint32_t sector_count, req_kind kind,
                                   bdev_fail_info *fi)
{
    /* Pre-poison status byte so a missing device write surfaces. */
    *(volatile uint8_t *)(THYLA_RING_USER_VA + VQ_STATUS_OFF) = 0xff;

    /* Update request header (type + sector). FLUSH ignores the sector. */
    uint64_t req_va  = THYLA_RING_USER_VA + VQ_REQ_OFF;
    uint32_t req_type = (kind == REQ_WRITE) ? VIRTIO_BLK_T_OUT
                      : (kind == REQ_FLUSH) ? VIRTIO_BLK_T_FLUSH
                      :                       VIRTIO_BLK_T_IN;
    mmio_write32(req_va + 0, req_type);
    mmio_write32(req_va + 4, 0);
    mmio_write64(req_va + 8, (kind == REQ_FLUSH) ? 0u : lba);

    uint64_t desc_va = THYLA_RING_USER_VA + VQ_DESC_OFF;
    if (kind == REQ_FLUSH) {
        /* FLUSH carries no data buffer: chain header -> status directly by
         * repointing desc[0].next from 1 to 2, skipping desc[1]. The head
         * (id 0) + the terminal status descriptor (id 2) are unchanged, so
         * the completion checks below hold identically. (VIRTIO 1.2 5.2.6.) */
        mmio_write16(desc_va + 14, 2);
    } else {
        /* Header -> data -> status. Restore desc[0].next to 1 in case a
         * prior FLUSH repointed it, then set desc[1].len to exactly the
         * request size (not the full DMA region) + the direction flag. */
        mmio_write16(desc_va + 14, 1);
        mmio_write32(desc_va + 16 + 8, sector_count * (uint32_t)SECTOR_SIZE);
        uint16_t data_flags = (kind == REQ_WRITE)
            ? VIRTQ_DESC_F_NEXT
            : (VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE);
        mmio_write16(desc_va + 16 + 12, data_flags);
    }

    /* avail.ring[(avail_idx) % QUEUE_SIZE] = head id (= 0). */
    uint64_t avail_va = THYLA_RING_USER_VA + VQ_AVAIL_OFF;
    uint16_t slot     = d->avail_idx % VQ_QUEUE_SIZE;
    mmio_write16(avail_va + 4 + slot * 2, 0);

    /* All descriptor + ring writes visible before avail.idx bump. */
    dsb_sy();

    /* Publish the new avail.idx, then kick the doorbell. */
    uint16_t new_idx = (uint16_t)(d->avail_idx + 1);
    mmio_write16(avail_va + 2, new_idx);
    dsb_sy();
    mmio_write32(d->slot_va + VREG_QUEUE_NOTIFY, 0);

    /* Wait for the device's IRQ; tolerate up to N spurious config-
     * change wakes before giving up. */
    uint32_t spurious = 0;
    for (;;) {
        if (spurious >= MAX_NON_USED_BUFFER_WAKES) {
            fi->arm = 1;
            goto io_fail;
        }
        int64_t count = t_irq_wait(d->irq_handle);
        if (count < 0) {
            fi->arm = 2;
            fi->irq_rc = count;
            goto io_fail;
        }

        uint32_t int_status = mmio_read32(d->slot_va + VREG_INTERRUPT_STATUS);
        mmio_write32(d->slot_va + VREG_INTERRUPT_ACK, int_status);
        if (int_status & VINT_USED_BUFFER) break;
        spurious++;
    }

    /* used.idx must equal expected. */
    uint64_t used_va = THYLA_RING_USER_VA + VQ_USED_OFF;
    uint16_t used_idx = mmio_read16(used_va + 2);
    /* Barrier between observing used.idx advance and reading used-ring
     * + data payload. */
    virtio_rmb();
    if (used_idx != new_idx) {
        fi->arm = 3;
        fi->used_idx = used_idx;
        fi->want_idx = new_idx;
        goto io_fail;
    }

    /* used.ring[(new_idx - 1) % QUEUE_SIZE].id must be 0 (the head). */
    uint32_t used_slot = (uint32_t)(new_idx - 1) % VQ_QUEUE_SIZE;
    uint32_t used_id   = *(volatile uint32_t *)(used_va + 4 + used_slot * 8);
    if (used_id != 0) {
        fi->arm = 4;
        goto io_fail;
    }

    /* Status byte. */
    uint8_t st = mmio_read_u8(THYLA_RING_USER_VA + VQ_STATUS_OFF);
    if (st != VIRTIO_BLK_S_OK) {
        fi->arm = 5;
        fi->st = st;
        goto io_fail;
    }

    /* Advance the bdev's counter. avail_idx wraps on uint16_t which
     * matches the device's 16-bit idx; invariant B-4 wrap-safe. */
    d->avail_idx = new_idx;
    return STM_OK;

io_fail:
    /* The avail.idx was published but the outcome is uncertain. Surface
     * STM_EIO to do_request(), which owns the re-init recovery + the
     * permanent latch -- a re-init resets both ends to idx 0, so this
     * uncertain state cannot strand a re-submitted request. */
    return STM_EIO;
}

/* Submit a request with bounded transient-fault recovery. A failed
 * do_request_once is a (possibly transient) virtio hiccup: re-init the
 * device (resyncs both ends to idx 0) + re-submit, up to
 * DO_REQUEST_MAX_REINIT times. Only after the recovery budget is
 * exhausted -- or a re-init itself fails -- is the bdev latched
 * PERMANENTLY (d->failed), surfacing STM_EIO to the FS (whose extent
 * writes are then retryable / commits wedge per the FS's own contract;
 * see tests/test_fs.c::fs_io_transient_write_eio_flush_recovers). A
 * re-submit is idempotent: a READ re-reads the same LBA; a WRITE
 * re-writes the same LBA from the unchanged data DMA buffer (the re-init
 * does not touch it). Caller holds d->lock (the request is serialised;
 * invariant B-2), so the latch + reinit_count are single-writer here. */
static stm_status do_request(thyla_bdev *d, uint64_t lba,
                              uint32_t sector_count, req_kind kind)
{
    /* Already permanently dead (recovery previously exhausted). R4-F1:
     * never re-publish onto a device whose ring state we abandoned. */
    if (d->failed) return STM_EIO;

    for (uint32_t attempt = 0; ; attempt++) {
        bdev_fail_info fi = {0};
        stm_status s = do_request_once(d, lba, sector_count, kind, &fi);
        if (s == STM_OK) return STM_OK;

        bdev_diag(d, "io-fail", lba, sector_count, kind, attempt, &fi);

        if (attempt >= DO_REQUEST_MAX_REINIT) {
            /* Recovery budget exhausted -- the device is genuinely dead.
             * Latch so every later op short-circuits + the FS surfaces
             * the durable failure. */
            bdev_diag(d, "LATCHED-DEAD", lba, sector_count, kind, attempt, &fi);
            d->failed = true;
            return STM_EIO;
        }
        if (!reinit_device_locked(d)) {
            /* The device cannot even be re-negotiated -- unrecoverable. */
            bdev_diag(d, "LATCHED-DEAD (reinit failed)", lba, sector_count,
                      kind, attempt, &fi);
            d->failed = true;
            return STM_EIO;
        }
        /* Re-submit against the freshly reset rings. */
    }
}

/* ------------------------------------------------------------------------- */
/* Public sync ops.                                                           */
/* ------------------------------------------------------------------------- */

static stm_status op_read(stm_bdev *base, uint64_t off, void *buf, size_t len)
{
    if ((off % SECTOR_SIZE) != 0) return STM_EINVAL;
    /* `len` need NOT be a SECTOR_SIZE multiple. Stratum's extent layer
     * reads/writes (block-aligned-plaintext + AEAD-tag), e.g. 4096+32 =
     * 4128 -- never sector-aligned because of the trailing tag. The
     * posix backend (pread) accepts arbitrary lengths; we honor the same
     * bdev contract by rounding the final partial sector UP to a whole
     * sector for the device transfer, then copying out only `len` real
     * bytes. Reading the extra tail bytes is safe: every Stratum extent
     * is reserved as N block-aligned blocks (N*4096 >= round_up(len,512)),
     * so the rounded read stays within the extent + on-device. */
    thyla_bdev *d = (thyla_bdev *)base;
    /* Bound the (rounded-up) device span against the device's sector
     * capacity, so an out-of-range LBA is a deterministic local reject
     * rather than a device-dependent EIO. The partial-sector round-up
     * can enlarge the addressed span by up to one sector. */
    if (off / SECTOR_SIZE + (uint64_t)((len + SECTOR_SIZE - 1) / SECTOR_SIZE)
        > d->base.caps.size_bytes / SECTOR_SIZE) {
        return STM_EINVAL;
    }
    uint8_t *p = buf;
    uint64_t cur_off = off;

    pthread_mutex_lock(&d->lock);
    while (len > 0) {
        size_t chunk_bytes = (len > VQ_DATA_DMA_SIZE) ? (size_t)VQ_DATA_DMA_SIZE : len;
        uint64_t lba       = cur_off / SECTOR_SIZE;
        uint32_t sectors   = (uint32_t)((chunk_bytes + SECTOR_SIZE - 1) / SECTOR_SIZE);

        stm_status s = do_request(d, lba, sectors, REQ_READ);
        if (s != STM_OK) { pthread_mutex_unlock(&d->lock); return s; }

        memcpy(p, (const void *)THYLA_DATA_USER_VA, chunk_bytes);

        p       += chunk_bytes;
        cur_off += chunk_bytes;
        len     -= chunk_bytes;
    }
    pthread_mutex_unlock(&d->lock);
    return STM_OK;
}

static stm_status op_write(stm_bdev *base, uint64_t off, const void *buf, size_t len)
{
    if ((off % SECTOR_SIZE) != 0) return STM_EINVAL;
    if (len == 0) return STM_OK;
    /* `len` need NOT be a SECTOR_SIZE multiple. The extent layer writes
     * (block-aligned-plaintext + AEAD-tag), e.g. 4128 B. A block device can
     * only transfer whole sectors, so the final partial sector is handled by
     * READ-MODIFY-WRITE: read the on-disk sector, overlay the real bytes,
     * write it back. This preserves the bytes beyond `len` in that sector,
     * matching the posix backend's byte-granular pwrite. The prior approach
     * (round up + zero-pad the tail) CLOBBERED those bytes; Stratum packs an
     * adjacent object / extent into the same sector, so the zero-pad
     * destroyed a neighbour's bytes -> read-back AEAD failure (STM_EBADTAG).
     * A whole-sector zero-pad is correct ONLY when `len` is a sector multiple;
     * for any partial tail, RMW is mandatory on a block backend that cannot
     * write sub-sector. (posix pwrite is byte-granular and never had this.) */
    thyla_bdev *d = (thyla_bdev *)base;
    /* Bound the (rounded-up) device span against the device's sector
     * capacity -- see op_read. */
    if (off / SECTOR_SIZE + (uint64_t)((len + SECTOR_SIZE - 1) / SECTOR_SIZE)
        > d->base.caps.size_bytes / SECTOR_SIZE) {
        return STM_EINVAL;
    }
    const uint8_t *p = buf;
    uint64_t cur_off = off;
    size_t aligned = (len / SECTOR_SIZE) * SECTOR_SIZE; /* whole-sector prefix */
    size_t tail    = len - aligned;                     /* 0 .. SECTOR_SIZE-1  */

    pthread_mutex_lock(&d->lock);

    /* 1. Whole-sector prefix, chunked by the DMA buffer size. Every transfer
     *    here is an exact sector multiple -- no padding, no RMW. */
    size_t remaining = aligned;
    while (remaining > 0) {
        size_t   chunk   = (remaining > VQ_DATA_DMA_SIZE) ? (size_t)VQ_DATA_DMA_SIZE : remaining;
        uint32_t sectors = (uint32_t)(chunk / SECTOR_SIZE);
        memcpy((void *)THYLA_DATA_USER_VA, p, chunk);
        dsb_sy();
        stm_status s = do_request(d, cur_off / SECTOR_SIZE, sectors, REQ_WRITE);
        if (s != STM_OK) { pthread_mutex_unlock(&d->lock); return s; }
        p        += chunk;
        cur_off  += chunk;
        remaining -= chunk;
    }

    /* 2. Partial tail sector: read-modify-write to preserve [tail, SECTOR_SIZE).
     *    The lock is held across the read+write so no concurrent op can touch
     *    this sector (or the shared DMA buffer) between them. */
    if (tail > 0) {
        uint64_t lba = cur_off / SECTOR_SIZE;
        stm_status rs = do_request(d, lba, 1, REQ_READ);
        if (rs != STM_OK) { pthread_mutex_unlock(&d->lock); return rs; }
        memcpy((void *)THYLA_DATA_USER_VA, p, tail);
        dsb_sy();
        stm_status ws = do_request(d, lba, 1, REQ_WRITE);
        if (ws != STM_OK) { pthread_mutex_unlock(&d->lock); return ws; }
    }

    pthread_mutex_unlock(&d->lock);
    return STM_OK;
}

static stm_status op_fsync(stm_bdev *base)
{
    thyla_bdev *d = (thyla_bdev *)base;

    /* A permanently-latched device cannot honestly report a flush as durable
     * -- fail closed so the latch is consistent across the whole vtable, not
     * just read/write (Area F #2 makes d->failed a reachable long-lived
     * state). */
    if (d->failed) return STM_EIO;

    /* Device negotiated no writeback cache (VIRTIO_BLK_F_FLUSH absent): every
     * completed op_write is already durable, so there is nothing to flush.
     * This also keeps a writethrough-only device (no FLUSH offered) correct. */
    if (!d->flush_supported) return STM_OK;

    /* Issue VIRTIO_BLK_T_FLUSH: the device flushes its writeback cache so
     * every previously-completed write becomes durable. This makes Stratum's
     * durability SELF-CONTAINED -- the commit's write-then-fsync barriers
     * (src/sync/sync.c + src/bootstrap/pool.c) are real on-device regardless
     * of the launch cache mode, rather than silently depending on
     * cache=writethrough (RW-8 R4-F3). lba/sector_count are unused for FLUSH.
     * d->lock serialises the shared descriptor chain (invariant B-2), exactly
     * as read/write do; a transient flush hiccup self-heals via the same
     * bounded reinit recovery in do_request. */
    pthread_mutex_lock(&d->lock);
    stm_status s = do_request(d, 0, 0, REQ_FLUSH);
    pthread_mutex_unlock(&d->lock);
    return s;
}

static stm_status op_fdatasync(stm_bdev *base)
{
    return op_fsync(base);
}

static stm_status op_discard(stm_bdev *base, uint64_t off, uint64_t len)
{
    (void)base; (void)off; (void)len;
    return STM_ENOTSUPPORTED;
}

static stm_status op_resize(stm_bdev *base, uint64_t new_size)
{
    (void)base; (void)new_size;
    return STM_ENOTSUPPORTED;
}

/* ------------------------------------------------------------------------- */
/* Async ops: synchronous-completion stubs.                                   */
/*                                                                            */
/* stm_bdev's public contract is "completions may fire on a thread other      */
/* than the submitter". The submitter-thread case (fire inside submit)        */
/* satisfies that. v1.0 ships the simplest correct shape.                     */
/* ------------------------------------------------------------------------- */

static stm_status op_submit_read(stm_bdev *base, uint64_t off, void *buf,
                                  size_t len,
                                  stm_bdev_completion_cb cb, void *user)
{
    stm_status s = op_read(base, off, buf, len);
    stm_op_result r = { .kind   = STM_OP_READ,
                         .status = s,
                         .bytes  = (s == STM_OK) ? len : 0,
                         .user   = user };
    cb(&r);
    return STM_OK;
}

static stm_status op_submit_write(stm_bdev *base, uint64_t off, const void *buf,
                                   size_t len,
                                   stm_bdev_completion_cb cb, void *user)
{
    stm_status s = op_write(base, off, buf, len);
    stm_op_result r = { .kind   = STM_OP_WRITE,
                         .status = s,
                         .bytes  = (s == STM_OK) ? len : 0,
                         .user   = user };
    cb(&r);
    return STM_OK;
}

static stm_status op_submit_fsync(stm_bdev *base,
                                   stm_bdev_completion_cb cb, void *user)
{
    stm_status s = op_fsync(base);
    stm_op_result r = { .kind = STM_OP_FSYNC, .status = s,
                         .bytes = 0, .user = user };
    cb(&r);
    return STM_OK;
}

static int op_poll(stm_bdev *base, int max_events)
{
    (void)base; (void)max_events;
    return 0;  /* completions fire synchronously inside submit_*. */
}

static int op_wait(stm_bdev *base, int max_events)
{
    (void)base; (void)max_events;
    /* There's nothing to wait for - completions already fired. Return
     * 0 rather than blocking forever; callers that arrive here have
     * a logic bug, but blocking would deadlock the mount path. */
    return 0;
}

static stm_status op_register_buffers(stm_bdev *base, void **bufs,
                                       uint32_t nbufs, size_t buf_len)
{
    (void)base; (void)bufs; (void)nbufs; (void)buf_len;
    return STM_ENOTSUPPORTED;
}

/* ------------------------------------------------------------------------- */
/* Close.                                                                     */
/*                                                                            */
/* The kobj handles auto-release when the process exits (stratumd is a        */
/* single-bdev process). Explicit close() is for completeness + future        */
/* multi-bdev contexts. We free what we can; kernel-side handle cleanup       */
/* on process exit covers the rest.                                           */
/* ------------------------------------------------------------------------- */

static void op_close(stm_bdev *base)
{
    thyla_bdev *d = (thyla_bdev *)base;

    /* No SYS_CLOSE on kobj handles today (the kernel has no syscall
     * to release individual KOBJ_MMIO/IRQ/DMA handles; cleanup is
     * at exit). When that lands, release here. v1.x followup. */

    if (d->lock_inited) pthread_mutex_destroy(&d->lock);
    free(d->base.path);
    free(d);
}

/* ------------------------------------------------------------------------- */
/* Ops vtable + open.                                                         */
/* ------------------------------------------------------------------------- */

static const struct stm_bdev_ops g_thylacine_ops = {
    .read              = op_read,
    .write             = op_write,
    .fsync             = op_fsync,
    .fdatasync         = op_fdatasync,
    .discard           = op_discard,
    .resize            = op_resize,
    .submit_read       = op_submit_read,
    .submit_write      = op_submit_write,
    .submit_fsync      = op_submit_fsync,
    .poll              = op_poll,
    .wait              = op_wait,
    .register_buffers  = op_register_buffers,
    .close             = op_close,
};

stm_status stm_bdev_open_thylacine(const char *path,
                                    const stm_bdev_open_opts *opts,
                                    stm_bdev **out)
{
    if (!out) return STM_EINVAL;

    thyla_bdev *d = calloc(1, sizeof *d);
    if (!d) return STM_ENOMEM;

    d->irq_handle  = -1;
    d->ring_handle = -1;
    d->data_handle = -1;

    if (pthread_mutex_init(&d->lock, NULL) != 0) {
        free(d);
        return STM_EBACKEND;
    }
    d->lock_inited = true;

    /* Phase 1: MMIO bank claim + map. */
    if (!claim_virtio_mmio_bank(d)) goto fail;

    /* Phase 2: find virtio-blk slot. */
    if (!find_blk_slot(d)) {
        pthread_mutex_destroy(&d->lock);
        free(d);
        return STM_ENODEV;
    }

    /* Phase 3: version check (refuses legacy mode). */
    if (mmio_read32(d->slot_va + VREG_VERSION) != VIRTIO_MMIO_VERSION_MODERN)
        goto fail;

    /* Phase 4: IRQ handle. */
    d->irq_handle = t_irq_create(d->intid, T_RIGHT_SIGNAL);
    if (d->irq_handle < 0) goto fail;

    /* Phase 5: ring DMA (4 KiB). */
    d->ring_handle = t_dma_create(VQ_RING_DMA_SIZE,
                                   T_RIGHT_READ | T_RIGHT_WRITE | T_RIGHT_MAP);
    if (d->ring_handle < 0) goto fail;
    int64_t rpa = t_dma_map(d->ring_handle, THYLA_RING_USER_VA,
                             T_PROT_READ | T_PROT_WRITE);
    if (rpa < 0) goto fail;
    d->ring_pa = (uint64_t)rpa;

    /* Phase 6: data DMA (1 MiB). */
    d->data_handle = t_dma_create(VQ_DATA_DMA_SIZE,
                                   T_RIGHT_READ | T_RIGHT_WRITE | T_RIGHT_MAP);
    if (d->data_handle < 0) goto fail;
    int64_t dpa = t_dma_map(d->data_handle, THYLA_DATA_USER_VA,
                             T_PROT_READ | T_PROT_WRITE);
    if (dpa < 0) goto fail;
    d->data_pa = (uint64_t)dpa;

    /* Pre-touch DMA pages so the kernel's userland_demand_page
     * installs the per-VA mappings before the descriptor / pattern
     * writes that follow. The Burrow demand-page path handles this
     * lazily; the touch loop just forces it eagerly so no later store
     * traps mid-state-machine. Mirror of the Rust driver. */
    for (uint64_t o = 0; o < VQ_RING_DMA_SIZE; o += THYLA_PAGE_SIZE)
        *(volatile uint8_t *)(THYLA_RING_USER_VA + o) = 0;
    for (uint64_t o = 0; o < VQ_DATA_DMA_SIZE; o += THYLA_PAGE_SIZE)
        *(volatile uint8_t *)(THYLA_DATA_USER_VA + o) = 0;

    /* Phase 7: VirtIO init. */
    if (!init_device(d->slot_va, d->ring_pa, &d->flush_supported)) goto fail;

    /* Phase 8: descriptor chain (one-time). */
    init_descriptors(THYLA_RING_USER_VA, d->ring_pa, d->data_pa);

    /* Phase 9: device capacity -> caps.size_bytes. VirtIO blk config
     * sec 5.2.4 - u64 capacity at config-space offset 0, in 512-byte
     * sectors. */
    uint64_t cap_lo = mmio_read32(d->slot_va + VREG_CONFIG + 0);
    uint64_t cap_hi = mmio_read32(d->slot_va + VREG_CONFIG + 4);
    uint64_t cap_sectors = cap_lo | (cap_hi << 32);

    d->base.ops       = &g_thylacine_ops;
    d->base.read_only = opts ? opts->read_only : false;
    d->base.path      = strdup(path ? path : "/dev/virtio-blk");
    if (!d->base.path) goto fail;

    d->base.caps.backend            = STM_BDEV_BACKEND_THYLACINE;
    d->base.caps.size_bytes         = cap_sectors * SECTOR_SIZE;
    d->base.caps.block_size         = (uint32_t)SECTOR_SIZE;
    d->base.caps.max_io_bytes       = (uint32_t)VQ_DATA_DMA_SIZE;
    d->base.caps.queue_depth        = 1;
    d->base.caps.has_discard        = false;
    d->base.caps.has_sqpoll         = false;
    d->base.caps.has_dax            = false;
    d->base.caps.has_fixed_buffers  = false;

    d->avail_idx = 0;

    *out = &d->base;
    return STM_OK;

fail:
    pthread_mutex_destroy(&d->lock);
    free(d->base.path);
    free(d);
    return STM_EBACKEND;
}
