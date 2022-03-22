#ifndef MEMORY_DEBUG_H
#define MEMORY_DEBUG_H

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "cpu.h"
#include "sysemu/kvm.h"

bool is_smm(CPUState *cpu);
AddressSpace *get_address_space(CPUState *cpu, const char *name);
hwaddr x86_cpu_get_phys_page_attrs_as(CPUState *cs, vaddr addr,
        MemTxAttrs *attrs, AddressSpace *as);
uint64_t x86_ldq_phys_as(CPUState *cs, hwaddr addr, AddressSpace *as);

static MemTxResult memory_debug_physical_memory_rw(CPUState *cpu, hwaddr addr,
    uint8_t *buf, hwaddr len, int is_write) {

  MemTxResult r;

  if (kvm_enabled() /* && is_smm(cpu) */) {
    // Let's guess this access is within smram because the cpu is in smram
    // If not, rollback to regular access
    AddressSpace *as = get_address_space(cpu, "KVM-SMRAM");
    if (!as) {
      printf("Failed to get SMM address space");
      assert(false);
    }
    r = address_space_rw(as, addr, MEMTXATTRS_UNSPECIFIED, buf,
        len, is_write);
    // Not is SMRAM address space, go for regular address space
    if (r == MEMTX_OK) {
      goto ok;
    }
    fprintf(stderr, "%s: Failed to fetch memory in KVM-SMRAM address space rollback to regular addresspace\n", __func__);
  }

  // Non SMM or SMM access failed, roolback to regular

  int asidx = cpu_asidx_from_attrs(cpu, MEMTXATTRS_UNSPECIFIED);
  return address_space_rw(cpu_get_address_space(cpu, asidx), addr,
      MEMTXATTRS_UNSPECIFIED, buf, len, is_write);

ok:
  return r;

}

#endif
