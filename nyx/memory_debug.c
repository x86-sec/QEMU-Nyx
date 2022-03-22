#include "memory_debug.h"

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "cpu.h"

bool is_smm(CPUState *cpu) {
    X86CPU *x86_cpu = X86_CPU(cpu);
    return x86_cpu->env.hflags >> HF_SMM_SHIFT & 1;
}

AddressSpace *get_address_space(CPUState *cpu, const char *name) {
    static AddressSpace *r = NULL;

    if (r != NULL) {
      return r;
    }

    AddressSpace *as = cpu->as, *cur = as;
    if (as == NULL) {
      return r;
    }

    do {
        fprintf(stderr, "get_address_space: @ of cur address space @0x%016lx\n", (uintptr_t)cur);
        fprintf(stderr, "get_address_space: name of cur address space %s\n", cur->name);
        if (strcmp(cur->name, name) == 0) {
            fprintf(stderr, "get_address_space: found SMM address space\n");
            fprintf(stderr, "get_address_space: root region name %s\n", cur->root->name);
            r = cur;
        }
        cur = cur->address_spaces_link.tqe_next;
        fprintf(stderr, "get_address_space: @ of next cur address space @0x%016lx\n", (uintptr_t)cur);
    } while (cur != as && cur != NULL);

    return r;
}

uint64_t x86_ldq_phys_as(CPUState *cs, hwaddr addr, AddressSpace *as)
{
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;
    MemTxAttrs attrs = cpu_get_mem_attrs(env);
    // This line from original x86_ldq_phys cannot work when KVM is used because
    // the second AS for SMM at asidx 1 is missing. We push it as a parameter.
    // AddressSpace *as = cpu_addressspace(cs, attrs);

    return address_space_ldq(as, addr, attrs, NULL);
}

hwaddr x86_cpu_get_phys_page_attrs_as(CPUState *cs, vaddr addr,
        MemTxAttrs *attrs, AddressSpace *as)
{
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;
    target_ulong pde_addr, pte_addr;
    uint64_t pte;
    int32_t a20_mask;
    uint32_t page_offset;
    int page_size;

    *attrs = cpu_get_mem_attrs(env);

    a20_mask = x86_get_a20_mask(env);
    if (!(env->cr[0] & CR0_PG_MASK)) {
        pte = addr & a20_mask;
        page_size = 4096;
    } else if (env->cr[4] & CR4_PAE_MASK) {
        target_ulong pdpe_addr;
        uint64_t pde, pdpe;

#ifdef TARGET_X86_64
        if (env->hflags & HF_LMA_MASK) {
            bool la57 = env->cr[4] & CR4_LA57_MASK;
            uint64_t pml5e_addr, pml5e;
            uint64_t pml4e_addr, pml4e;
            int32_t sext;

            /* test virtual address sign extension */
            sext = la57 ? (int64_t)addr >> 56 : (int64_t)addr >> 47;
            if (sext != 0 && sext != -1) {
                return -1;
            }

            if (la57) {
                pml5e_addr = ((env->cr[3] & ~0xfff) +
                        (((addr >> 48) & 0x1ff) << 3)) & a20_mask;
                pml5e = x86_ldq_phys_as(cs, pml5e_addr, as);
                if (!(pml5e & PG_PRESENT_MASK)) {
                    return -1;
                }
            } else {
                pml5e = env->cr[3];
            }

            pml4e_addr = ((pml5e & PG_ADDRESS_MASK) +
                    (((addr >> 39) & 0x1ff) << 3)) & a20_mask;
            pml4e = x86_ldq_phys_as(cs, pml4e_addr, as);
            if (!(pml4e & PG_PRESENT_MASK)) {
                return -1;
            }
            pdpe_addr = ((pml4e & PG_ADDRESS_MASK) +
                         (((addr >> 30) & 0x1ff) << 3)) & a20_mask;
            pdpe = x86_ldq_phys_as(cs, pdpe_addr, as);
            if (!(pdpe & PG_PRESENT_MASK)) {
                return -1;
            }
            if (pdpe & PG_PSE_MASK) {
                page_size = 1024 * 1024 * 1024;
                pte = pdpe;
                goto out;
            }

        } else
#endif
        {
            pdpe_addr = ((env->cr[3] & ~0x1f) + ((addr >> 27) & 0x18)) &
                a20_mask;
            pdpe = x86_ldq_phys_as(cs, pdpe_addr, as);
            if (!(pdpe & PG_PRESENT_MASK))
                return -1;
        }

        pde_addr = ((pdpe & PG_ADDRESS_MASK) +
                    (((addr >> 21) & 0x1ff) << 3)) & a20_mask;
        pde = x86_ldq_phys_as(cs, pde_addr, as);
        if (!(pde & PG_PRESENT_MASK)) {
            return -1;
        }
        if (pde & PG_PSE_MASK) {
            /* 2 MB page */
            page_size = 2048 * 1024;
            pte = pde;
        } else {
            /* 4 KB page */
            pte_addr = ((pde & PG_ADDRESS_MASK) +
                        (((addr >> 12) & 0x1ff) << 3)) & a20_mask;
            page_size = 4096;
            pte = x86_ldq_phys_as(cs, pte_addr, as);
        }
        if (!(pte & PG_PRESENT_MASK)) {
            return -1;
        }
    } else {
        uint32_t pde;

        /* page directory entry */
        pde_addr = ((env->cr[3] & ~0xfff) + ((addr >> 20) & 0xffc)) & a20_mask;
        pde = x86_ldl_phys(cs, pde_addr);
        if (!(pde & PG_PRESENT_MASK))
            return -1;
        if ((pde & PG_PSE_MASK) && (env->cr[4] & CR4_PSE_MASK)) {
            pte = pde | ((pde & 0x1fe000LL) << (32 - 13));
            page_size = 4096 * 1024;
        } else {
            /* page directory entry */
            pte_addr = ((pde & ~0xfff) + ((addr >> 10) & 0xffc)) & a20_mask;
            pte = x86_ldl_phys(cs, pte_addr);
            if (!(pte & PG_PRESENT_MASK)) {
                return -1;
            }
            page_size = 4096;
        }
        pte = pte & a20_mask;
    }

#ifdef TARGET_X86_64
out:
#endif
    pte &= PG_ADDRESS_MASK & ~(page_size - 1);
    page_offset = (addr & TARGET_PAGE_MASK) & (page_size - 1);
    return pte | page_offset;
}
