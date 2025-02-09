/*

Copyright (C) 2017 Sergej Schumilo

This file is part of QEMU-PT (kAFL).

QEMU-PT is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

QEMU-PT is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with QEMU-PT.  If not, see <http://www.gnu.org/licenses/>.

*/
#include <errno.h>
#include "qemu/osdep.h"
#include "sysemu/sysemu.h"
#include "cpu.h"
#include "exec/ram_addr.h"
#include "qemu/rcu_queue.h"

#include "memory_access.h"
#include "nyx/hypercall/hypercall.h"
#include "debug.h"
#include "nyx/fast_vm_reload.h"
#include "exec/gdbstub.h"
#include "nyx/state/state.h"
#include "sysemu/kvm.h"
#include "nyx/helpers.h"

#define INVALID_ADDRESS 0xFFFFFFFFFFFFFFFFULL

static uint64_t get_48_paging_phys_addr(uint64_t cr3, uint64_t addr, bool read_from_snapshot);

#define x86_64_PAGE_SIZE        0x1000
#define x86_64_PAGE_MASK        ~(x86_64_PAGE_SIZE - 1)

static void set_mem_mode(CPUState *cpu){
	kvm_arch_get_registers(cpu);

	X86CPU *cpux86 = X86_CPU(cpu);
	CPUX86State *env = &cpux86->env;
    
    if (!(env->cr[0] & CR0_PG_MASK)) {
        GET_GLOBAL_STATE()->mem_mode = mm_32_protected;
        return;
    }
    else{
    	if (env->cr[4] & CR4_PAE_MASK) {
	        if (env->hflags & HF_LMA_MASK) {
	            if (env->cr[4] & CR4_LA57_MASK) {
	            	GET_GLOBAL_STATE()->mem_mode = mm_64_l5_paging;
                    return;
	            } else {
                    GET_GLOBAL_STATE()->mem_mode = mm_64_l4_paging;
                    return;
	            }
	        } 
	        else{
                GET_GLOBAL_STATE()->mem_mode = mm_32_pae;
                return;
	        }
	    } 
	    else {
            GET_GLOBAL_STATE()->mem_mode = mm_32_paging;
	    	return;
	    }
    }

    return;
}

/*  Warning: This might break memory handling for hypervisor fuzzing => FIXME LATER */
uint64_t get_paging_phys_addr(CPUState *cpu, uint64_t cr3, uint64_t addr){
    if(GET_GLOBAL_STATE()->mem_mode == mm_unkown){
        set_mem_mode(cpu);
    }

    switch(GET_GLOBAL_STATE()->mem_mode){
        case mm_32_protected:
            return addr & 0xFFFFFFFFULL;
        case mm_32_paging:
            fprintf(stderr, "mem_mode: mm_32_paging not implemented!\n");
            abort();
        case mm_32_pae:
            fprintf(stderr, "mem_mode: mm_32_pae not implemented!\n");
            abort();
        case mm_64_l4_paging:
            return get_48_paging_phys_addr(cr3, addr, false);
        case mm_64_l5_paging:
            fprintf(stderr, "mem_mode: mm_64_l5_paging not implemented!\n");
            abort();
        case mm_unkown:
            fprintf(stderr, "mem_mode: unkown!\n");
            abort();
    }
    return 0;
}

static uint64_t get_paging_phys_addr_snapshot(CPUState *cpu, uint64_t cr3, uint64_t addr){
    if(GET_GLOBAL_STATE()->mem_mode == mm_unkown){
        set_mem_mode(cpu);
    }

    switch(GET_GLOBAL_STATE()->mem_mode){
        case mm_32_protected:
            return addr & 0xFFFFFFFFULL;
        case mm_32_paging:
            fprintf(stderr, "mem_mode: mm_32_paging not implemented!\n");
            abort();
        case mm_32_pae:
            fprintf(stderr, "mem_mode: mm_32_pae not implemented!\n");
            abort();
        case mm_64_l4_paging:
            return get_48_paging_phys_addr(cr3, addr, true);
        case mm_64_l5_paging:
            fprintf(stderr, "mem_mode: mm_64_l5_paging not implemented!\n");
            abort();
        case mm_unkown:
            fprintf(stderr, "mem_mode: unkown!\n");
            abort();
    }
    return 0;
}

bool read_physical_memory(uint64_t address, uint8_t* data, uint32_t size, CPUState *cpu){
    kvm_arch_get_registers(cpu);
    cpu_physical_memory_read(address, data, size);
    return true;
}

bool write_physical_memory(uint64_t address, uint8_t* data, uint32_t size, CPUState *cpu){
    kvm_arch_get_registers(cpu);
    cpu_physical_memory_write(address, data, size);
    return true;
}

static void refresh_kvm(CPUState *cpu){
    //int ret = 0;
    if (!cpu->vcpu_dirty) {
        //kvm_arch_get_registers_fast(cpu);
        kvm_arch_get_registers(cpu);

        //cpu->vcpu_dirty = true;
    }
}

static void refresh_kvm_non_dirty(CPUState *cpu){
    if (!cpu->vcpu_dirty) {
        kvm_arch_get_registers_fast(cpu);
        //kvm_arch_get_registers(cpu);
    }
}

bool remap_payload_slot(uint64_t phys_addr, uint32_t slot, CPUState *cpu){
    //assert(0); /* nested code -> test me later */ 

    assert(GET_GLOBAL_STATE()->shared_payload_buffer_fd && GET_GLOBAL_STATE()->shared_payload_buffer_size);
    RAMBlock *block;
    refresh_kvm_non_dirty(cpu);

    uint32_t i = slot;

    phys_addr = address_to_ram_offset(phys_addr);

    QLIST_FOREACH_RCU(block, &ram_list.blocks, next) {
        if(!memcmp(block->idstr, "pc.ram", 6)){
            /* TODO: put assert calls here */ 
            munmap((void*)(((uint64_t)block->host) + phys_addr), x86_64_PAGE_SIZE);
            mmap((void*)(((uint64_t)block->host) + phys_addr), 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, GET_GLOBAL_STATE()->shared_payload_buffer_fd, (i*x86_64_PAGE_SIZE));

            //printf("MMUNMAP: %d\n", munmap((void*)(((uint64_t)block->host) + phys_addr), x86_64_PAGE_SIZE));
            //printf("MMAP: %p\n", mmap((void*)(((uint64_t)block->host) + phys_addr), 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, GET_GLOBAL_STATE()->shared_payload_buffer_fd, (i*x86_64_PAGE_SIZE)));

            fast_reload_blacklist_page(get_fast_reload_snapshot(), phys_addr);
            break;
        }
    }
    
    return true;
}

bool remap_slot(uint64_t addr, uint32_t slot, CPUState *cpu, int fd, uint64_t shm_size, bool virtual, uint64_t cr3){
    //printf("%s ---> \n", __func__);
    assert(fd && shm_size);
    assert((slot*x86_64_PAGE_SIZE) < shm_size);

    RAMBlock *block;
    refresh_kvm_non_dirty(cpu);

    uint32_t i = slot;

    uint64_t phys_addr = addr;
    if(virtual){
        phys_addr = get_paging_phys_addr(cpu, cr3, (addr & x86_64_PAGE_MASK));

        if(phys_addr == INVALID_ADDRESS){
			fprintf(stderr, "[QEMU-Nyx] Error: failed to translate v_addr (0x%lx) to p_addr!\n", addr);
            fprintf(stderr, "[QEMU-Nyx] Check if the buffer is present in the guest's memory...\n");
            exit(1);
        }

        phys_addr = address_to_ram_offset(phys_addr);
    }

    //printf("phys_addr -> %lx\n", phys_addr);
        
    debug_fprintf(stderr, "%s: addr => %lx phys_addr => %lx\n", __func__, addr, phys_addr);

    QLIST_FOREACH_RCU(block, &ram_list.blocks, next) {
        if(!memcmp(block->idstr, "pc.ram", 6)){
            /* TODO: put assert calls here */ 
            munmap((void*)(((uint64_t)block->host) + phys_addr), x86_64_PAGE_SIZE);
            mmap((void*)(((uint64_t)block->host) + phys_addr), 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, (i*x86_64_PAGE_SIZE));

            //printf("MMUNMAP: %d\n", munmap((void*)(((uint64_t)block->host) + phys_addr), x86_64_PAGE_SIZE));
            //printf("MMAP: %p\n", mmap((void*)(((uint64_t)block->host) + phys_addr), 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, (i*x86_64_PAGE_SIZE)));

            fast_reload_blacklist_page(get_fast_reload_snapshot(), phys_addr);
            break;
        }
    }
    
    return true;
}

bool remap_payload_slot_protected(uint64_t phys_addr, uint32_t slot, CPUState *cpu){
    //assert(0); /* nested code -> test me later */ 

    assert(GET_GLOBAL_STATE()->shared_payload_buffer_fd && GET_GLOBAL_STATE()->shared_payload_buffer_size);
    RAMBlock *block;
    refresh_kvm_non_dirty(cpu);

    uint32_t i = slot;

    phys_addr = address_to_ram_offset(phys_addr);

    QLIST_FOREACH_RCU(block, &ram_list.blocks, next) {
        if(!memcmp(block->idstr, "pc.ram", 6)){

            /* TODO: put assert calls here */ 
            munmap((void*)(((uint64_t)block->host) + phys_addr), x86_64_PAGE_SIZE);
            mmap((void*)(((uint64_t)block->host) + phys_addr), 0x1000, PROT_READ , MAP_SHARED | MAP_FIXED, GET_GLOBAL_STATE()->shared_payload_buffer_fd, (i*x86_64_PAGE_SIZE));

            //printf("MMUNMAP: %d\n", munmap((void*)(((uint64_t)block->host) + phys_addr), x86_64_PAGE_SIZE));
            //printf("MMAP: %p\n", mmap((void*)(((uint64_t)block->host) + phys_addr), 0x1000, PROT_READ , MAP_SHARED | MAP_FIXED, GET_GLOBAL_STATE()->shared_payload_buffer_fd, (i*x86_64_PAGE_SIZE)));

            fast_reload_blacklist_page(get_fast_reload_snapshot(), phys_addr);
            break;
        }
    }
    
    return true;
}

void resize_shared_memory(uint32_t new_size, uint32_t* shm_size, void** shm_ptr, int fd){
    assert(fd && *shm_size);

    /* check if the new_size is a multiple of PAGE_SIZE */
    if(new_size & (PAGE_SIZE-1)){
        new_size = (new_size & ~(PAGE_SIZE-1)) + PAGE_SIZE;
    }

    if(*shm_size >= new_size){
        /* no need no resize the buffer -> early exit */
        return;
    }

    assert(!GET_GLOBAL_STATE()->in_fuzzing_mode);
    assert(ftruncate(fd, new_size) == 0);

    if(shm_ptr){
        munmap(*shm_ptr , *shm_size);
	    *shm_ptr = (void*)mmap(0, new_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
        assert(*shm_ptr != MAP_FAILED);
    }

    *shm_size = new_size;
}

bool remap_payload_buffer(uint64_t virt_guest_addr, CPUState *cpu){    
    assert(GET_GLOBAL_STATE()->shared_payload_buffer_fd && GET_GLOBAL_STATE()->shared_payload_buffer_size);
    RAMBlock *block;
    refresh_kvm_non_dirty(cpu);

    for(uint32_t i = 0; i < (GET_GLOBAL_STATE()->shared_payload_buffer_size/x86_64_PAGE_SIZE); i++){
        //MemTxAttrs attrs = MEMTXATTRS_UNSPECIFIED;
        //hwaddr phys_addr = cpu_get_phys_page_attrs_debug(cpu, ((virt_guest_addr+(i*x86_64_PAGE_SIZE)) & x86_64_PAGE_MASK), &attrs);
        uint64_t phys_addr = get_paging_phys_addr(cpu, GET_GLOBAL_STATE()->parent_cr3, ((virt_guest_addr+(i*x86_64_PAGE_SIZE)) & x86_64_PAGE_MASK));

        assert(phys_addr != INVALID_ADDRESS);

        phys_addr = address_to_ram_offset(phys_addr);

        QLIST_FOREACH_RCU(block, &ram_list.blocks, next) {
            if(!memcmp(block->idstr, "pc.ram", 6)){
                //printf("MMUNMAP: %d\n", munmap((void*)(((uint64_t)block->host) + phys_addr), x86_64_PAGE_SIZE));
                if(munmap((void*)(((uint64_t)block->host) + phys_addr), x86_64_PAGE_SIZE) == -1){
                    fprintf(stderr, "munmap failed!\n");
                    //exit(1);
                    assert(false);
                }
                //printf("MMAP: %lx\n", mmap((void*)(((uint64_t)block->host) + phys_addr), 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, shared_payload_buffer_fd, (i*x86_64_PAGE_SIZE)));

                if(mmap((void*)(((uint64_t)block->host) + phys_addr), 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, GET_GLOBAL_STATE()->shared_payload_buffer_fd, (i*x86_64_PAGE_SIZE)) == MAP_FAILED){
                    fprintf(stderr, "mmap failed!\n");
                    //exit(1);
                    assert(false);
                }

                memset((block->host) + phys_addr, 0xab, 0x1000);

                if(GET_GLOBAL_STATE()->protect_payload_buffer){
                    mprotect((block->host) + phys_addr, 0x1000, PROT_READ);
                }

                fast_reload_blacklist_page(get_fast_reload_snapshot(), phys_addr);
                break;
            }
        }
    }
    return true;
}

bool write_virtual_memory(uint64_t address, uint8_t* data, uint32_t size, CPUState *cpu)
{
    /* Todo: later &address_space_memory + phys_addr -> mmap SHARED */
    int asidx;
    MemTxAttrs attrs;
    hwaddr phys_addr;
    MemTxResult res;

    uint64_t counter, l, i;

    counter = size;
    while(counter != 0){
        l = x86_64_PAGE_SIZE;
        if (l > counter)
            l = counter;

        refresh_kvm(cpu);
        //cpu_synchronize_state(cpu);
        asidx = cpu_asidx_from_attrs(cpu, MEMTXATTRS_UNSPECIFIED);
        attrs = MEMTXATTRS_UNSPECIFIED;
        phys_addr = cpu_get_phys_page_attrs_debug(cpu, (address & x86_64_PAGE_MASK), &attrs);

        if (phys_addr == INVALID_ADDRESS){
            QEMU_PT_PRINTF(MEM_PREFIX, "phys_addr == -1:\t%lx", address);
            return false;
        }
        
        phys_addr += (address & ~x86_64_PAGE_MASK);   
        res = address_space_rw(cpu_get_address_space(cpu, asidx), phys_addr, MEMTXATTRS_UNSPECIFIED, data, l, true);
        if (res != MEMTX_OK){
            QEMU_PT_PRINTF(MEM_PREFIX, "!MEMTX_OK:\t%lx", address);
            return false;
        }   

        i++;
        data += l;
        address += l;
        counter -= l;
    }

    return true;
}


void hexdump_virtual_memory(uint64_t address, uint32_t size, CPUState *cpu){
    assert(size < 0x100000); // 1MB max 
    uint64_t i = 0;
    uint8_t tmp[17];
    uint8_t* data = malloc(size);
    bool success = read_virtual_memory(address, data, size, cpu);

    if(success){
        for (i = 0; i < size; i++){
            if(!(i % 16)){
                if (i != 0){
                    printf ("  %s\n", tmp);
                }
                printf ("  %04lx ", i);
            }
            printf (" %02x", data[i]);

            if ((data[i] < 0x20) || (data[i] > 0x7e))
                tmp[i % 16] = '.';
            else
                tmp[i % 16] = data[i];
            tmp[(i % 16) + 1] = '\0';
        }

        while ((i % 16) != 0) {
            printf ("   ");
            i++;
        }
        printf ("  %s\n", tmp);
    }

    free(data);
}


static int redqueen_insert_sw_breakpoint(CPUState *cs, struct kvm_sw_breakpoint *bp)
{
    static const uint8_t int3 = 0xcc;

    hwaddr phys_addr = (hwaddr) get_paging_phys_addr(cs, GET_GLOBAL_STATE()->parent_cr3, bp->pc);
    int asidx = cpu_asidx_from_attrs(cs, MEMTXATTRS_UNSPECIFIED);

    if (address_space_rw(cpu_get_address_space(cs, asidx), phys_addr, MEMTXATTRS_UNSPECIFIED, (uint8_t *)&bp->saved_insn, 1, 0) ||
        address_space_rw(cpu_get_address_space(cs, asidx), phys_addr, MEMTXATTRS_UNSPECIFIED, (uint8_t *)&int3, 1, 1)) {
        //fprintf(stderr, "%s WRITTE AT %lx %lx failed!\n", __func__, bp->pc, phys_addr);
        return -EINVAL;
    }

    return 0;
}

static int redqueen_remove_sw_breakpoint(CPUState *cs, struct kvm_sw_breakpoint *bp)
{
    uint8_t int3;

    hwaddr phys_addr = (hwaddr) get_paging_phys_addr(cs, GET_GLOBAL_STATE()->parent_cr3, bp->pc);
    int asidx = cpu_asidx_from_attrs(cs, MEMTXATTRS_UNSPECIFIED);

    if (address_space_rw(cpu_get_address_space(cs, asidx), phys_addr, MEMTXATTRS_UNSPECIFIED, (uint8_t *)&int3, 1, 0) || int3 != 0xcc ||
        address_space_rw(cpu_get_address_space(cs, asidx), phys_addr, MEMTXATTRS_UNSPECIFIED, (uint8_t *)&bp->saved_insn, 1, 1)) {
        //fprintf(stderr, "%s failed\n", __func__);
        return -EINVAL;
    }

    return 0;
}

static struct kvm_sw_breakpoint *redqueen_find_breakpoint(CPUState *cpu, target_ulong pc){
    struct kvm_sw_breakpoint *bp;

    QTAILQ_FOREACH(bp, &GET_GLOBAL_STATE()->redqueen_breakpoints, entry) {
        if (bp->pc == pc) {
            return bp;
        }
    }
    return NULL;
}

static int redqueen_breakpoints_active(CPUState *cpu){
    return !QTAILQ_EMPTY(&GET_GLOBAL_STATE()->redqueen_breakpoints);
}

struct kvm_set_guest_debug_data {
    struct kvm_guest_debug dbg;
    int err;
};

static int redqueen_update_guest_debug(CPUState *cpu) {
    struct kvm_set_guest_debug_data data;

    data.dbg.control = 0;

    if (redqueen_breakpoints_active(cpu)) {
        data.dbg.control |= KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP;
    }

    return kvm_vcpu_ioctl(cpu, KVM_SET_GUEST_DEBUG, &data.dbg);

    return 0;
}

static void redqueen_remove_all_breakpoints(CPUState *cpu) {
    struct kvm_sw_breakpoint *bp, *next;

    QTAILQ_FOREACH_SAFE(bp, &GET_GLOBAL_STATE()->redqueen_breakpoints, entry, next) {
        redqueen_remove_sw_breakpoint(cpu, bp);
        QTAILQ_REMOVE(&GET_GLOBAL_STATE()->redqueen_breakpoints, bp, entry);
        g_free(bp);
    }

    redqueen_update_guest_debug(cpu);
}

static int redqueen_insert_breakpoint(CPUState *cpu, target_ulong addr, target_ulong len){
    struct kvm_sw_breakpoint *bp;
    int err;

    bp = redqueen_find_breakpoint(cpu, addr);
    if (bp) {
        bp->use_count++;
        return 0;
    }

    bp = g_malloc(sizeof(struct kvm_sw_breakpoint));
    bp->pc = addr;
    bp->use_count = 1;

    err = redqueen_insert_sw_breakpoint(cpu, bp);
    if (err) {
        g_free(bp);
        return err;
    }

    QTAILQ_INSERT_HEAD(&GET_GLOBAL_STATE()->redqueen_breakpoints, bp, entry);
    
    err = redqueen_update_guest_debug(cpu);
    if(err){
        return err;
    }

    return 0;
}

static int redqueen_remove_breakpoint(CPUState *cpu, target_ulong addr, target_ulong len){
    struct kvm_sw_breakpoint *bp;
    int err;

    bp = redqueen_find_breakpoint(cpu, addr);
    if (!bp) {
        return -ENOENT;
    }

    if (bp->use_count > 1) {
        bp->use_count--;
        return 0;
    }

    err = redqueen_remove_sw_breakpoint(cpu, bp);
    if (err) {
        return err;
    }

    QTAILQ_REMOVE(&GET_GLOBAL_STATE()->redqueen_breakpoints, bp, entry);
    g_free(bp);
    
    err = redqueen_update_guest_debug(cpu);
    if(err){
        return err;
    }

    return 0;
}

int insert_breakpoint(CPUState *cpu, uint64_t addr, uint64_t len){
    redqueen_insert_breakpoint(cpu, addr, len);
    redqueen_update_guest_debug(cpu);
    return 0;
}


int remove_breakpoint(CPUState *cpu, uint64_t addr, uint64_t len){
    //fprintf(stderr, "%s %lx\n", __func__, addr);
    redqueen_remove_breakpoint(cpu, addr, len);
    redqueen_update_guest_debug(cpu);
    return 0;
}

void remove_all_breakpoints(CPUState *cpu){
    redqueen_remove_all_breakpoints(cpu);
}













#define PPAGE_SIZE 0x1000
#define PENTRIES 0x200
#define PLEVEL_4_SHIFT 12
#define PLEVEL_3_SHIFT 21
#define PLEVEL_2_SHIFT 30
#define PLEVEL_1_SHIFT 39
#define SIGN_EXTEND_TRESHOLD 0x100
#define SIGN_EXTEND 0xFFFF000000000000ULL
#define PAGETABLE_MASK 0x1FFFFFFFFF000ULL
#define PML4_ENTRY_MASK 0x1FFFFFFFFF000ULL
#define PML3_ENTRY_MASK 0x1FFFFC0000000ULL
#define PML2_ENTRY_MASK 0x1FFFFFFE00000ULL

#define CHECK_BIT(var,pos) !!(((var) & (1ULL<<(pos))))


static void write_address(uint64_t address, uint64_t size, uint64_t prot){
    //fprintf(stderr, "%s %lx %lx %lx\n", __func__, address, size, prot);
    static uint64_t next_address = PAGETABLE_MASK;
    static uint64_t last_address = 0x0; 
    static uint64_t last_prot = 0;

    if((address != next_address || prot != last_prot)){
        /* do not print guard pages or empty pages without any permissions */
        if(last_address && prot && (last_address+size != next_address || prot != last_prot)){
            fprintf(stderr, "%016lx - %016lx %c%c%c\n",
                last_address, next_address,
                CHECK_BIT(last_prot, 1) ? 'W' : '-', 
                CHECK_BIT(last_prot, 2) ? 'U' : 'K', 
                !CHECK_BIT(last_prot, 63)? 'X' : '-');
        }
        last_address = address;
    }
    next_address = address+size;
    last_prot = prot;
    
}

void print_48_paging2(uint64_t cr3){
    uint64_t paging_entries_level_1[PENTRIES];
    uint64_t paging_entries_level_2[PENTRIES];
    uint64_t paging_entries_level_3[PENTRIES];
    uint64_t paging_entries_level_4[PENTRIES];

    uint64_t address_identifier_1, address_identifier_2, address_identifier_3, address_identifier_4;
    uint32_t i1, i2, i3,i4;

    cpu_physical_memory_rw((cr3&PAGETABLE_MASK), (uint8_t *) paging_entries_level_1, PPAGE_SIZE, false);
    for(i1 = 0; i1 < 512; i1++){
        if(paging_entries_level_1[i1]){
            address_identifier_1 = ((uint64_t)i1) << PLEVEL_1_SHIFT;
            if (i1 & SIGN_EXTEND_TRESHOLD){
                address_identifier_1 |= SIGN_EXTEND;
            }
            if(CHECK_BIT(paging_entries_level_1[i1], 0)){ /* otherwise swapped out */ 
                cpu_physical_memory_rw((paging_entries_level_1[i1]&PAGETABLE_MASK), (uint8_t *) paging_entries_level_2, PPAGE_SIZE, false);
                for(i2 = 0; i2 < PENTRIES; i2++){
                    if(paging_entries_level_2[i2]){
                        address_identifier_2 = (((uint64_t)i2) << PLEVEL_2_SHIFT) + address_identifier_1;
                        if (CHECK_BIT(paging_entries_level_2[i2], 0)){ /* otherwise swapped out */ 
                            if((paging_entries_level_2[i2]&PAGETABLE_MASK) == (paging_entries_level_1[i1]&PAGETABLE_MASK)){
                                /* loop */
                                continue;
                            }

                            if (CHECK_BIT(paging_entries_level_2[i2], 7)){
                                    write_address(address_identifier_2, 0x40000000, (uint64_t)paging_entries_level_2[i2] & ((1ULL<<63) | (1ULL<<2) | (1ULL<<1)));
                            }
                            else{
                                /* otherwise this PDPE references a 1GB page */
                                cpu_physical_memory_rw((paging_entries_level_2[i2]&PAGETABLE_MASK), (uint8_t *) paging_entries_level_3, PPAGE_SIZE, false);
                                for(i3 = 0; i3 < PENTRIES; i3++){
                                    if(paging_entries_level_3[i3]){
                                        address_identifier_3 = (((uint64_t)i3) << PLEVEL_3_SHIFT) + address_identifier_2;
                                        if (CHECK_BIT(paging_entries_level_3[i3], 0)){ /* otherwise swapped out */ 
                                            if (CHECK_BIT(paging_entries_level_3[i3], 7)){
                                                write_address(address_identifier_3, 0x200000, (uint64_t)paging_entries_level_3[i3] & ((1ULL<<63) | (1ULL<<2) | (1ULL<<1)));
                                            }
                                            else{
                                                cpu_physical_memory_rw((paging_entries_level_3[i3]&PAGETABLE_MASK), (uint8_t *) paging_entries_level_4, PPAGE_SIZE, false);
                                                for(i4 = 0; i4 < PENTRIES; i4++){
                                                    if(paging_entries_level_4[i4]){
                                                        address_identifier_4 = (((uint64_t)i4) << PLEVEL_4_SHIFT) + address_identifier_3;
                                                        if (CHECK_BIT(paging_entries_level_4[i4], 0)){
                                                            write_address(address_identifier_4, 0x1000, (uint64_t)paging_entries_level_4[i4] & ((1ULL<<63) | (1ULL<<2) | (1ULL<<1)));
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }

                            }
                        }
                    }
                }
            }
        }
    }
    write_address(0, 0x1000, 0);
}


static uint64_t* load_page_table(uint64_t page_table_address, uint64_t* paging_entries_buffer, uint8_t level, bool read_from_snapshot, bool *success){
    if(page_table_address == INVALID_ADDRESS){
        *success = false;
    }

    if (read_from_snapshot){
        *success = read_snapshot_memory(get_fast_reload_snapshot(), page_table_address, (uint8_t *) paging_entries_buffer, PPAGE_SIZE);   
    }
    else{
        cpu_physical_memory_rw(page_table_address, (uint8_t *) paging_entries_buffer, PPAGE_SIZE, false);
        *success = true; /* fix this */
    }
    return paging_entries_buffer;
}

static uint64_t get_48_paging_phys_addr(uint64_t cr3, uint64_t addr, bool read_from_snapshot){
    /* signedness broken af -> fix me! */
    uint16_t pml_4_index = (addr & 0xFF8000000000ULL) >> 39;
    uint16_t pml_3_index = (addr & 0x0007FC0000000UL) >> 30;
    uint16_t pml_2_index = (addr & 0x000003FE00000UL) >> 21;
    uint16_t pml_1_index = (addr & 0x00000001FF000UL) >> 12;

    uint64_t address_identifier_4;
    uint64_t paging_entries_buffer[PENTRIES];
    uint64_t* paging_entries_buffer_ptr = NULL;
    uint64_t page_table_address = 0;

    bool success = false;

    page_table_address = (cr3&PAGETABLE_MASK);
    paging_entries_buffer_ptr = load_page_table(page_table_address, paging_entries_buffer, 0, read_from_snapshot, &success);

    if (unlikely(success == false)){
        goto fail;
    }

    if(paging_entries_buffer_ptr[pml_4_index]){
        address_identifier_4 = ((uint64_t)pml_4_index) << PLEVEL_1_SHIFT;
        if (pml_4_index & SIGN_EXTEND_TRESHOLD){
            address_identifier_4 |= SIGN_EXTEND;
        }
        if(CHECK_BIT(paging_entries_buffer_ptr[pml_4_index], 0)){ /* otherwise swapped out */ 

            page_table_address = (paging_entries_buffer_ptr[pml_4_index]&PAGETABLE_MASK);
            paging_entries_buffer_ptr = load_page_table(page_table_address, paging_entries_buffer, 1, read_from_snapshot, &success);

            if (unlikely(success == false)){
                goto fail;
            }

            if(paging_entries_buffer_ptr[pml_3_index]){

                if (CHECK_BIT(paging_entries_buffer_ptr[pml_3_index], 0)){ /* otherwise swapped out */ 

                    if (CHECK_BIT(paging_entries_buffer_ptr[pml_3_index], 7)){
                        /* 1GB PAGE */
                        return (paging_entries_buffer_ptr[pml_3_index] & PML3_ENTRY_MASK) | (0x7FFFFFFF & addr); 
                    }
                    else{

                        page_table_address = (paging_entries_buffer_ptr[pml_3_index]&PAGETABLE_MASK);
                        paging_entries_buffer_ptr = load_page_table(page_table_address, paging_entries_buffer, 2, read_from_snapshot, &success);

                        if (unlikely(success == false)){
                            goto fail;
                        }

                        if(paging_entries_buffer_ptr[pml_2_index]){
                            if (CHECK_BIT(paging_entries_buffer_ptr[pml_2_index], 0)){ /* otherwise swapped out */ 
                                if (CHECK_BIT(paging_entries_buffer_ptr[pml_2_index], 7)){
                                    /* 2MB PAGE */
                                    return (paging_entries_buffer_ptr[pml_2_index] & PML2_ENTRY_MASK) | (0x3FFFFF & addr); 
                                }
                                else{

                                    page_table_address = (paging_entries_buffer_ptr[pml_2_index]&PAGETABLE_MASK);
                                    paging_entries_buffer_ptr = load_page_table(page_table_address, paging_entries_buffer, 3, read_from_snapshot, &success);

                                    if (unlikely(success == false)){
                                         goto fail;
                                    }

                                    if(paging_entries_buffer_ptr[pml_1_index]){
                                        if (CHECK_BIT(paging_entries_buffer_ptr[pml_1_index], 0)){
                                            /* 4 KB PAGE */
                                            return (paging_entries_buffer_ptr[pml_1_index] & PML4_ENTRY_MASK) | (0xFFF & addr); 
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fail:
    
    return INVALID_ADDRESS;
}

//#define DEBUG_48BIT_WALK

bool read_virtual_memory(uint64_t address, uint8_t* data, uint32_t size, CPUState *cpu){
    uint8_t tmp_buf[x86_64_PAGE_SIZE];
    //MemTxAttrs attrs;
    hwaddr phys_addr;
    int asidx;
    
    uint64_t amount_copied = 0;
    
    kvm_arch_get_registers_fast(cpu);
    CPUX86State *env = &(X86_CPU(cpu))->env;

    // copy per page 
    while(amount_copied < size){
        uint64_t len_to_copy = (size - amount_copied);
        if(len_to_copy > x86_64_PAGE_SIZE)
            len_to_copy = x86_64_PAGE_SIZE;

        asidx = cpu_asidx_from_attrs(cpu, MEMTXATTRS_UNSPECIFIED);
        //MemTxAttrs attrs = MEMTXATTRS_UNSPECIFIED;
#ifdef DEBUG_48BIT_WALK
        phys_addr_2 = cpu_get_phys_page_attrs_debug(cpu, (address & x86_64_PAGE_MASK), &attrs);
#endif
        phys_addr = (hwaddr)get_paging_phys_addr(cpu, env->cr[3], address) & 0xFFFFFFFFFFFFF000ULL;// != 0xFFFFFFFFFFFFFFFFULL)
        //QEMU_PT_PRINTF(MEM_PREFIX, "TRANSLATE: %lx -> %lx == %lx", address, phys_addr, phys_addr_2);

#ifdef DEBUG_48BIT_WALK
        assert(phys_addr == phys_addr_2);
#endif

        if (phys_addr == INVALID_ADDRESS){
            uint64_t next_page = (address & x86_64_PAGE_MASK) + x86_64_PAGE_SIZE;
            uint64_t len_skipped =next_page-address;  
            if(len_skipped > size-amount_copied){
                len_skipped = size-amount_copied;
            }

            fprintf(stderr, "Warning, read from unmapped memory:\t%lx, skipping to %lx", address, next_page);
            QEMU_PT_PRINTF(MEM_PREFIX, "Warning, read from unmapped memory:\t%lx, skipping to %lx", address, next_page);
            memset( data+amount_copied, ' ',  len_skipped);
            address += len_skipped;
            amount_copied += len_skipped;
            continue;
        }
        
        phys_addr += (address & ~x86_64_PAGE_MASK);
        uint64_t remaining_on_page = x86_64_PAGE_SIZE - (address & ~x86_64_PAGE_MASK);
        if(len_to_copy > remaining_on_page){
            len_to_copy = remaining_on_page;
        }

        MemTxResult txt = address_space_rw(cpu_get_address_space(cpu, asidx), phys_addr, MEMTXATTRS_UNSPECIFIED, tmp_buf, len_to_copy, 0);
        if(txt){
            QEMU_PT_PRINTF(MEM_PREFIX, "Warning, read failed:\t%lx (%lx)", address, phys_addr);
        }
        
        memcpy(data+amount_copied, tmp_buf, len_to_copy);
        
        address += len_to_copy;
        amount_copied += len_to_copy;
    }
    
    return true;
}

bool is_addr_mapped_cr3(uint64_t address, CPUState *cpu, uint64_t cr3){
    return (get_paging_phys_addr(cpu, cr3, address) != INVALID_ADDRESS);
} 

bool is_addr_mapped(uint64_t address, CPUState *cpu){
    CPUX86State *env = &(X86_CPU(cpu))->env;
    kvm_arch_get_registers_fast(cpu);
    return (get_paging_phys_addr(cpu, env->cr[3], address) != INVALID_ADDRESS);
} 

bool is_addr_mapped_cr3_snapshot(uint64_t address, CPUState *cpu, uint64_t cr3){
    return (get_paging_phys_addr_snapshot(cpu, cr3, address) != INVALID_ADDRESS);
} 

bool dump_page_cr3_snapshot(uint64_t address, uint8_t* data, CPUState *cpu, uint64_t cr3){
    fast_reload_t* snapshot = get_fast_reload_snapshot();
    uint64_t phys_addr = get_paging_phys_addr_snapshot(cpu, cr3, address);
    if(phys_addr == INVALID_ADDRESS){
        return false;
    }
    else{
        return read_snapshot_memory(snapshot, phys_addr, data, PPAGE_SIZE);   
    }
}


bool dump_page_cr3_ht(uint64_t address, uint8_t* data, CPUState *cpu, uint64_t cr3){
    hwaddr phys_addr = (hwaddr) get_paging_phys_addr(cpu, cr3, address);
    int asidx = cpu_asidx_from_attrs(cpu, MEMTXATTRS_UNSPECIFIED);
    if(phys_addr == INVALID_ADDRESS || address_space_rw(cpu_get_address_space(cpu, asidx), phys_addr, MEMTXATTRS_UNSPECIFIED, data, 0x1000, 0)){
        if(phys_addr != INVALID_ADDRESS){
            fprintf(stderr, "%s: Warning, read failed:\t%lx (%lx)\n", __func__, address, phys_addr);
        }
        return false;
    }
    return true;
}

bool dump_page_ht(uint64_t address, uint8_t* data, CPUState *cpu){
    CPUX86State *env = &(X86_CPU(cpu))->env;
    kvm_arch_get_registers_fast(cpu);
    hwaddr phys_addr = (hwaddr) get_paging_phys_addr(cpu, env->cr[3], address);
    int asidx = cpu_asidx_from_attrs(cpu, MEMTXATTRS_UNSPECIFIED);
    if(phys_addr == 0xffffffffffffffffULL || address_space_rw(cpu_get_address_space(cpu, asidx), phys_addr, MEMTXATTRS_UNSPECIFIED, data, 0x1000, 0)){
        if(phys_addr != 0xffffffffffffffffULL){
            fprintf(stderr, "%s: Warning, read failed:\t%lx (%lx)\n", __func__, address, phys_addr);
        }
    }
    return true;
}

uint64_t disassemble_at_rip(int fd, uint64_t address, CPUState *cpu, uint64_t cr3){

	csh handle;

	size_t code_size = 256;
    uint8_t code_ptr[256];


    /* don't => GET_GLOBAL_STATE()->disassembler_word_width */
	if (cs_open(CS_ARCH_X86, get_capstone_mode(GET_GLOBAL_STATE()->disassembler_word_width), &handle) != CS_ERR_OK)
		assert(false);
	
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    cs_insn* insn = cs_malloc(handle);

    read_virtual_memory(address, code_ptr, code_size, cpu);

    int count = cs_disasm(handle, code_ptr, code_size, address, 5, &insn);
    if(count > 0){
        for(int i = 0; i < count; i++){
            fprintf(stderr, "=> 0x%"PRIx64":\t%s\t\t%s\n", insn[i].address, insn[i].mnemonic, insn[i].op_str);
        }
    }
    else{
        fprintf(stderr, "ERROR in %s at %lx (cr3: %lx)\n", __func__, address, cr3);
    }
    
    
    cs_free(insn, 1);
    cs_close(&handle);
    return 0;
}



