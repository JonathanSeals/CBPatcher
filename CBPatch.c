//
//  CBPatch.c
//  CBPatcher
//
//  Created by JonathanSeals on 11/18/18.
//  Copyright © 2018 JonathanSeals. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mac_policy.h"
#include <mach-o/nlist.h>
#include <mach-o/dyld.h>
#include <mach-o/fat.h>
#include <mach/vm_types.h>
#include <dlfcn.h>
#include <sys/mman.h>

#define PatchLog(...) printf("[CBPatch] " __VA_ARGS__)

/* Some stuff from https://github.com/kpwn/yalu/blob/master/data/dyldmagic/libxnuexp.m, courtesy of qwertyoruiop */

/* Find start of a section in a macho */
struct section *find_section(struct segment_command *seg, const char *name)
{
    struct section *sect, *fs = NULL;
    uint32_t i = 0;
    for (i = 0, sect = (struct section *)((uintptr_t)seg + (uintptr_t)sizeof(struct segment_command));
         i < seg->nsects;
         i++, sect = (struct section*)((uintptr_t)sect + sizeof(struct section)))
    {
        if (!strcmp(sect->sectname, name)) {
            fs = sect;
            break;
        }
    }
    return fs;
}

/* Find start of a load command in a macho */
struct load_command *find_load_command(struct mach_header *mh, uint32_t cmd)
{
    struct load_command *lc, *flc;
    
    lc = (struct load_command *)((uintptr_t)mh + sizeof(struct mach_header));
    
    while (1) {
        if ((uintptr_t)lc->cmd == cmd) {
            flc = (struct load_command *)(uintptr_t)lc;
            break;
        }
        lc = (struct load_command *)((uintptr_t)lc + (uintptr_t)lc->cmdsize);
    }
    return flc;
}

/* Find start of a segment in a macho */
struct segment_command *find_segment(struct mach_header *mh, const char *segname)
{
    struct load_command *lc;
    struct segment_command *s, *fs = NULL;
    lc = (struct load_command *)((uintptr_t)mh + sizeof(struct mach_header));
    while ((uintptr_t)lc < (uintptr_t)mh + (uintptr_t)mh->sizeofcmds) {
        if (lc->cmd == LC_SEGMENT) {
            s = (struct segment_command *)lc;
            if (!strcmp(s->segname, segname)) {
                fs = s;
                break;
            }
        }
        lc = (struct load_command *)((uintptr_t)lc + (uintptr_t)lc->cmdsize);
    }
    return fs;
}

/* Find offset of an exported symbol in a macho */
void* find_sym(struct mach_header *mh, const char *name) {
    struct segment_command* first = (struct segment_command*) find_load_command(mh, LC_SEGMENT);
    struct symtab_command* symtab = (struct symtab_command*) find_load_command(mh, LC_SYMTAB);
    vm_address_t vmaddr_slide = (vm_address_t)mh - (vm_address_t)first->vmaddr;
    
    char* sym_str_table = (char*) (((char*)mh) + symtab->stroff);
    struct nlist* sym_table = (struct nlist*)(((char*)mh) + symtab->symoff);
    
    for (int i = 0; i < symtab->nsyms; i++) {
        if (sym_table[i].n_value && !strcmp(name,&sym_str_table[sym_table[i].n_un.n_strx])) {
            return (void*)(uintptr_t)(sym_table[i].n_value + vmaddr_slide);
        }
    }
    return 0;
}

/* The rest */

/* Find the VM base for prelinked kexts in a kernelcache */
uint32_t find_kextbase(void *kernelcache, size_t size) {
    
    if (!(*(uint32_t*)&kernelcache[0] == 0xFEEDFACE)) {
        PatchLog("This doesn't look like a kernelcache\n");
        return 0;
    }
    
    struct mach_header *mh = kernelcache;
    struct segment_command *sc = (kernelcache+sizeof(struct mach_header));
    
    for (int i = 0; i < mh->ncmds; i++) {
        
        if (!strcmp(sc->segname, "__PRELINK_TEXT")) {
            
            uint32_t ret = (sc->vmaddr - sc->fileoff);
            
            return ret;
        }
        
        uintptr_t next = (uintptr_t)sc->cmdsize+(void*)sc-kernelcache;
        
        if (next+(uintptr_t)kernelcache > mh->sizeofcmds+(uintptr_t)kernelcache) {
            break;
        }
        
        sc=kernelcache+next;
        
    }
    
    return 0;
}

/* Find the beginning of a kext's _TEXT section */
uint32_t find_kext_text_section(void *kernelcache, size_t size, const char *name) {
    
    if (!(*(uint32_t*)&kernelcache[0] == 0xFEEDFACE)) {
        PatchLog("This doesn't look like a kernelcache\n");
        return 0;
    }
    
    struct mach_header *mh = kernelcache;
    
    struct segment_command *sc = (kernelcache+sizeof(struct mach_header));
    
    for (int i = 0; i < mh->ncmds; i++) {
        
        if (!strcmp(sc->segname, "__PRELINK_INFO")) {
            
            uint32_t fileOffToBegin = sc->fileoff;
            uint32_t fileSize = sc->filesize;
            
            if (fileSize > size || (fileSize+fileOffToBegin > size)) {
                PatchLog("Bounds check error\n");
                return 0;
            }
            
            void *prelinkInfo = (void*)(kernelcache+fileOffToBegin);
            
            uint32_t requestedKextStart = 0;
            
            /* XML parsing for dummies. Don't do this, kids */
            for (int c=0; c < fileSize; c++) {
                if (!memcmp(prelinkInfo+c, name, strlen(name))) {
                    for (int d=c; d < fileSize; d++) {
                        if (!memcmp(prelinkInfo+d, "_PrelinkExecutableLoadAddr", strlen("_PrelinkExecutableLoadAddr"))) {
                            for (int e=d; e < (d+0x40); e++) {
                                if (*(uint16_t*)&prelinkInfo[e] == 0x7830) {
                                    char addr[0x10];
                                    bzero(&addr, 0x10);
                                    memcpy(&addr, prelinkInfo+e+2, 0x8);
                                    *(uint8_t*)&addr[0xB-2] = 0x0;
                                    
                                    uint32_t addre = (uint32_t)strtoul(addr, NULL, 16);
                                    
                                    if (!(addre < 0x80000000+fileOffToBegin && addre > 0x80000000)) {
                                        goto done;
                                    }
                                    
                                    requestedKextStart = addre;
                                    
                                    goto done;
                                }
                            }
                        }
                    }
                }
            }
            
        done:;
            
            if(!requestedKextStart) {
                PatchLog("Failed to find beginning of requested kext __text section\n");
                return 0;
            }
            
            return requestedKextStart;
        }
        
        
    nextSC:;
        uintptr_t next = (uintptr_t)sc->cmdsize+(void*)sc-kernelcache;
        
        if (next+(uintptr_t)kernelcache > mh->sizeofcmds+(uintptr_t)kernelcache) {
            break;
        }
        
        sc=kernelcache+next;
        
    }
    
    return 0;
}

/*
 * Patch an armv7/armv7s kernelcache for use in a jailbreak.
 * buf should be a buffer containing a kernelcache macho, len
 * should be the size of the macho, version should be a c-string
 * containing the iOS version number (such as "9.3.3").
 *
 * Note: You must disable KASLR to use the sbops patch.
 */
int kernPat9(void *buf, size_t len, char *version) {
    
    int i = 0;
    int ii = 0;
    
    float versionFloat = strtof(version, 0);
    
    while ((uint32_t)i < (uint32_t)(len-0x8000)) {
        
        if (ii == 0) {
            
            if (versionFloat == (float)9.3) {
                if (*(uint64_t*)&buf[i] == 0x2501d1030f01f01b && *(uint32_t*)&buf[i+0x8] == 0x2501e016) {
                    
                    PatchLog("Found mount_common at 0x%x\n", i + 0x5);
                    
                    //change conditional branch to unconditional
                    *(uint8_t*)&buf[i+0x5] = 0xe0;
                    
                    ii++;
                    i = 0;
                }
                
                /* Since our expected offset is always on a multiple of 2, add 1 to the cursor to save cycles */
                else {
                    i+=1;
                }
            }
            else if (versionFloat == (float)9.0) {
                if ((*(uint64_t*)&buf[i] & 0x00ffffffffffffff) == 0xd4d0060f01f010) {
                    
                    PatchLog("Found mount_common at 0x%x\n", i + 0x5);
                    
                    //change conditional branch to unconditional
                    *(uint8_t*)&buf[i+0x5] = 0xe0;
                    
                    ii++;
                    i = 0;
                }
                
                /* Since our expected offset is always on a multiple of 2, add 1 to the cursor to save cycles */
                else {
                    i+=1;
                }
            }
            else {
                if (*(uint32_t*)&buf[i] == 0x0f01f010 && *(uint8_t*)&buf[i+0x5] == 0xd0 && *(uint32_t*)&buf[i+0xe] == 0x0f40f010 && *(uint8_t*)&buf[i+0x13] == 0xd0) {
                    
                    PatchLog("Found mount_common at 0x%x\n", i + 0x5);
                    
                    //change conditional branch to unconditional
                    *(uint8_t*)&buf[i+0x5] = 0xe0;
                    
                    ii++;
                    i = 0;
                }
                
                /* Since our expected offset is always on a multiple of 2, add 1 to the cursor to save cycles */
                else {
                    i+=1;
                }
            }
            
        }
        
        if (ii == 1) {
            
            /*
             * _mapForIO / 9.3.5/j2
             * A0 6D  LDR R0, [R4,#0x58]
             * 40 44  ADD R0, R8
             * Offset: 0xbb0726
             * Address: 0x80bfa726
             *
             * Change the lwvm kext's xref to PE_i_can_has_kernel_configuration to _mapForIO
             */
            
            /* This is only enforced on the first LwVM device before 9.3.2. Since we use the third device, skip */
            if (versionFloat < (float)9.3 || !strcmp(version, "9.3.1") || !strcmp(version, "9.3")) {
                ii++;
                i = 0;
                continue;
            }
            
            i = (uint32_t)find_sym(buf, "_PE_i_can_has_kernel_configuration")-(uint32_t)buf;
            
            if (!i) {
                break;
            }
            
            PatchLog("Found PE_i_can_has_kernel_configuration offset at 0x%x\n", i);
            
            uint32_t PE_i_can_has_kernel_configuration = (i + 0x80001000 + 0x1);
            
            i = 0;
            
            int iii = 0;
            
            uint32_t osMallocTagFree = 0;
            
            uint32_t mapforIO = 0;
            
            for (uint32_t a=0; (uint32_t)a < (uint32_t)(len-0x8000); a++) {
                if (!iii) {
                    
                    a = (uint32_t)find_sym(buf, "_OSMalloc_Tagfree")-(int)buf;
                    
                    if (!a) {
                        break;
                    }
                    
                    PatchLog("Found OSMalloc_Tagfree at 0x%x\n", a);
                    
                    osMallocTagFree = (a + 0x80001000 + 0x1);
                    
                    a = 0;
                    iii++;
                    
                }
                if (iii == 1) {
                    if (*(uint64_t*)&buf[a] == 0xf010798044406da0 && *(uint32_t*)&buf[a+0x8] == 0xd0060f01 && *(uint16_t*)&buf[a+0xC] == 0x4620) {
                        PatchLog("Found _mapForIO at 0x%x\n", a);
                        mapforIO = ((a + 0x80001000) + 0x1);
                        iii++;
                        a = 0;
                    }
                }
                if (iii == 2) {
                    if (*(uint32_t*)&buf[a] == osMallocTagFree) {
                        if (*(uint32_t*)&buf[a+0x4] == PE_i_can_has_kernel_configuration) {
                            PatchLog("Found LwVM call to PE_i_can_has_kernel_configuration at 0x%x\n", a + 0x4);
                            *(uint32_t*)&buf[a+0x4] = mapforIO;
                            iii++;
                            a = 0;
                        }
                    }
                }
                
                if (iii == 3) {
                    break;
                }
                
            }
            
            if (iii != 3) {
                PatchLog("One or more patches not found %d at line %d\n", iii, __LINE__);
                return -1;
            }
            
            ii++;
            i = 0;
            
        }
        
        if (ii == 2) {
            i = (uint32_t)find_sym(buf, "_PE_i_can_has_debugger")-(uint32_t)buf;
            
            if (!i) {
                break;
            }
            
            PatchLog("Found PE_i_can_has_debugger offset at 0x%x\n", i);
            
            for (i=i; i < (i+0x100); i+=0x2) {
                if (*(uint16_t*)(buf+i) == 0x4770) {
                    
                    PatchLog("Found BX LR at 0x%x\n", i);
                    
                    *(uint32_t*)&buf[i-0x4] = 0x20012001;
                    
                    ii++;
                    i=0;
                    break;
                }
            }
        }
        
        if (ii == 3) {
            
            if (*(uint16_t*)&buf[i] == 0x4630 && *(uint64_t*)&buf[i+6] == 0xf0000f00f1ba4682 && *(uint32_t*)&buf[i+0x10] == 0xf0014650) {
                PatchLog("Found tfp0 at 0x%x\n", i);
                
                for (int a=i; a > (i-0x30); a-=2) {
                    if (*(uint16_t*)&buf[a] == 0xb5f0) {
                        PatchLog("Found tfp0 PUSH at 0x%x\n", a);
                        
                        for (int e=a; e < (a+0x20); e+=2) {
                            if (*(uint16_t*)&buf[e] == 0x2e00) {
                                PatchLog("Found tfp0 CMP R6, #0 at 0x%x\n", e);
                                *(uint32_t*)&buf[e+0x2] = 0xbf00bf00;
                                goto tfpout;
                            }
                        }
                    }
                    
                    continue;
                    
                tfpout:
                    ii++;
                    i=0;
                    break;
                }
            }
            
        }
        
        if (ii == 4) {
            
            /*
             * amfi's call to memcmp is being replaced with a jump to a MOV R0, #0 then BX LR.
             * This makes any memcmp performed by amfi return 0 (match).
             */
            
            uint32_t memcmpAddress = 0;
            
            i = (uint32_t)find_sym(buf, "_memcmp")-(uint32_t)buf;
            
            if (!i) {
                break;
            }
            
            PatchLog("Found memcmp at 0x%x\n", i);
            
            memcmpAddress = (i+(0x80001000+1));
            
            uint32_t mach_msg_rpc_from_kernel_proper = 0;
            
            i = 0;
            int iii = 0;
            
            uint32_t bxlrGadget = 0;
            
            mach_msg_rpc_from_kernel_proper = (uint32_t)find_sym(buf, "_mach_msg_rpc_from_kernel_proper")-(uint32_t)buf+0x1;
            
            if (!mach_msg_rpc_from_kernel_proper) {
                break;
            }
            
            while ((uint32_t)i < (uint32_t)(len-0x8000)) {
                if (iii == 0) {
                    if (*(uint32_t*)&buf[i] == 0x47702000) {
                        
                        PatchLog("Found MOV R0, #0 gadget at 0x%x\n", i);
                        
                        bxlrGadget = ((i + 0x80001000) + 0x1);
                        
                        iii++;
                        i = 0;
                    }
                }
                if (iii == 1) {
                    if (*(uint32_t*)&buf[i] == (uint32_t)mach_msg_rpc_from_kernel_proper+(0x80001000)) {
                        if (*(uint32_t*)&buf[i+4] == memcmpAddress) {
                            PatchLog("Found AMFI call to memcmp at 0x%x\n", i + 0x4);
                            *(uint32_t*)&buf[i+0x4] = bxlrGadget;
                            iii++;
                            i = 0;
                        }
                    }
                }
                
                if (iii == 2) {
                    break;
                }
                
                i++;
            }
            
            if (iii != 2) {
                PatchLog("One or more patches not found %d at line %d\n", iii, __LINE__);
                return -1;
            }
            
            ii++;
            i = 0;
        }
        
        if (ii == 5) {
            
            uint32_t seatbeltSandboxPolicyStr = 0;
            
            uint32_t sbops = 0;
            
            if (!memcmp(buf + i, "Seatbelt sandbox policy", strlen("Seatbelt sandbox policy"))) {
                seatbeltSandboxPolicyStr = i;
            }
            else {
                i++;
                continue;
            }
            
            if (seatbeltSandboxPolicyStr) {
                
                uint32_t kextbase = find_kextbase(buf, len)-0x80001000;
                
                if (!kextbase) {
                    PatchLog("Error finding kextbase\n");
                    break;
                }
                
                uint32_t strRef = (seatbeltSandboxPolicyStr + 0x80001000 + kextbase);
                
                PatchLog("Found seatbelt sandbox policy at 0x%x\n", i);
                
                uint32_t strXref = 0;
                
                for (int af=0; af < (len-0x10000); af+=1) {
                    if (*(uint32_t*)&buf[af] == strRef) {
                        strXref = af;
                        break;
                    }
                }
                
                if (!strXref) {
                    break;
                }
                
                for (uint32_t cur=seatbeltSandboxPolicyStr; cur > seatbeltSandboxPolicyStr-0x10000; cur--) {
                    
                    if (*(uint32_t*)&buf[cur] == 0xFEEDFACE) {
                        
                        PatchLog("Found mach-o header at 0x%x\n", cur);
                        
                        uint32_t off = 0x0;
                        
                        for (uint32_t cur1=strXref; cur1 < (strXref+0x10); cur1+=0x1) {
                            if (*(uint32_t*)&buf[cur1] == 0x1) {
                                off = cur1+0x4;
                                break;
                            }
                        }
                        
                        if (!off) {
                            return -1;
                        }
                        
                        uint32_t sbops_offset = *(uint32_t*)&buf[off];
                        
                        sbops_offset = (sbops_offset-(kextbase-0x80001000))-0x2000;
                        
                        PatchLog("Found sbops at 0x%x\n", sbops_offset);
                        
                        sbops = sbops_offset;
                    }
                }
                
                if (!sbops) {
                    break;
                }
                
                /* 9.2.1+ use mac_policy_ops v46, older 9.x use v37 (xnu/security/mac_policy.h) */
                if (versionFloat >= (float)9.2 && strcmp(version, "9.2")) {
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops9, mpo_file_check_mmap)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_check_rename)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_check_rename)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_check_access)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_check_chroot)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_check_create)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_check_deleteextattr)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_check_exchangedata)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_check_exec)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_check_getattrlist)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_check_getextattr)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_check_ioctl)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_check_link)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_check_listextattr)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_check_open)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_check_readlink)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_check_setattrlist)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_check_setextattr)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_check_setflags)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_check_setmode)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_check_setowner)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_check_setutimes)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_check_setutimes)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_check_stat)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_check_truncate)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_check_unlink)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_notify_create)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_check_fsgetpath)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_check_getattr)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops9, mpo_mount_check_stat)), 0x4);
                }
                else {
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops90, mpo_file_check_mmap)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops90, mpo_vnode_check_rename)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops90, mpo_vnode_check_rename)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops90, mpo_vnode_check_access)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops90, mpo_vnode_check_chroot)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops90, mpo_vnode_check_create)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops90, mpo_vnode_check_deleteextattr)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops90, mpo_vnode_check_exchangedata)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops90, mpo_vnode_check_exec)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops90, mpo_vnode_check_getattrlist)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops90, mpo_vnode_check_getextattr)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops90, mpo_vnode_check_ioctl)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops90, mpo_vnode_check_link)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops90, mpo_vnode_check_listextattr)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops90, mpo_vnode_check_open)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops90, mpo_vnode_check_readlink)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops90, mpo_vnode_check_setattrlist)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops90, mpo_vnode_check_setextattr)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops90, mpo_vnode_check_setflags)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops90, mpo_vnode_check_setmode)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops90, mpo_vnode_check_setowner)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops90, mpo_vnode_check_setutimes)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops90, mpo_vnode_check_setutimes)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops90, mpo_vnode_check_stat)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops90, mpo_vnode_check_truncate)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops90, mpo_vnode_check_unlink)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops90, mpo_vnode_notify_create)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops90, mpo_vnode_check_fsgetpath)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops90, mpo_mount_check_stat)), 0x4);
                }
                
                ii++;
                i=0;
            }
        }
        
        if (ii == 6) {
            
            /*
             * Substrate on iOS 8 and higher requires just
             * adding the CS_INSTALLER entitlement to every
             * process.
             *
             * Example disassembly from iOS 9.3.5/n49:
             *
             * 00 28       CMP             R0, #0
             * 1E BF       ITTT NE
             * DA F8 00 00 LDRNE.W         R0, [R10]
             * 40 F0 04 00 ORRNE.W         R0, R0, #4 <--- CS_GET_TASK_ALLOW
             * CA F8 00 00 STRNE.W         R0, [R10]
             * 17 F8 22 0C LDRB.W          R0, [R7,#var_22]
             * 00 28       CMP             R0, #0
             * 1E BF       ITTT NE
             * DA F8 00 00 LDRNE.W         R0, [R10]
             * 40 F0 08 00 ORRNE.W         R0, R0, #8 <--- CS_INSTALLER
             *
             * NOP the two ITTT NE instructions
             * (0xBF1E -> 0xBF00)
             *
             */
            
            if (*(uint64_t*)&buf[i] == 0x0000f8dabf1e2800 && *(uint32_t*)&buf[i+0x8] == 0x0004f040) {
                
                PatchLog("Found substrate patch offset at 0x%x\n", i);
                
                /* CS_GET_TASK_ALLOW */
                *(uint16_t*)&buf[i+0x2] = 0xbf00;
                
                /* CS_INSTALLER */
                *(uint16_t*)&buf[i+0x16] = 0xbf00;
                
                ii++;
                i=0;
            }
            
        }
        
        if (ii == 7) {
            break;
        }
        
        i++;
    }
    
    if (ii != 7) {
        PatchLog("One or more patches not found %d at line %d\n", ii, __LINE__);
        return -1;
    }
    
    return 0;
}

/*
 * Patch an armv7s kernelcache for use in a jailbreak.
 * buf should be a buffer containing a kernelcache macho, len
 * should be the size of the macho, version should be a c-string
 * containing the iOS version number (such as "10.3.3").
 *
 * Note: You must disable KASLR to use the sbops patch.
 */
int kernPat10(void *buf, size_t len, char *version) {
    
    uint32_t* fullSize = (uint32_t*)len;
    int i = 0;
    int ii = 0;
    
    float versionFloat = strtof(version, 0);
    
    while ((uint32_t)i < (uint32_t)(fullSize-0x8000)) {
        
        if (ii == 0) {
            
            if (versionFloat < (float)10.3) {
                
                if (*(uint64_t*)&buf[i] == 0xf04fd1040f01f01b && *(uint32_t*)&buf[i+8] == 0x9d080801) {
                    
                    PatchLog("Found mount_common at 0x%x\n", i + 0x5);
                    
                    *(uint8_t*)&buf[(i+0x5)] = 0xe0;
                    
                    ii++;
                    
                    i = 0;
                }
            }
            else {
                if (*(uint32_t*)&buf[i] == 0x0f01f01a && *(uint16_t*)&buf[i+4] == 0xd13b) {
                    
                    PatchLog("Found mount_common at 0x%x\n", i + 0x5);
                    
                    *(uint8_t*)&buf[(i+0x5)] = 0xe0;
                    
                    ii++;
                    
                    i = 0;
                }
            }
        }
        if (ii == 1) {
            
            /*
             * _mapForIO / 9.3.5/j2
             * A0 6D  LDR R0, [R4,#0x58]
             * 40 44  ADD R0, R8
             * Offset: 0xbb0726
             * Address: 0x80bfa726
             *
             * Change the lwvm kext's xref to PE_i_can_has_kernel_configuration to _mapForIO
             */
            
            i = (uint32_t)find_sym(buf, "_PE_i_can_has_kernel_configuration")-(uint32_t)buf;
            
            if (!i) {
                break;
            }
            
            PatchLog("Found PE_i_can_has_kernel_configuration offset at 0x%x\n", i);
            
            uint32_t PE_i_can_has_kernel_configuration = (i + 0x80001000 + 0x1);
            
            i = 0;
            
            int iii = 0;
            
            uint32_t osMallocTagFree = 0;
            
            uint32_t mapforIO = 0;
            
            for (uint32_t a=0; (uint32_t)a < (uint32_t)(len-0x8000); a++) {
                if (!iii) {
                    
                    a = (uint32_t)find_sym(buf, "_OSMalloc_Tagfree")-(int)buf;
                    
                    if (!a) {
                        break;
                    }
                    
                    PatchLog("Found OSMalloc_Tagfree at 0x%x\n", a);
                    
                    osMallocTagFree = (a + 0x80001000 + 0x1);
                    
                    a = 0;
                    iii++;
                    
                }
                if (iii == 1) {
                    if (*(uint64_t*)&buf[a] == 0xf010798044406da8 && *(uint16_t*)&buf[a+0x8] == 0x0f01) {
                        PatchLog("Found _mapForIO at 0x%x\n", a);
                        mapforIO = ((a + 0x80001000) + 0x1);
                        iii++;
                        a = 0;
                    }
                }
                if (iii == 2) {
                    if (*(uint32_t*)&buf[a] == osMallocTagFree) {
                        if (*(uint32_t*)&buf[a+0x4] == PE_i_can_has_kernel_configuration) {
                            PatchLog("Found LwVM call to PE_i_can_has_kernel_configuration at 0x%x\n", a + 0x4);
                            *(uint32_t*)&buf[a+0x4] = mapforIO;
                            iii++;
                            a = 0;
                        }
                    }
                }
                
                if (iii == 3) {
                    break;
                }
                
            }
            
            if (iii != 3) {
                PatchLog("One or more patches not found %d at line %d\n", iii, __LINE__);
                return -1;
            }
            
            ii++;
            i = 0;
        }
        
        if (ii == 2) {
            
            i = (uint32_t)find_sym(buf, "_PE_i_can_has_debugger")-(uint32_t)buf;
            
            if (!i) {
                break;
            }
            
            PatchLog("Found PE_i_can_has_debugger offset at 0x%x\n", i);
            
            for (i=i; i < (i+0x100); i+=0x2) {
                if (*(uint16_t*)(buf+i) == 0x4770) {
                    PatchLog("Found BX LR at 0x%x\n", i);
                    *(uint32_t*)&buf[i-0x4] = 0x20012001;
                    ii++;
                    i=0;
                    break;
                }
            }
        }
        
        if (ii == 3) {
            if (versionFloat < (float)10.3) {
                ii++;
                i=0;
            }
            else {
                if (*(uint64_t*)&buf[i] == 0x0108f04043080102) {
                    i+=0x4;
                    PatchLog("Found nosuid enforcement at 0x%x\n", i);
                    *(uint8_t*)&buf[i+0x2] = 0x0;
                    ii++;
                    i=0;
                }
            }
        }
        
        if (ii == 4) {
            if (*(uint64_t*)&buf[i] == 0xd04d2e001101e9cd && *(uint32_t*)&buf[i+0xC] == 0x28009002) {
                PatchLog("Found task for pid at 0x%x\n", i);
                *(uint16_t*)&buf[i+0x6] = 0xbf00;
                ii++;
                i = 0;
            }
        }
        
        if (ii == 5) {
            
            /*
             * amfi's call to memcmp is being replaced with a jump to a MOV R0, #0 then BX LR.
             * This makes any memcmp performed by amfi return 0 (match).
             */
            
            uint32_t memcmpAddress = 0;
            
            i = (uint32_t)find_sym(buf, "_memcmp")-(uint32_t)buf;
            
            if (!i) {
                break;
            }
            
            PatchLog("Found memcmp at 0x%x\n", i);
            
            memcmpAddress = (i+(0x80001000+1));
            
            uint32_t mach_msg_rpc_from_kernel_proper = 0;
            
            i = 0;
            int iii = 0;
            
            uint32_t bxlrGadget = 0;
            
            mach_msg_rpc_from_kernel_proper = (uint32_t)find_sym(buf, "_mach_msg_rpc_from_kernel_proper")-(uint32_t)buf+0x1;
            
            if (!mach_msg_rpc_from_kernel_proper) {
                break;
            }
            
            while ((uint32_t)i < (uint32_t)(len-0x8000)) {
                if (iii == 0) {
                    if (*(uint32_t*)&buf[i] == 0x47702000) {
                        PatchLog("Found MOV R0, #0 gadget at 0x%x\n", i);
                        bxlrGadget = ((i + 0x80001000) + 0x1);
                        iii++;
                        i = 0;
                    }
                }
                if (iii == 1) {
                    if (*(uint32_t*)&buf[i] == (uint32_t)mach_msg_rpc_from_kernel_proper+(0x80001000)) {
                        if (*(uint32_t*)&buf[i+4] == memcmpAddress) {
                            PatchLog("Found AMFI call to memcmp at 0x%x\n", i + 0x4);
                            *(uint32_t*)&buf[i+0x4] = bxlrGadget;
                            iii++;
                            i = 0;
                        }
                    }
                }
                
                if (iii == 2) {
                    break;
                }
                
                i++;
            }
            
            if (iii != 2) {
                PatchLog("One or more patches not found %d at line %d\n", iii, __LINE__);
                return -1;
            }
            
            ii++;
            i = 0;
        }
        
        if (ii == 6) {
            uint32_t seatbeltSandboxPolicyStr = 0;
            
            uint32_t sbops = 0;
            
            if (!memcmp(buf + i, "Seatbelt sandbox policy", strlen("Seatbelt sandbox policy"))) {
                seatbeltSandboxPolicyStr = i;
            }
            else {
                i++;
                continue;
            }
            
            if (seatbeltSandboxPolicyStr) {
                
                uint32_t kextbase = find_kextbase(buf, len)-0x80001000;
                
                if (!kextbase) {
                    PatchLog("Error finding kextbase\n");
                    break;
                }
                
                uint32_t strRef = (seatbeltSandboxPolicyStr + 0x80001000 + kextbase);
                
                PatchLog("Found seatbelt sandbox policy at 0x%x\n", i);
                
                uint32_t strXref = 0;
                
                for (int af=0; af < (len-0x10000); af+=1) {
                    if (*(uint32_t*)&buf[af] == strRef) {
                        strXref = af;
                        break;
                    }
                }
                
                if (!strXref) {
                    break;
                }
                
                uint32_t off = 0x0;
                
                for (uint32_t cur1=strXref; cur1 < (strXref+0x10); cur1+=0x1) {
                    if (*(uint32_t*)&buf[cur1] == 0x1) {
                        off = cur1+0x4;
                        break;
                    }
                }
                
                if (!off) {
                    return -1;
                }
                
                uint32_t sbops_offset = *(uint32_t*)&buf[off];
                
                sbops_offset = (sbops_offset-(kextbase-0x80001000))-0x2000;
                
                PatchLog("Found sbops at 0x%x\n", sbops_offset);
                
                sbops = sbops_offset;
                
                if (!sbops) {
                    break;
                }
                
                if (versionFloat == (float)10.0) {
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops100, mpo_file_check_mmap)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops100, mpo_vnode_check_rename)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops100, mpo_vnode_check_rename)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops100, mpo_vnode_check_access)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops100, mpo_vnode_check_chroot)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops100, mpo_vnode_check_create)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops100, mpo_vnode_check_deleteextattr)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops100, mpo_vnode_check_exchangedata)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops100, mpo_vnode_check_exec)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops100, mpo_vnode_check_getattrlist)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops100, mpo_vnode_check_getextattr)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops100, mpo_vnode_check_ioctl)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops100, mpo_vnode_check_link)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops100, mpo_vnode_check_listextattr)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops100, mpo_vnode_check_open)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops100, mpo_vnode_check_readlink)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops100, mpo_vnode_check_setattrlist)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops100, mpo_vnode_check_setextattr)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops100, mpo_vnode_check_setflags)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops100, mpo_vnode_check_setmode)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops100, mpo_vnode_check_setowner)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops100, mpo_vnode_check_setutimes)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops100, mpo_vnode_check_setutimes)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops100, mpo_vnode_check_stat)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops100, mpo_vnode_check_truncate)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops100, mpo_vnode_check_unlink)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops100, mpo_vnode_notify_create)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops100, mpo_vnode_check_fsgetpath)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops100, mpo_mount_check_stat)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops100, mpo_proc_check_setauid)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops100, mpo_proc_check_getauid)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops100, mpo_proc_check_fork)), 0x4);
                }
                
                else if (versionFloat < (float)10.3 && versionFloat > (float)10.0) {
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops101, mpo_file_check_mmap)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_check_rename)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_check_rename)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_check_access)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_check_chroot)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_check_create)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_check_deleteextattr)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_check_exchangedata)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_check_exec)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_check_getattrlist)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_check_getextattr)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_check_ioctl)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_check_link)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_check_listextattr)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_check_open)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_check_readlink)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_check_setattrlist)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_check_setextattr)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_check_setflags)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_check_setmode)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_check_setowner)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_check_setutimes)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_check_setutimes)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_check_stat)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_check_truncate)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_check_unlink)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_notify_create)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_check_fsgetpath)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_check_getattr)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops101, mpo_mount_check_stat)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops101, mpo_proc_check_setauid)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops101, mpo_proc_check_getauid)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops101, mpo_proc_check_fork)), 0x4);
                }
                else {
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops103, mpo_file_check_mmap)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_rename)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_rename)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_access)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_chroot)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_create)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_deleteextattr)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_exchangedata)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_exec)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_getattrlist)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_getextattr)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_ioctl)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_link)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_listextattr)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_open)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_readlink)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_setattrlist)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_setextattr)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_setflags)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_setmode)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_setowner)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_setutimes)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_setutimes)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_stat)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_truncate)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_unlink)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_notify_create)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_fsgetpath)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_getattr)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops103, mpo_mount_check_stat)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops103, mpo_proc_check_setauid)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops103, mpo_proc_check_getauid)), 0x4);
                    bzero(buf+(sbops+offsetof(struct mac_policy_ops103, mpo_proc_check_fork)), 0x4);
                    
                    uint32_t res = *(uint32_t*)(buf+sbops+offsetof(struct mac_policy_ops103, mpo_cred_label_update_execve))-kextbase-0x80001000-1;
                    
                    int found1 = 0;
                    
                    for (uint32_t i = res; i < (uint32_t)(res+0x20000); i+=2) {
                        if (*(uint32_t*)&buf[i] == 0x4019e9cd) {
                            PatchLog("Found STRD.W R4, R0, [SP, #0x64] at 0x%x\n", i);
                            for (uint32_t a=i; a < (i+0x18); a+=2) {
                                if (*(uint16_t*)&buf[a] == 0xf000) {
                                    PatchLog("Found BEQ.W at 0x%x\n", a);
                                    
                                    *(uint32_t*)&buf[a] = 0xbf00bf00;
                                    
                                    found1 = 1;
                                    break;
                                }
                            }
                            break;
                        }
                    }
                    
                    if (!found1) {
                        break;
                    }
                    
                }
                
                ii++;
                i=0;
            }
        }
        
        if (ii == 7) {
            
            /*
             * Substrate on iOS 8 and higher requires just
             * adding the CS_INSTALLER entitlement to every
             * process, so our patch is to initialize CS_FLAGS
             * with CS_INSTALLER flags, rather than
             * initializing as NULL
             *
             * Example disassembly from iOS 10.2.1/n49:
             *
             * 00 68       LDR             R0, [R0]
             * 00 90       STR             R0, [SP,#0x30+var_30]
             * 00 26       MOVS            R6, #0
             *
             * R6 is CS_FLAGS
             * MOVS R6, #0 -> MOVS R6, #4
             * (0x2600 -> 0x2604)
             *
             */
            
            uint32_t startOff = 0;
            
            uint32_t kextbase = find_kextbase(buf, len);
            
            startOff = find_kext_text_section(buf, len, "AppleMobileFileIntegrity")-kextbase;
            
            if (!startOff) {
                PatchLog("ERR (startOff == 0x0)\n");
                break;
            }
            
            for (int e = startOff; e < (len-0x100); e+=2) {
                if (versionFloat < (float)10.3) {
                    if (*(uint64_t*)&buf[e] == 0xe036260090006800) {
                        PatchLog("Found substrate patch offset at 0x%x\n", e);
                        *(uint8_t*)&buf[(e+0x4)] = 0x4;
                        ii++;
                        i=0;
                        break;
                    }
                }
                else {
                    if (*(uint64_t*)&buf[e] == 0xe03a260090004478) {
                        PatchLog("Found substrate patch offset at 0x%x\n", e);
                        *(uint8_t*)&buf[(e+0x4)] = 0x4;
                        ii++;
                        i=0;
                        break;
                    }
                }
                
                
            }
        }
        
        if (ii == 8) {
            
            /* This patch is required because loading substrate on-boot would break here */
            
            uint32_t startOff = 0;
            uint32_t kextbase = find_kextbase(buf, len);
            
            startOff = find_kext_text_section(buf, len, "AppleHDQGasGaugeControl")-kextbase;
            
            if (!startOff) {
                PatchLog("ERR (startOff == 0x0)\n");
                break;
            }
            
            for (int g=startOff; g < (len-0x1000); g+=2) {
                if (versionFloat < (float)10.3) {
                    if (*(uint32_t*)&buf[g] == 0x47884630 && *(uint16_t*)&buf[g+4] == 0x455e) {
                        
                        int found = 0;
                        
                        for (int e=g; e < (g+0x100); e+=2) {
                            if (*(uint16_t*)&buf[e] == 0x21ff) {
                                PatchLog("Found gasgauge entitlement check 0x%x\n", e);
                                e-=4;
                                *(uint32_t*)&buf[e] = 0xbf00e014;
                                found = 1;
                                break;
                            }
                        }
                        
                        if (found) {
                            ii++;
                            i=0;
                        }
                    }
                }
                else {
                    
                    if (*(uint32_t*)&(buf+g)[0] == 0x47884630 && *(uint16_t*)&(buf+g+4)[0] == 0x42ae) {
                        
                        int found = 0;
                        
                        for (int e=g; e < (g+0x100); e+=2) {
                            if (*(uint16_t*)&buf[e] == 0x21ff) {
                                PatchLog("Found gasgauge entitlement check 0x%x\n", e);
                                e-=4;
                                *(uint32_t*)&buf[e] = 0xbf00e014;
                                found = 1;
                                break;
                            }
                        }
                        
                        if (found) {
                            ii++;
                            i=0;
                        }
                    }
                }
            }
            
            if (ii == 9) {
                break;
            }
        }
        
        if (ii == 9) {
            break;
        }
        
        i++;
    }
    
    if (ii != 9) {
        PatchLog("One or more patches not found %d at line %d\n", ii, __LINE__);
        return -1;
    }
    
    return 0;
}

int kernPat(void **buf, size_t size, char *versionNumber) {
    
    long versionInt = strtol(versionNumber, 0, 0);
    
    if (*(uint32_t*)&buf[0] != 0xFEEDFACE) {
        PatchLog("Not a kernelcache\n");
        return -1;
    }
    
    int ret = 0;
    
    switch (versionInt) {
            
        case 10:
            ret = kernPat10(buf, size, versionNumber);
            break;
      
        case 9:
            ret = kernPat9(buf, size, versionNumber);
            break;
            
        /* more soon */
            
        default:
            printf("This version of CBPatcher does not support iOS %ld kernels\n", versionInt);
            return -1;
    }
    
    return ret;
}
