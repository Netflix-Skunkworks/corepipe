// SPDX-License-Identifier: BSD-3-Clause

/* Copyright (c) 2005-2008, Google Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * ---
 * Author: Markus Gutschke, Carl Crous
 */

/*
 * Structs coming across from google-coredumper project.
 *
 * There is no formal documentation for the core file data structure, it is
 * only verifiable by comparing to output from gdb.
 *
 * https://github.com/madscientist/google-coredumper/tree/master/src
 * https://github.com/madscientist/google-coredumper/blob/master/src/elfcore.c
 */


typedef struct elf_siginfo {    /* Information about signal (unused)         */                                                                                                            
  int32_t si_signo;             /* Signal number                             */
  int32_t si_code;              /* Extra code                                */
  int32_t si_errno;             /* Errno                                     */
} elf_siginfo;

typedef struct elf_timeval {    /* Time value with microsecond resolution    */
  long tv_sec;                  /* Seconds                                   */
  long tv_usec;                 /* Microseconds                              */
} elf_timeval;

typedef struct prpsinfo {       /* Information about process                 */
  unsigned char  pr_state;      /* Numeric process state                     */
  char           pr_sname;      /* Char for pr_state                         */
  unsigned char  pr_zomb;       /* Zombie                                    */
  signed char    pr_nice;       /* Nice val                                  */
  unsigned long  pr_flag;       /* Flags                                     */
  uint32_t       pr_uid;        /* User ID                                   */
  uint32_t       pr_gid;        /* Group ID                                  */
  pid_t          pr_pid;        /* Process ID                                */
  pid_t          pr_ppid;       /* Parent's process ID                       */
  pid_t          pr_pgrp;       /* Group ID                                  */
  pid_t          pr_sid;        /* Session ID                                */
  char           pr_fname[16];  /* Filename of executable                    */
  char           pr_psargs[80]; /* Initial part of arg list                  */
} prpsinfo;

typedef struct i386_regs {    /* Normal (non-FPU) CPU registers            */
  #define BP rbp
  #define SP rsp
  #define IP rip
  uint64_t  r15,r14,r13,r12,rbp,rbx,r11,r10;
  uint64_t  r9,r8,rax,rcx,rdx,rsi,rdi,orig_rax;
  uint64_t  rip,cs,eflags;
  uint64_t  rsp,ss;
  uint64_t  fs_base, gs_base;
  uint64_t  ds,es,fs,gs;
} i386_regs;

#define regs i386_regs

typedef struct prstatus {       /* Information about thread; includes CPU reg*/
  elf_siginfo    pr_info;       /* Info associated with signal               */
  uint32_t       pr_cursig;     /* Current signal                            */
  unsigned long  pr_sigpend;    /* Set of pending signals                    */
  unsigned long  pr_sighold;    /* Set of held signals                       */
  pid_t          pr_pid;        /* Process ID                                */
  pid_t          pr_ppid;       /* Parent's process ID                       */
  pid_t          pr_pgrp;       /* Group ID                                  */
  pid_t          pr_sid;        /* Session ID                                */
  elf_timeval    pr_utime;      /* User time                                 */
  elf_timeval    pr_stime;      /* System time                               */
  elf_timeval    pr_cutime;     /* Cumulative user time                      */
  elf_timeval    pr_cstime;     /* Cumulative system time                    */
  regs           pr_reg;        /* CPU registers                             */
  uint32_t       pr_fpvalid;    /* True if math co-processor being used      */
} prstatus;

typedef struct fpregs {     /* FPU registers                             */
    uint16_t  cwd;
    uint16_t  swd;
    uint16_t  twd;
    uint16_t  fop;
    uint32_t  fip;
    uint32_t  fcs;
    uint32_t  foo;
    uint32_t  fos;
    uint32_t  mxcsr;
    uint32_t  mxcsr_mask;
    uint32_t  st_space[32];     /*  8*16 bytes for each FP-reg  = 128 bytes  */
    uint32_t  xmm_space[64];    /* 16*16 bytes for each XMM-reg = 128 bytes  */
    uint32_t  padding[24];
} fpregs;
