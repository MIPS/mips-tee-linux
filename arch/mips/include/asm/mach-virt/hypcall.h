/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * (C) 2016 Kernkonzept GmbH, Adam Lackorzynski <adam@l4re.org>
 */
#pragma once

enum {
	L4VMM_FUNC_BASE      = 0x160,
	L4VMM_FUNC_PRINTCHAR = L4VMM_FUNC_BASE + 0,
};

static inline unsigned long
l4vmm_hypcall1(unsigned func, unsigned long a0)
{
	register unsigned long _a0 asm ("a0") = a0;
	asm volatile(".set push; .set virt; hypcall %[func]; .set pop"
	             : "=r" (_a0)
	             : [func] "K" (func),
	               "0" (_a0)
	             : "cc", "memory");
	return _a0;
}

static inline unsigned long
l4vmm_hypcall2(unsigned func, unsigned long a0, unsigned long a1)
{
	register unsigned long _a0 asm ("a0") = a0;
	register unsigned long _a1 asm ("a1") = a1;
	asm volatile(".set push; .set virt; hypcall %[func]; .set pop"
	             : "=r" (_a0),
	               "=r" (_a1)
	             : [func] "K" (func),
	               "0" (_a0),
	               "1" (_a1)
	             : "cc", "memory");
	return _a0;
}

static inline unsigned long
l4vmm_hypcall2_ret(unsigned func, unsigned long a0, unsigned long *a1)
{
	register unsigned long _a0 asm ("a0") = a0;
	register unsigned long _a1 asm ("a1") = *a1;
	asm volatile(".set push; .set virt; hypcall %[func]; .set pop"
	             : "=r" (_a0),
	               "=r" (_a1)
	             : [func] "K" (func),
	               "0" (_a0),
	               "1" (_a1)
	             : "cc", "memory");
	*a1 = _a1;
	return _a0;
}

static inline unsigned long
l4vmm_hypcall3(unsigned func, unsigned long a0, unsigned long a1,
                              unsigned long a2)
{
	register unsigned long _a0 asm ("a0") = a0;
	register unsigned long _a1 asm ("a1") = a1;
	register unsigned long _a2 asm ("a2") = a2;
	asm volatile(".set push; .set virt; hypcall %[func]; .set pop"
	             : "=r" (_a0),
	               "=r" (_a1),
	               "=r" (_a2)
	             : [func] "K" (func),
	               "0" (_a0),
	               "1" (_a1),
	               "2" (_a2)
	             : "cc", "memory");
	return _a0;
}

static inline unsigned long
l4vmm_hypcall3_ret(unsigned func, unsigned long a0, unsigned long *a1,
                                  unsigned long *a2)
{
	register unsigned long _a0 asm ("a0") = a0;
	register unsigned long _a1 asm ("a1") = *a1;
	register unsigned long _a2 asm ("a2") = *a2;
	asm volatile(".set push; .set virt; hypcall %[func]; .set pop"
	             : "=r" (_a0),
	               "=r" (_a1),
	               "=r" (_a2)
	             : [func] "K" (func),
	               "0" (_a0),
	               "1" (_a1),
	               "2" (_a2)
	             : "cc", "memory");
	*a1 = _a1;
	*a2 = _a2;
	return _a0;
}
