/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2016 Kernkonzept GmbH
 */
#include <asm/mach-virt/hypcall.h>

void prom_putchar(char c)
{
	l4vmm_hypcall1(L4VMM_FUNC_PRINTCHAR, c);
}
