/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2016 Kernkonzept GmbH
 */

#include <linux/init.h>
#include <linux/irqchip.h>

#include <asm/irq.h>

void __init arch_init_irq(void)
{
	irqchip_init();
}
