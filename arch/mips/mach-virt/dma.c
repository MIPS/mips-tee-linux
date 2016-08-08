/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2016 Kernkonzept GmbH
 */


#include <linux/of.h>
#include <linux/of_fdt.h>
#include <linux/of_address.h>

#include <asm/mach-virt/dma-coherence.h>

unsigned long l4vmm_gpa_start;
unsigned long l4vmm_gpa_size;
dma_addr_t l4vmm_dma_start;

/* For now, we just have a single contiguous physical region in the
 * hypervisor */
static int __init mips_virt_dma_init(void)
{
	struct device_node *np;
	const __be32 *ranges = NULL;
	int naddr, nsize, len;

	l4vmm_gpa_size = 0;

	np = of_find_node_by_name(NULL, "memory");
	if (!np)
		return 0;

	naddr = of_n_addr_cells(np);
	nsize = of_n_size_cells(np);

	ranges = of_get_property(np, "dma-ranges", &len);

	if (ranges && len >= (sizeof(*ranges) * (2 * naddr + nsize))) {
		l4vmm_dma_start = of_read_number(ranges, naddr);
		l4vmm_gpa_start = of_read_number(ranges + naddr, naddr);
		l4vmm_gpa_size = of_read_number(ranges + 2 * naddr, nsize);

		pr_info("DMA range for memory 0x%lx - 0x%lx set @ 0x%lx\n",
		        l4vmm_gpa_start,
		        l4vmm_gpa_start + l4vmm_gpa_size,
		        (unsigned long) l4vmm_dma_start);
	}

	return 0;
}

fs_initcall(mips_virt_dma_init);
