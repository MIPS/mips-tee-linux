/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2016 Kernkonzept GmbH
 */
#pragma once

#include <linux/mm.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/bug.h>
#include <linux/io.h>
#include <linux/dma-mapping.h>

extern unsigned long l4vmm_gpa_start;
extern unsigned long l4vmm_gpa_size;
extern dma_addr_t l4vmm_dma_start;

struct device;

static inline dma_addr_t plat_map_gpa_to_dma(unsigned long gpa)
{
	if (likely(l4vmm_gpa_size)) {
		if (likely(l4vmm_gpa_start <= gpa
		           && gpa < l4vmm_gpa_start + l4vmm_gpa_size))
			return gpa - l4vmm_gpa_start + l4vmm_dma_start;
	}

	pr_err("Failed to translate guest-physical 0x%lx to dma-addr\n",
	       gpa);
	BUG(); /* What else? If not here we'll go chaos sooner anyway */
}

static inline dma_addr_t plat_map_dma_mem(struct device *dev, void *addr,
	size_t size)
{
	return plat_map_gpa_to_dma(virt_to_phys(addr));
}

static inline dma_addr_t plat_map_dma_mem_page(struct device *dev,
	struct page *page)
{
	return plat_map_gpa_to_dma(page_to_phys(page));
}

static inline unsigned long plat_dma_addr_to_phys(struct device *dev,
	dma_addr_t dma_addr)
{
	if (likely(l4vmm_gpa_size)) {
		if (likely(l4vmm_dma_start <= dma_addr
		           && dma_addr < l4vmm_dma_start + l4vmm_gpa_size))
			return dma_addr - l4vmm_dma_start + l4vmm_gpa_start;
	}

	pr_err("%s: Do not know about dma_addr=%lx\n", __func__,
	       (unsigned long) dma_addr);
	BUG();
}

static inline void plat_unmap_dma_mem(struct device *dev, dma_addr_t dma_addr,
	size_t size, enum dma_data_direction direction)
{
	if (0) pr_warn("%s\n", __func__);
}

static inline int plat_dma_supported(struct device *dev, u64 mask)
{
	/*
	 * we fall back to GFP_DMA when the mask isn't all 1s,
	 * so we can't guarantee allocations that must be
	 * within a tighter range than GFP_DMA..
	 */
	if (mask < DMA_BIT_MASK(24))
		return 0;

	return 1;
}

static inline int plat_device_is_coherent(struct device *dev)
{
	return coherentio;
}

#ifndef plat_post_dma_flush
static inline void plat_post_dma_flush(struct device *dev)
{
}
#endif

#ifdef CONFIG_SWIOTLB
static inline dma_addr_t phys_to_dma(struct device *dev, phys_addr_t paddr)
{
	return plat_map_gpa_to_dma(paddr);
}

static inline phys_addr_t dma_to_phys(struct device *dev, dma_addr_t daddr)
{
	return daddr;
}
#endif
