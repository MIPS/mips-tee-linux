/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2016 Kernkonzept GmbH
 */

#include <linux/init.h>
#include <linux/initrd.h>
#include <linux/of.h>
#include <linux/of_fdt.h>
#include <linux/of_platform.h>
#include <linux/clk-provider.h>
#include <linux/clocksource.h>

#include <asm/bootinfo.h>
#include <asm/cpu-features.h>
#include <asm/irq_cpu.h>
#include <asm/prom.h>
#include <asm/time.h>

const char *get_system_type(void)
{
	return "MIPS Virtual Platform";
}

static void __init init_mips_cpu_timer(void)
{
	struct device_node *np;
	u32 freq;

	mips_hpt_frequency = 0;

	/* The timer frequency must be defined in the device tree.
	   If the definition is missing, we assume that the timer should
	   not be used.
	*/
	np = of_find_node_by_name(NULL, "cpus");
	if (np && of_property_read_u32(np, "mips-hpt-frequency", &freq) >= 0) {
		mips_hpt_frequency = freq;

		printk("CPU frequency %d.%02d MHz\n", freq/1000000,
		       (freq%1000000)*100/1000000);
	} else
		pr_warn("MIPS CPU core timer not used. %p, %u\n", np, freq);

	of_node_put(np);
}

void __init plat_time_init(void)
{
	init_mips_cpu_timer();
}

void __init prom_init(void)
{
	int i;
	int argc = fw_arg0;
	char **argv = (char **)fw_arg1;

	for (i = 0; i < argc; i++) {
		strlcat(arcs_cmdline, argv[i], COMMAND_LINE_SIZE);
		if (i < argc - 1)
			strlcat(arcs_cmdline, " ", COMMAND_LINE_SIZE);
	}

	printk("DT at address %p\n", (void *)fw_arg3);
	__dt_setup_arch((void *)fw_arg3);
}

void __init plat_mem_setup(void)
{
}

void __init prom_free_prom_memory(void)
{
}

void __init device_tree_init(void)
{
	unflatten_and_copy_device_tree();
}

static int __init publish_devices(void)
{
	if (!of_have_populated_dt())
		return 0;

	if (of_platform_populate(NULL, of_default_bus_match_table, NULL, NULL))
		panic("Failed to populate DT");

	return 0;
}
device_initcall(publish_devices);
