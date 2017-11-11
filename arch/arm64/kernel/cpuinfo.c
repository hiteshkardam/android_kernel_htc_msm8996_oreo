/*
 * Record and handle CPU attributes.
 *
 * Copyright (C) 2014 ARM Ltd.
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <asm/arch_timer.h>
#include <asm/cachetype.h>
#include <asm/cpu.h>
#include <asm/cputype.h>
#include <asm/cpufeature.h>
#include <asm/system_misc.h>

#include <linux/bitops.h>
#include <linux/bug.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/personality.h>
#include <linux/preempt.h>
#include <linux/printk.h>
#include <linux/seq_file.h>
#include <linux/sched.h>
#include <linux/smp.h>
#include <linux/of_address.h>
#include <linux/io.h>

/*
 * In case the boot CPU is hotpluggable, we record its initial state and
 * current state separately. Certain system registers may contain different
 * values depending on configuration at or after reset.
 */
DEFINE_PER_CPU(struct cpuinfo_arm64, cpu_data);
static struct cpuinfo_arm64 boot_cpu_data;

static char *icache_policy_str[] = {
	[ICACHE_POLICY_RESERVED] = "RESERVED/UNKNOWN",
	[ICACHE_POLICY_AIVIVT] = "AIVIVT",
	[ICACHE_POLICY_VIPT] = "VIPT",
	[ICACHE_POLICY_PIPT] = "PIPT",
};

unsigned long __icache_flags;

static const char *hwcap_str[] = {
	"fp",
	"asimd",
	"evtstrm",
	"aes",
	"pmull",
	"sha1",
	"sha2",
	"crc32",
	"atomics",
	NULL
};

#ifdef CONFIG_COMPAT
static const char *compat_hwcap_str[] = {
	"swp",
	"half",
	"thumb",
	"26bit",
	"fastmult",
	"fpa",
	"vfp",
	"edsp",
	"java",
	"iwmmxt",
	"crunch",
	"thumbee",
	"neon",
	"vfpv3",
	"vfpv3d16",
	"tls",
	"vfpv4",
	"idiva",
	"idivt",
	"vfpd32",
	"lpae",
	"evtstrm",
	NULL
};

static const char *compat_hwcap2_str[] = {
	"aes",
	"pmull",
	"sha1",
	"sha2",
	"crc32",
	NULL
};
#endif /* CONFIG_COMPAT */

static u32 cx_fuse_data = 0x0;
static u32 mx_fuse_data = 0x0;

static const u32 vddcx_pvs_retention_data[8] =
{
  /* 000 */ 600000,
  /* 001 */ 550000,
  /* 010 */ 500000,
  /* 011 */ 450000,
  /* 100 */ 400000,
  /* 101 */ 400000, //limiting based on CR812560
  /* 110 */ 400000, //limiting based on CR812560
  /* 111 */ 600000
};

static const u32 vddmx_pvs_retention_data[8] =
{
  /* 000 */ 700000,
  /* 001 */ 650000,
  /* 010 */ 580000,
  /* 011 */ 550000,
  /* 100 */ 490000,
  /* 101 */ 490000,
  /* 110 */ 490000,
  /* 111 */ 490000
};

static int read_cx_fuse_setting(void){
	if(cx_fuse_data != 0x0)
		/* 0x00070134[31:29] */
		return ((cx_fuse_data & (0x7 << 29)) >> 29);
	else
		return -ENOMEM;
}

static int read_mx_fuse_setting(void){
	if(mx_fuse_data != 0x0)
		/* 0x00070148[4:2] */
		return ((mx_fuse_data & (0x7 << 2)) >> 2);
	else
		return -ENOMEM;
}

static u32 Get_min_cx(void) {
	u32 lookup_val = 0;
	int mapping_data;
	mapping_data = read_cx_fuse_setting();
	if(mapping_data >= 0)
		lookup_val = vddcx_pvs_retention_data[mapping_data];
	return lookup_val;
}

static u32 Get_min_mx(void) {
	u32 lookup_val = 0;
	int mapping_data;
	mapping_data = read_mx_fuse_setting();
	if(mapping_data >= 0)
		lookup_val = vddmx_pvs_retention_data[mapping_data];
	return lookup_val;
}

extern u64* htc_target_quot[2];
extern int htc_target_quot_len;

static int c_show(struct seq_file *m, void *v)
{
	int i, j, size;

	for_each_online_cpu(i) {
		struct cpuinfo_arm64 *cpuinfo = &per_cpu(cpu_data, i);
		u32 midr = cpuinfo->reg_midr;

		/*
		 * glibc reads /proc/cpuinfo to determine the number of
		 * online processors, looking for lines beginning with
		 * "processor".  Give glibc what it expects.
		 */
#ifdef CONFIG_SMP
		seq_printf(m, "processor\t: %d\n", i);
#endif
		seq_printf(m, "min_vddcx\t: %d\n", Get_min_cx());
		seq_printf(m, "min_vddmx\t: %d\n", Get_min_mx());
		
		seq_printf(m, "BogoMIPS\t: %lu.%02lu\n",
			   loops_per_jiffy / (500000UL/HZ),
			   loops_per_jiffy / (5000UL/HZ) % 100);

		/*
		 * Dump out the common processor features in a single line.
		 * Userspace should read the hwcaps with getauxval(AT_HWCAP)
		 * rather than attempting to parse this, but there's a body of
		 * software which does already (at least for 32-bit).
		 */
		seq_puts(m, "Features\t:");
		if (personality(current->personality) == PER_LINUX32) {
#ifdef CONFIG_COMPAT
			for (j = 0; compat_hwcap_str[j]; j++)
				if (compat_elf_hwcap & (1 << j))
					seq_printf(m, " %s", compat_hwcap_str[j]);

			for (j = 0; compat_hwcap2_str[j]; j++)
				if (compat_elf_hwcap2 & (1 << j))
					seq_printf(m, " %s", compat_hwcap2_str[j]);
#endif /* CONFIG_COMPAT */
		} else {
			for (j = 0; hwcap_str[j]; j++)
				if (elf_hwcap & (1 << j))
					seq_printf(m, " %s", hwcap_str[j]);
		}
		seq_puts(m, "\n");

		seq_printf(m, "CPU implementer\t: 0x%02x\n",
			   MIDR_IMPLEMENTOR(midr));
		seq_printf(m, "CPU architecture: 8\n");
		seq_printf(m, "CPU variant\t: 0x%x\n", MIDR_VARIANT(midr));
		seq_printf(m, "CPU part\t: 0x%03x\n", MIDR_PARTNUM(midr));
		seq_printf(m, "CPU revision\t: %d\n\n", MIDR_REVISION(midr));
	}

	if (!arch_read_hardware_id)
		seq_printf(m, "Hardware\t: %s\n", machine_name);
	else
		seq_printf(m, "Hardware\t: %s\n", arch_read_hardware_id());

	size = sizeof(htc_target_quot)/(sizeof(u64)*htc_target_quot_len);
	seq_printf(m, "CPU param\t: ");
	for (i = 0; i < size; i++) {
		for(j = 0; j < htc_target_quot_len; j++)
			seq_printf(m, "%lld ", htc_target_quot[i][j]);
	}
	seq_printf(m, "\n");

	return 0;
}

static void *c_start(struct seq_file *m, loff_t *pos)
{
	return *pos < 1 ? (void *)1 : NULL;
}

static void *c_next(struct seq_file *m, void *v, loff_t *pos)
{
	++*pos;
	return NULL;
}

static void c_stop(struct seq_file *m, void *v)
{
}

const struct seq_operations cpuinfo_op = {
	.start	= c_start,
	.next	= c_next,
	.stop	= c_stop,
	.show	= c_show
};

static void cpuinfo_detect_icache_policy(struct cpuinfo_arm64 *info)
{
	unsigned int cpu = smp_processor_id();
	u32 l1ip = CTR_L1IP(info->reg_ctr);

	if (l1ip != ICACHE_POLICY_PIPT) {
		/*
		 * VIPT caches are non-aliasing if the VA always equals the PA
		 * in all bit positions that are covered by the index. This is
		 * the case if the size of a way (# of sets * line size) does
		 * not exceed PAGE_SIZE.
		 */
		u32 waysize = icache_get_numsets() * icache_get_linesize();

		if (l1ip != ICACHE_POLICY_VIPT || waysize > PAGE_SIZE)
			set_bit(ICACHEF_ALIASING, &__icache_flags);
	}
	if (l1ip == ICACHE_POLICY_AIVIVT)
		set_bit(ICACHEF_AIVIVT, &__icache_flags);

	pr_info("Detected %s I-cache on CPU%d\n", icache_policy_str[l1ip], cpu);
}

static void __cpuinfo_store_cpu(struct cpuinfo_arm64 *info)
{
	info->reg_cntfrq = arch_timer_get_cntfrq();
	info->reg_ctr = read_cpuid_cachetype();
	info->reg_dczid = read_cpuid(SYS_DCZID_EL0);
	info->reg_midr = read_cpuid_id();

	info->reg_id_aa64dfr0 = read_cpuid(SYS_ID_AA64DFR0_EL1);
	info->reg_id_aa64dfr1 = read_cpuid(SYS_ID_AA64DFR1_EL1);
	info->reg_id_aa64isar0 = read_cpuid(SYS_ID_AA64ISAR0_EL1);
	info->reg_id_aa64isar1 = read_cpuid(SYS_ID_AA64ISAR1_EL1);
	info->reg_id_aa64mmfr0 = read_cpuid(SYS_ID_AA64MMFR0_EL1);
	info->reg_id_aa64mmfr1 = read_cpuid(SYS_ID_AA64MMFR1_EL1);
	info->reg_id_aa64mmfr2 = read_cpuid(SYS_ID_AA64MMFR2_EL1);
	info->reg_id_aa64pfr0 = read_cpuid(SYS_ID_AA64PFR0_EL1);
	info->reg_id_aa64pfr1 = read_cpuid(SYS_ID_AA64PFR1_EL1);

	info->reg_id_dfr0 = read_cpuid(SYS_ID_DFR0_EL1);
	info->reg_id_isar0 = read_cpuid(SYS_ID_ISAR0_EL1);
	info->reg_id_isar1 = read_cpuid(SYS_ID_ISAR1_EL1);
	info->reg_id_isar2 = read_cpuid(SYS_ID_ISAR2_EL1);
	info->reg_id_isar3 = read_cpuid(SYS_ID_ISAR3_EL1);
	info->reg_id_isar4 = read_cpuid(SYS_ID_ISAR4_EL1);
	info->reg_id_isar5 = read_cpuid(SYS_ID_ISAR5_EL1);
	info->reg_id_mmfr0 = read_cpuid(SYS_ID_MMFR0_EL1);
	info->reg_id_mmfr1 = read_cpuid(SYS_ID_MMFR1_EL1);
	info->reg_id_mmfr2 = read_cpuid(SYS_ID_MMFR2_EL1);
	info->reg_id_mmfr3 = read_cpuid(SYS_ID_MMFR3_EL1);
	info->reg_id_pfr0 = read_cpuid(SYS_ID_PFR0_EL1);
	info->reg_id_pfr1 = read_cpuid(SYS_ID_PFR1_EL1);

	info->reg_mvfr0 = read_cpuid(SYS_MVFR0_EL1);
	info->reg_mvfr1 = read_cpuid(SYS_MVFR1_EL1);
	info->reg_mvfr2 = read_cpuid(SYS_MVFR2_EL1);

	cpuinfo_detect_icache_policy(info);

	check_local_cpu_errata();
}

void cpuinfo_store_cpu(void)
{
	struct cpuinfo_arm64 *info = this_cpu_ptr(&cpu_data);
	__cpuinfo_store_cpu(info);
	update_cpu_features(smp_processor_id(), info, &boot_cpu_data);
}

void __init cpuinfo_store_boot_cpu(void)
{
	struct cpuinfo_arm64 *info = &per_cpu(cpu_data, 0);
	__cpuinfo_store_cpu(info);

	boot_cpu_data = *info;
	init_cpu_features(&boot_cpu_data);
}

u64 __attribute_const__ icache_get_ccsidr(void)
{
	u64 ccsidr;

	WARN_ON(preemptible());

	/* Select L1 I-cache and read its size ID register */
	asm("msr csselr_el1, %1; isb; mrs %0, ccsidr_el1"
	    : "=r"(ccsidr) : "r"(1L));
	return ccsidr;
}

static int msm8996_read_cx_fuse(void){
	void __iomem *addr;
	struct device_node *dn = of_find_compatible_node(NULL,
						NULL, "qcom,cpucx-8996");
	if (dn && (cx_fuse_data == 0x0)) {
		addr = of_iomap(dn, 0);
		if (!addr)
			return -ENOMEM;
		cx_fuse_data = readl_relaxed(addr);
		iounmap(addr);
	}
	else {
		return -ENOMEM;
	}
	return 0;
}
arch_initcall_sync(msm8996_read_cx_fuse);

static int msm8996_read_mx_fuse(void){
	void __iomem *addr;
	struct device_node *dn = of_find_compatible_node(NULL,
						NULL, "qcom,cpumx-8996");
	if (dn && (mx_fuse_data == 0x0)) {
		addr = of_iomap(dn, 0);
		if (!addr)
			return -ENOMEM;
		mx_fuse_data = readl_relaxed(addr);
		iounmap(addr);
	}
	else {
		return -ENOMEM;
	}
	return 0;
}

arch_initcall_sync(msm8996_read_mx_fuse);
