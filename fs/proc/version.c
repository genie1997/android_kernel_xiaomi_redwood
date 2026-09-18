// SPDX-License-Identifier: GPL-2.0
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/utsname.h>

#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
/* Same SuSFS key + helper the newuname() syscall uses (see kernel/sys.c). When
 * the user arms uname spoofing via the ksu_susfs CLI, /proc/version must report
 * the SAME spoofed release/version as uname(2), or the mismatch is itself a
 * tamper tell. Build host/compiler are already scrubbed at compile time. */
extern struct static_key_false susfs_set_uname_key_true;
extern void susfs_spoof_uname(struct new_utsname *tmp);
#endif

static int version_proc_show(struct seq_file *m, void *v)
{
#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
	if (static_branch_unlikely(&susfs_set_uname_key_true)) {
		struct new_utsname tmp;

		memcpy(&tmp, utsname(), sizeof(tmp));
		susfs_spoof_uname(&tmp);
		seq_printf(m, linux_proc_banner,
			tmp.sysname, tmp.release, tmp.version);
		return 0;
	}
#endif
	seq_printf(m, linux_proc_banner,
		utsname()->sysname,
		utsname()->release,
		utsname()->version);
	return 0;
}

static int __init proc_version_init(void)
{
	proc_create_single("version", 0, NULL, version_proc_show);
	return 0;
}
fs_initcall(proc_version_init);
