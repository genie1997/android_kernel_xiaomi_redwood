#include <linux/err.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/printk.h>

#include "policy/allowlist.h"
#include "klog.h" // IWYU pragma: keep
#include "runtime/ksud_boot.h"
#include "runtime/ksud.h"
#include "manager/manager_observer.h"
#include "manager/throne_tracker.h"
#include "selinux/selinux.h"

bool ksu_module_mounted __read_mostly = false;
bool ksu_boot_completed __read_mostly = false;
extern void stop_input_hook();
extern void ksu_stop_sys_read_hook(void);

extern void ksu_avc_spoof_late_init();

void on_post_fs_data(void)
{
	static bool done = false;
	if (done) {
		pr_info("on_post_fs_data already done\n");
		return;
	}
	done = true;
	pr_info("on_post_fs_data!\n");

	ksu_load_allow_list();
	ksu_observer_init();
	// sanity check, this may influence the performance
	stop_input_hook();
	/* init.rc is read by now, so retire the read hook. Runs in sleepable
	 * context (init task_work / ksud supercall). */
	ksu_stop_sys_read_hook();
}

extern void ext4_unregister_sysfs(struct super_block *sb);

int nuke_ext4_sysfs(const char *mnt)
{
	struct path path;
	int err = kern_path(mnt, 0, &path);
	if (err) {
		pr_err("nuke path err: %d\n", err);
		return err;
	}

	/* Only act on a real mount root: kern_path() also resolves a plain dir,
	 * whose i_sb is the containing fs (e.g. ext4 /data). Refuse rather than
	 * nuke the wrong superblock. */
	if (path.dentry != path.mnt->mnt_root) {
		pr_err("nuke refused: '%s' is not a mount root\n", mnt);
		path_put(&path);
		return -EINVAL;
	}

	struct super_block *sb = path.mnt->mnt_sb;
	const char *name = sb->s_type->name;
	if (strcmp(name, "ext4") != 0) {
		pr_info("nuke but module aren't mounted\n");
		path_put(&path);
		return -EINVAL;
	}

	ext4_unregister_sysfs(sb);
	path_put(&path);
	return 0;
}

void on_module_mounted(void)
{
	pr_info("on_module_mounted!\n");
	ksu_module_mounted = true;
}

void on_boot_completed(void)
{
    pr_info("on_boot_completed!\n");
    /* Raise the flag only after the first track_throne(), or a packages.list
     * rename can re-enter the synchronous path with i_rwsem held. */
    track_throne(true);
    ksu_boot_completed = true;
    ksu_avc_spoof_late_init();
}
