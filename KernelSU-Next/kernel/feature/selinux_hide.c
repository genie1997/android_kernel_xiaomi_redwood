#include <linux/errno.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include "policy/feature.h"
#include "include/ksu.h"
#include  "uapi/feature.h"
#include "feature/selinux_hide.h"

void ksu_selinux_hide_drop_backup_if_unused(void)
{
	/* legacy build keeps no backup sepolicy; nothing to drop */
}

void ksu_selinux_hide_handle_second_stage(void)
{
}

void ksu_selinux_hide_handle_post_fs_data(void)
{
}

static int selinux_hide_status_feature_get(u64 *value)
{
	*value = 0;
	return 0;
}

// the selinuxfs nodes answer for added types themselves, so there is nothing left to toggle
static int selinux_hide_status_feature_set(u64 value)
{
	if (value)
		return -EOPNOTSUPP;
	return 0;
}

static const struct ksu_feature_handler selinux_hide_status_handler = {
	.feature_id = KSU_FEATURE_SELINUX_HIDE,
	.name = "selinux_hide",
	.get_handler = selinux_hide_status_feature_get,
	.set_handler = selinux_hide_status_feature_set,
};

void __init ksu_selinux_hide_init(void)
{
	if (ksu_register_feature_handler(&selinux_hide_status_handler))
		pr_err("ksu_selinux_hide: failed to register feature handler\n");
}

void __exit ksu_selinux_hide_exit(void)
{
	ksu_unregister_feature_handler(KSU_FEATURE_SELINUX_HIDE);
}
