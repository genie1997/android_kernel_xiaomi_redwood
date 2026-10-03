#include <linux/compiler.h>
#include <linux/version.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/task_work.h>
#include <linux/thread_info.h>
#include <linux/seccomp.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>

#include "policy/allowlist.h"
#include "policy/app_profile.h"
#include "hook/setuid_hook.h"
#include "klog.h" // IWYU pragma: keep
#include "manager/manager_identity.h"
#include "infra/seccomp_cache.h"
#include "supercall/supercall.h"
#include "hook/hook_manager.h"
#include "feature/kernel_umount.h"
#include "compat/kernel_compat.h"
#ifdef CONFIG_KSU_SUSFS
#include <linux/susfs.h>
#endif

int ksu_handle_setresuid(uid_t old_uid, uid_t new_uid)
{
    // we rely on the fact that zygote always call setresuid(3) with same uids
    bool allowed;

    pr_debug("handle_setresuid from %d to %d\n", old_uid, new_uid);

    if (unlikely(is_uid_manager(new_uid))) {

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
        if (current->seccomp.mode == SECCOMP_MODE_FILTER && current->seccomp.filter) {
            ksu_seccomp_allow_cache(current->seccomp.filter, __NR_reboot);
        }
#else
		/* keep the app's filter (mode 2), just let its reboot knock through */
		set_thread_flag(TIF_KSU_ALLOW_REBOOT);
#endif

#ifdef KSU_KPROBES_HOOK
        ksu_set_task_tracepoint_flag(current);
#endif

#ifdef CONFIG_KSU_SUSFS
        /* manager is always root-allowed and returns below, so clear the flag here */
        susfs_clear_current_proc_no_su();
#endif

        pr_info("install fd for manager: %d\n", new_uid);
        ksu_install_fd();
        return 0;
    }

    /* single allowlist walk, reused by the susfs no_su gate below */
    allowed = ksu_is_allow_uid_for_current(new_uid);

    if (allowed) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
        if (current->seccomp.mode == SECCOMP_MODE_FILTER && current->seccomp.filter) {
            ksu_seccomp_allow_cache(current->seccomp.filter, __NR_reboot);
        }
#else
		/* keep the app's filter (mode 2), just let its reboot knock through */
		set_thread_flag(TIF_KSU_ALLOW_REBOOT);
#endif

#ifdef KSU_KPROBES_HOOK
		ksu_set_task_tracepoint_flag(current);
#endif
	} else {
#ifdef KSU_KPROBES_HOOK
		ksu_clear_task_tracepoint_flag_if_needed(current);
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
		// a revoke must clear what a grant set, same as the susfs no_su flag below
		clear_thread_flag(TIF_KSU_ALLOW_REBOOT);
#endif
    }

    // Handle kernel umount
    ksu_handle_umount(old_uid, new_uid);

#ifdef CONFIG_KSU_SUSFS
    // flag whether this uid is root-allowed (the per-app susfs layer gates on it); thread flags survive fork/exec, so set on one branch and clear on the other to stay in step with a grant or revoke
    if (!allowed) {
        susfs_set_current_proc_no_su();
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
        // re-flag sus_path_loop entries; skip the queue when none are armed
        if (static_branch_unlikely(&susfs_sus_path_key))
            schedule_work(&susfs_extra_works);
#endif
    } else {
        susfs_clear_current_proc_no_su();
    }
#endif

    return 0;
}

void __init ksu_setuid_hook_init(void)
{
	ksu_kernel_umount_init();
}

void __exit ksu_setuid_hook_exit(void)
{
	pr_info("ksu_core_exit\n");
	ksu_kernel_umount_exit();
}