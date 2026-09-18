#include <linux/compiler.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
#include <linux/sched/signal.h>
#endif
#include <linux/slab.h>
#include <linux/task_work.h>
#include <linux/thread_info.h>
#include <linux/seccomp.h>
#include <linux/bpf.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>
#include <linux/version.h>

#include "policy/allowlist.h"
#include "setuid_hook.h"
#include "klog.h" // IWYU pragma: keep
#include "manager/manager_identity.h"
#include "selinux/selinux.h"
#include "infra/seccomp_cache.h"
#include "supercall/supercall.h"
#include "hook_manager.h"
#include "feature/kernel_umount.h"
#include "compat/kernel_compat.h"
#ifdef CONFIG_KSU_SUSFS
#include <linux/susfs.h>
#endif

extern void disable_seccomp(struct task_struct *tsk);

static void ksu_install_manager_fd_tw_func(struct callback_head *cb)
{
    ksu_install_fd();
    kfree(cb);
}

int ksu_handle_setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
    // we rely on the fact that zygote always call setresuid(3) with same uids
    uid_t new_uid = ruid;
    uid_t old_uid = current_uid().val;

    pr_debug("handle_setresuid from %d to %d\n", old_uid, new_uid);

    if (unlikely(is_uid_manager(new_uid))) {

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
        if (current->seccomp.mode == SECCOMP_MODE_FILTER && current->seccomp.filter) {
            ksu_seccomp_allow_cache(current->seccomp.filter, __NR_reboot);
        }
#else
		disable_seccomp(current);
#endif

#ifdef KSU_KPROBES_HOOK
        ksu_set_task_tracepoint_flag(current);
#endif

        pr_info("install fd for manager: %d\n", new_uid);
        struct callback_head *cb = kzalloc(sizeof(*cb), GFP_ATOMIC);
        if (!cb)
            return 0;
        cb->func = ksu_install_manager_fd_tw_func;
        if (task_work_add(current, cb, TWA_RESUME)) {
            kfree(cb);
            pr_warn("install manager fd add task_work failed\n");
        }
        return 0;
    }

	if (ksu_is_allow_uid_for_current(new_uid)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
        if (current->seccomp.mode == SECCOMP_MODE_FILTER && current->seccomp.filter) {
            ksu_seccomp_allow_cache(current->seccomp.filter, __NR_reboot);
        }
#else
		disable_seccomp(current);
#endif

#ifdef KSU_KPROBES_HOOK
		ksu_set_task_tracepoint_flag(current);
#endif
	} else {
#ifdef KSU_KPROBES_HOOK
		ksu_clear_task_tracepoint_flag_if_needed(current);
#endif
    }

    // Handle kernel umount
    ksu_handle_umount(old_uid, new_uid);

#ifdef CONFIG_KSU_SUSFS
    // Mark non-root apps as "umounted" so the SuSFS per-app hiding layer
    // (sus_path / sus_kstat / sus_map / open_redirect) actually applies to
    // them. Every one of those features gates on
    // susfs_is_current_proc_umounted_app() == (TIF_PROC_UMOUNTED && uid>=10000).
    // Nothing else in the tree sets TIF_PROC_UMOUNTED, so without this the flag
    // is never raised and the entire per-app SuSFS layer is inert (proven: all
    // 9 module-registered sus_paths hid nothing). Mirrors upstream susfs4ksu,
    // which sets it right after ksu_handle_umount(). The manager returned early
    // above; we additionally skip root-allowed uids so genuine root apps keep
    // full filesystem visibility — leaving exactly the non-su app processes
    // (detectors included) to be fooled.
    if (!ksu_is_allow_uid_for_current(new_uid)) {
        susfs_set_current_proc_umounted();
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
        // Re-flag any sus_path_loop entries for this freshly-spawned app
        // (deferred to a workqueue to avoid blocking the setuid path). No-op
        // when the loop list is empty. Matches upstream.
        schedule_work(&susfs_extra_works);
#endif
    }
#endif

    return 0;
}

extern void ksu_lsm_hook_init(void);
void __init ksu_setuid_hook_init(void)
{
	ksu_kernel_umount_init();
}

void __exit ksu_setuid_hook_exit(void)
{
	pr_info("ksu_core_exit\n");
	ksu_kernel_umount_exit();
}
