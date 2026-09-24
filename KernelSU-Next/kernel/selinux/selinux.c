#include "selinux.h"
#include "linux/cred.h"
#include "linux/sched.h"
#include "linux/security.h"
#include "objsec.h"
#include "linux/version.h"
#include "klog.h" // IWYU pragma: keep
#include "ksu.h"

/* SIDs cached once at policy load; 0 means unresolved and callers fall back
 * to the string compare. */
static u32 cached_su_sid __read_mostly = 0;
static u32 cached_zygote_sid __read_mostly = 0;
static u32 cached_init_sid __read_mostly = 0;
static u32 cached_system_server_sid __read_mostly = 0;
/* keep the servicemanager family exempt from masking: they gate service
 * lookups over /sys/fs/selinux/access, so masking ksu's allow bit hangs the
 * su prompt. They only return a handle, never the raw decision. */
static u32 cached_servicemanager_sid __read_mostly = 0;
static u32 cached_hwservicemanager_sid __read_mostly = 0;
static u32 cached_vndservicemanager_sid __read_mostly = 0;

#define SYSTEM_SERVER_CONTEXT "u:r:system_server:s0"
#define SERVICEMANAGER_CONTEXT "u:r:servicemanager:s0"
#define HWSERVICEMANAGER_CONTEXT "u:r:hwservicemanager:s0"
#define VNDSERVICEMANAGER_CONTEXT "u:r:vndservicemanager:s0"
u32 ksu_file_sid __read_mostly = 0;

static int transive_to_domain(const char *domain, struct cred *cred, bool clear_exec_sid)
{
    struct task_security_struct *tsec;
    u32 sid;
    int error;

    tsec = selinux_cred(cred);
    if (!tsec) {
        pr_err("tsec == NULL!\n");
        return -1;
    }

    error = security_secctx_to_secid(domain, strlen(domain), &sid);
    if (error) {
        pr_info("security_secctx_to_secid %s -> sid: %d, error: %d\n", domain,
                sid, error);
    }
    if (!error) {
        tsec->sid = sid;
        tsec->create_sid = 0;
        tsec->keycreate_sid = 0;
        tsec->sockcreate_sid = 0;
		if (clear_exec_sid) {
            tsec->exec_sid = 0;
        }
    }
    return error;
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 19, 0)
bool __maybe_unused
is_ksu_transition(const struct task_security_struct *old_tsec,
		  const struct task_security_struct *new_tsec)
{
	static u32 ksu_sid;
	char *secdata;
	u32 seclen;
	bool allowed = false;

	if (!ksu_sid)
		security_secctx_to_secid(KERNEL_SU_CONTEXT,
					 strlen(KERNEL_SU_CONTEXT), &ksu_sid);

	if (security_secid_to_secctx(old_tsec->sid, &secdata, &seclen))
		return false;

	allowed = (!strcmp("u:r:init:s0", secdata) && new_tsec->sid == ksu_sid);
	security_release_secctx(secdata, seclen);
	return allowed;
}
#endif

void setup_selinux(const char *domain, struct cred *cred)
{
    if (transive_to_domain(domain, cred, false)) {
        pr_err("transive domain failed.\n");
        return;
    }
}

void setup_ksu_cred(void)
{
    if (ksu_cred && transive_to_domain(KERNEL_SU_CONTEXT, ksu_cred, false)) {
        pr_err("setup ksu cred failed.\n");
    }
}

void setenforce(bool enforce)
{
#ifdef CONFIG_SECURITY_SELINUX_DEVELOP
#ifdef KSU_COMPAT_USE_SELINUX_STATE
	selinux_state.enforcing = enforce;
#else
	selinux_enforcing = enforce;
#endif
#endif
}

bool getenforce(void)
{
#ifdef CONFIG_SECURITY_SELINUX_DISABLE
#ifdef KSU_COMPAT_USE_SELINUX_STATE
	if (selinux_state.disabled) {
		return false;
	}
#else
	if (selinux_disabled) {
		return false;
	}
#endif // KSU_COMPAT_USE_SELINUX_STATE
#endif // CONFIG_SECURITY_SELINUX_DISABLE

#ifdef CONFIG_SECURITY_SELINUX_DEVELOP
#ifdef KSU_COMPAT_USE_SELINUX_STATE
	return selinux_state.enforcing;
#else
	return selinux_enforcing;
#endif
#else
	return true;
#endif
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 14, 0)
struct lsm_context {
    char *context;
    u32 len;
};

static int __security_secid_to_secctx(u32 secid, struct lsm_context *cp)
{
    return security_secid_to_secctx(secid, &cp->context, &cp->len);
}
static void __security_release_secctx(struct lsm_context *cp)
{
    security_release_secctx(cp->context, cp->len);
}
#else
#define __security_secid_to_secctx security_secid_to_secctx
#define __security_release_secctx security_release_secctx
#endif

/*
 * Resolve the cached SIDs once, after the policy is loaded (post-fs-data).
 */

void cache_sid(void)
{
    int err;

    err = security_secctx_to_secid(KERNEL_SU_CONTEXT, strlen(KERNEL_SU_CONTEXT),
                                   &cached_su_sid);
    if (err) {
        pr_warn("Failed to cache kernel su domain SID: %d\n", err);
        cached_su_sid = 0;
    } else {
        pr_info("Cached su SID: %u\n", cached_su_sid);
    }

    err = security_secctx_to_secid(ZYGOTE_CONTEXT, strlen(ZYGOTE_CONTEXT),
                                   &cached_zygote_sid);
    if (err) {
        pr_warn("Failed to cache zygote SID: %d\n", err);
        cached_zygote_sid = 0;
    } else {
        pr_info("Cached zygote SID: %u\n", cached_zygote_sid);
    }

    err = security_secctx_to_secid(INIT_CONTEXT, strlen(INIT_CONTEXT),
                                   &cached_init_sid);
    if (err) {
        pr_warn("Failed to cache init SID: %d\n", err);
        cached_init_sid = 0;
    } else {
        pr_info("Cached init SID: %u\n", cached_init_sid);
    }

    err = security_secctx_to_secid(KSU_FILE_CONTEXT, strlen(KSU_FILE_CONTEXT),
                                   &ksu_file_sid);
    if (err) {
        pr_warn("Failed to cache ksu_file SID: %d\n", err);
        ksu_file_sid = 0;
    } else {
        pr_info("Cached ksu_file SID: %u\n", ksu_file_sid);
    }

    err = security_secctx_to_secid(SYSTEM_SERVER_CONTEXT,
                                   strlen(SYSTEM_SERVER_CONTEXT),
                                   &cached_system_server_sid);
    if (err) {
        pr_warn("Failed to cache system_server SID: %d\n", err);
        cached_system_server_sid = 0;
    } else {
        pr_info("Cached system_server SID: %u\n", cached_system_server_sid);
    }

    /* servicemanager family: resolve up front, kept exempt from the masking. */
    {
        static const struct {
            const char *ctx;
            u32 *out;
        } smgr[] = {
            { SERVICEMANAGER_CONTEXT, &cached_servicemanager_sid },
            { HWSERVICEMANAGER_CONTEXT, &cached_hwservicemanager_sid },
            { VNDSERVICEMANAGER_CONTEXT, &cached_vndservicemanager_sid },
        };
        int i;
        for (i = 0; i < ARRAY_SIZE(smgr); i++) {
            err = security_secctx_to_secid(smgr[i].ctx, strlen(smgr[i].ctx),
                                           smgr[i].out);
            if (err) {
                pr_warn("Failed to cache %s SID: %d\n", smgr[i].ctx, err);
                *smgr[i].out = 0;
            } else {
                pr_info("Cached %s SID: %u\n", smgr[i].ctx, *smgr[i].out);
            }
        }
    }
}

/* whether this caller should see the base-policy answer: yes for everyone
 * except kernel/init/system_server/zygote/ksu and the servicemanager family. */
bool ksu_mask_compute_av_for_caller(void)
{
    u32 sid = current_sid();

    if (sid == SECINITSID_KERNEL)
        return false;
    if (cached_init_sid && sid == cached_init_sid)
        return false;
    if (cached_zygote_sid && sid == cached_zygote_sid)
        return false;
    if (cached_system_server_sid && sid == cached_system_server_sid)
        return false;
    if (cached_su_sid && sid == cached_su_sid)
        return false;
    if (cached_servicemanager_sid && sid == cached_servicemanager_sid)
        return false;
    if (cached_hwservicemanager_sid && sid == cached_hwservicemanager_sid)
        return false;
    if (cached_vndservicemanager_sid && sid == cached_vndservicemanager_sid)
        return false;
    return true;
}

/* compare against the cached SID; fall back to the string compare if unset */
static bool is_sid_match(const struct cred *cred, u32 cached_sid,
                         const char *fallback_context)
{
    if (!cred) {
        return false;
    }
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 18, 0)
    const struct task_security_struct *tsec = selinux_cred(cred);
#else
    const struct cred_security_struct *tsec = selinux_cred(cred);
#endif
    if (!tsec) {
        return false;
    }
    
    // Fast path: use cached SID if available
    if (likely(cached_sid != 0)) {
        return tsec->sid == cached_sid;
    }

    // Slow path fallback: string comparison (only before cache is initialized)
    struct lsm_context ctx;
    bool result;
    if (__security_secid_to_secctx(tsec->sid, &ctx)) {
        return false;
    }
    result = strncmp(fallback_context, ctx.context, ctx.len) == 0;
    __security_release_secctx(&ctx);
    return result;
}

bool is_task_ksu_domain(const struct cred *cred)
{
    return is_sid_match(cred, cached_su_sid, KERNEL_SU_CONTEXT);
}

bool is_ksu_domain(void)
{
    return is_task_ksu_domain(current_cred());
}

#ifdef CONFIG_KSU_SUSFS
/* SuSFS predicate (extern-declared in fs/susfs.c): true only for the KSU
 * root-granted domain, so root tooling sees the real fs while everything else
 * gets the spoofed view. Backed by legacy's own SELinux domain check. */
bool susfs_is_current_ksu_domain(void)
{
	return is_ksu_domain();
}
#endif

bool is_zygote(const struct cred *cred)
{
    return is_sid_match(cred, cached_zygote_sid, ZYGOTE_CONTEXT);
}

bool is_init(const struct cred *cred)
{
    return is_sid_match(cred, cached_init_sid, INIT_CONTEXT);
}

void escape_to_root_for_adb_root(void)
{
    struct cred *cred = prepare_creds();
    if (!cred) {
        pr_err("Failed to prepare adbd's creds!\n");
        return;
    }

    if (transive_to_domain(KERNEL_SU_CONTEXT, cred, true)) {
        pr_err("transive domain failed.\n");
        abort_creds(cred);
        return;
    }
    commit_creds(cred);
}
