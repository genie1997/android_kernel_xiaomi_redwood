#ifndef __KSU_H_SELINUX
#define __KSU_H_SELINUX

#include <linux/types.h>
#include <linux/version.h>
#include <linux/cred.h>

#include "objsec.h"
#include "security.h" // Samsung SELinux Porting

#ifndef KSU_COMPAT_USE_SELINUX_STATE
#include "avc.h"
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 18, 0)
typedef struct task_security_struct taskcred_sec_t;
#else
typedef struct cred_security_struct taskcred_sec_t;
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)) &&                         \
	!defined(KSU_COMPAT_HAS_CURRENT_SID)
/*
 * get the subjective security ID of the current task
 */
static inline u32 current_sid(void)
{
	const struct task_security_struct *tsec = current_security();

	return tsec->sid;
}
#endif

#include <linux/ksu_domain.h>
/* names come from linux/ksu_domain.h (single source of truth) */
#define KERNEL_SU_DOMAIN KSU_DOMAIN_NAME
#define KERNEL_SU_FILE KSU_FILE_NAME

#define KERNEL_SU_CONTEXT "u:r:" KERNEL_SU_DOMAIN ":s0"
#define KSU_FILE_CONTEXT "u:object_r:" KERNEL_SU_FILE ":s0"
#define ZYGOTE_CONTEXT "u:r:zygote:s0"
#define INIT_CONTEXT "u:r:init:s0"

void setup_selinux(const char *, struct cred *);

void setenforce(bool);

bool getenforce();

void cache_sid(void);

bool is_task_ksu_domain(const struct cred* cred);

bool is_ksu_domain();

#ifdef CONFIG_KSU_SUSFS
bool susfs_is_current_ksu_domain(void);
#endif

bool is_zygote(const struct cred* cred);

bool is_init(const struct cred* cred);

void apply_kernelsu_rules();

int handle_sepolicy(void __user *user_data, u64 data_len);

/* Userspace SELinux av-query reconciliation (defined in selinux.c / rules.c) */
bool ksu_mask_compute_av_for_caller(void);
u32 ksu_compute_av_delta_bits(u32 ssid, u32 tsid, u16 tclass);
bool ksu_sid_is_ksu_added_type(u32 sid);

void setup_ksu_cred();

void escape_to_root_for_adb_root();

extern u32 ksu_file_sid;

#endif
