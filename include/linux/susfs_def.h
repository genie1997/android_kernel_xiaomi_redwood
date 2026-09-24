#ifndef KSU_SUSFS_DEF_H
#define KSU_SUSFS_DEF_H

#include <linux/bits.h>
#include <linux/jump_label.h>
#include <linux/string.h>
#include <linux/version.h> // We need check kernel version.
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
#include <linux/cred.h>
#endif

/********/
/* ENUM */
/********/
/* shared with userspace ksu_susfs tool */
#define SUSFS_MAGIC 0xFAFAFAFA
#define CMD_SUSFS_ADD_SUS_PATH 0x55550
#define CMD_SUSFS_SET_ANDROID_DATA_ROOT_PATH 0x55551 /* deprecated */
#define CMD_SUSFS_SET_SDCARD_ROOT_PATH 0x55552 /* deprecated */
#define CMD_SUSFS_ADD_SUS_PATH_LOOP 0x55553
#define CMD_SUSFS_ADD_SUS_MOUNT 0x55560 /* deprecated */
#define CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS 0x55561
#define CMD_SUSFS_UMOUNT_FOR_ZYGOTE_ISO_SERVICE 0x55562 /* deprecated */
#define CMD_SUSFS_ADD_SUS_KSTAT 0x55570
#define CMD_SUSFS_UPDATE_SUS_KSTAT 0x55571
#define CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY 0x55572
#define CMD_SUSFS_ADD_TRY_UMOUNT 0x55580 /* deprecated */
#define CMD_SUSFS_SET_UNAME 0x55590
#define CMD_SUSFS_ENABLE_LOG 0x555a0
#define CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG 0x555b0
#define CMD_SUSFS_ADD_OPEN_REDIRECT 0x555c0
#define CMD_SUSFS_SHOW_VERSION 0x555e1
#define CMD_SUSFS_SHOW_ENABLED_FEATURES 0x555e2
#define CMD_SUSFS_SHOW_VARIANT 0x555e3
#define CMD_SUSFS_SHOW_SUS_SU_WORKING_MODE 0x555e4 /* deprecated */
#define CMD_SUSFS_IS_SUS_SU_READY 0x555f0 /* deprecated */
#define CMD_SUSFS_SUS_SU 0x60000 /* deprecated */
#define CMD_SUSFS_ENABLE_AVC_LOG_SPOOFING 0x60010
#define CMD_SUSFS_ADD_SUS_MAP 0x60020

#define SUSFS_MAX_LEN_PATHNAME 256 // 256 should address many paths already unless you are doing some strange experimental stuff, then set your own desired length
#define SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE 8192 // 8192 is enough I guess
#define SUSFS_ENABLED_FEATURES_SIZE 8192 // 8192 is enough I guess
#define SUSFS_MAX_VERSION_BUFSIZE 16
#define SUSFS_MAX_VARIANT_BUFSIZE 16

#define TRY_UMOUNT_DEFAULT 0 /* used by susfs_try_umount() */
#define TRY_UMOUNT_DETACH 1 /* used by susfs_try_umount() */

#define VFSMOUNT_MNT_FLAGS_KSU_UNSHARED_MNT 0x80000000 /* used for mounts that are unshared by ksu process */
#define DEFAULT_KSU_MNT_ID 500000 /* used for mounts created or single cloned by ksu process */
#define DEFAULT_KSU_MNT_GROUP_ID 5000 /* used by mount->mnt_group_id */

#ifndef FUSE_SUPER_MAGIC
#define FUSE_SUPER_MAGIC 0x65735546
#endif
/*
 * inode->i_state => A 'unsigned long' type storing flag 'AS_FLAGS_', bit 1 to 31 is not usable since 6.12
 * nd->state => storing flag 'ND_STATE_'
 * nd->flags => storing flag 'ND_FLAGS_'
 * task_struct->thread_info.flags => storing flag 'TIF_'
 */
 // thread_info->flags is unsigned long :D
#define TIF_PROC_UMOUNTED 33
#define TIF_PROC_NO_SU 34
/* reserved to match upstream's bit layout; unused in this tree */
#define TIF_PROC_UMOUNTED_FOR_ZYGOTE_NEXT 35

#define AS_FLAGS_SUS_PATH 33
#define AS_FLAGS_SUS_MOUNT 34
#define AS_FLAGS_SUS_KSTAT 35
#define AS_FLAGS_OPEN_REDIRECT 36
#define AS_FLAGS_SUS_MAP 39

#define ND_STATE_LOOKUP_LAST 32
#define ND_STATE_OPEN_LAST 64
#define ND_FLAGS_LOOKUP_LAST		0x2000000

#define MAGIC_MOUNT_WORKDIR "/debug_ramdisk/workdir"


static inline bool susfs_starts_with(const char *str, const char *prefix) {
	while (*prefix) {
		if (*str++ != *prefix++)
			return false;
	}
	return true;
}

static inline bool susfs_ends_with(const char *str, const char *suffix) {
	size_t str_len, suffix_len;

	if (!str || !suffix)
		return false;

	str_len = strlen(str);
	suffix_len = strlen(suffix);

	if (suffix_len > str_len)
		return false;

	return !strcmp(str + str_len - suffix_len, suffix);
}

/* From KernelSU */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
typedef const struct qstr *susfs_fname_t;
#define susfs_fname_len(f) ((f)->len)
#define susfs_fname_arg(f) ((f)->name)
#else
typedef const unsigned char *susfs_fname_t;
#define susfs_fname_len(f) (strlen(f))
#define susfs_fname_arg(f) (f)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
#define SUSFS_DECL_FSNOTIFY_OPS(name)                                            \
int name(struct fsnotify_mark *mark, u32 mask, struct inode *inode,    \
struct inode *dir, const struct qstr *file_name, u32 cookie)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
#define SUSFS_DECL_FSNOTIFY_OPS(name)                                            \
int name(struct fsnotify_group *group, struct inode *inode, u32 mask,  \
const void *data, int data_type, susfs_fname_t file_name,       \
u32 cookie, struct fsnotify_iter_info *iter_info)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
#define SUSFS_DECL_FSNOTIFY_OPS(name)                                            \
int name(struct fsnotify_group *group, struct inode *inode, u32 mask,  \
const void *data, int data_type, susfs_fname_t file_name,       \
u32 cookie, struct fsnotify_iter_info *iter_info)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
#define SUSFS_DECL_FSNOTIFY_OPS(name)                                            \
int name(struct fsnotify_group *group, struct inode *inode,            \
struct fsnotify_mark *inode_mark,                             \
struct fsnotify_mark *vfsmount_mark, u32 mask,                \
const void *data, int data_type, susfs_fname_t file_name,       \
u32 cookie, struct fsnotify_iter_info *iter_info)
#else
#define SUSFS_DECL_FSNOTIFY_OPS(name)                                            \
int name(struct fsnotify_group *group, struct inode *inode,            \
struct fsnotify_mark *inode_mark,                             \
struct fsnotify_mark *vfsmount_mark, u32 mask, void *data,    \
int data_type, susfs_fname_t file_name, u32 cookie)
#endif

/* only records that ksu_handle_umount() queued the umount for this task; it
 * may still fail, so no hiding decision may depend on it. */
static inline bool susfs_is_current_proc_umounted(void) {
	return test_ti_thread_flag(&current->thread_info, TIF_PROC_UMOUNTED);
}

static inline void susfs_set_current_proc_umounted(void) {
	set_ti_thread_flag(&current->thread_info, TIF_PROC_UMOUNTED);
}

static inline void susfs_clear_current_proc_umounted(void) {
	clear_ti_thread_flag(&current->thread_info, TIF_PROC_UMOUNTED);
}

/* set when this task's uid is not root-allowed. Inherited across fork/exec,
 * so the setuid hook sets/clears it to track the allowlist; the per-app
 * hiding layer gates on it. */
static inline bool susfs_is_current_proc_no_su(void) {
	return test_ti_thread_flag(&current->thread_info, TIF_PROC_NO_SU);
}

static inline void susfs_set_current_proc_no_su(void) {
	set_ti_thread_flag(&current->thread_info, TIF_PROC_NO_SU);
}

static inline void susfs_clear_current_proc_no_su(void) {
	clear_ti_thread_flag(&current->thread_info, TIF_PROC_NO_SU);
}

static inline bool susfs_is_current_proc_no_su_app(void) {
	return (test_ti_thread_flag(&current->thread_info, TIF_PROC_NO_SU) &&
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
			__kuid_val(current_uid()) >= 10000);
#else
			current_uid().val >= 10000);
#endif
}

#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
extern struct static_key_false susfs_is_hide_sus_mnts_for_non_su_procs_enabled;
extern bool susfs_is_current_ksu_domain(void);

/* true for tasks shown the mount tree with ksu mounts dropped; statfs() and
 * fdinfo must answer with the non-ksu parent for the same tasks. */
static inline bool susfs_is_sus_mnt_hidden_from_current(void)
{
	return static_branch_unlikely(&susfs_is_hide_sus_mnts_for_non_su_procs_enabled) &&
		!susfs_is_current_ksu_domain();
}
#endif

/* sus_path/sus_kstat fast-path gates: the real work is out of line in
 * fs/susfs.c; these inlines gate it behind a static key, off until armed, so
 * an unarmed kernel pays nothing on these hot paths. */
struct inode;
struct kstat;
struct mnt_idmap;

#ifdef CONFIG_KSU_SUSFS_SUS_PATH
extern struct static_key_false susfs_sus_path_key;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
extern bool __susfs_is_inode_sus_path(struct mnt_idmap *idmap, struct inode *inode);
static inline bool susfs_is_inode_sus_path(struct mnt_idmap *idmap, struct inode *inode)
{
	return static_branch_unlikely(&susfs_sus_path_key) &&
		__susfs_is_inode_sus_path(idmap, inode);
}
#else
extern bool __susfs_is_inode_sus_path(struct inode *inode);
static inline bool susfs_is_inode_sus_path(struct inode *inode)
{
	return static_branch_unlikely(&susfs_sus_path_key) &&
		__susfs_is_inode_sus_path(inode);
}
#endif
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_PATH

#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
extern struct static_key_false susfs_sus_kstat_key;
extern void __susfs_sus_kstat_spoof_generic_fillattr(struct inode *inode, struct kstat *stat);
static inline void susfs_sus_kstat_spoof_generic_fillattr(struct inode *inode, struct kstat *stat)
{
	if (static_branch_unlikely(&susfs_sus_kstat_key))
		__susfs_sus_kstat_spoof_generic_fillattr(inode, stat);
}
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_KSTAT

#define SUSFS_IS_INODE_SUS_MAP(inode) \
		((inode) && (inode)->i_mapping && \
		 unlikely(test_bit(AS_FLAGS_SUS_MAP, &(inode)->i_state)) && \
		 susfs_is_current_proc_no_su_app())

#define SUSFS_IS_INODE_OPEN_REDIRECT_WITHOUT_UID_CHECK(inode) \
		((inode) && (inode)->i_mapping && \
		 unlikely(test_bit(AS_FLAGS_OPEN_REDIRECT, &(inode)->i_state)))

#define SUSFS_IS_INODE_OPEN_REDIRECT(inode) \
		((inode) && (inode)->i_mapping && \
		 unlikely(test_bit(AS_FLAGS_OPEN_REDIRECT, &(inode)->i_state)) && \
		 susfs_is_current_proc_no_su_app())
#endif // #ifndef KSU_SUSFS_DEF_H
