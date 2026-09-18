/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ksu_domain.h - KernelSU SELinux domain/type names.
 *
 * Uses KernelSU-Next's own names (ksu / ksu_file): the KSU domain is minted
 * and kept fully functional (root/susfs/zygisk depend on it). susfs references
 * KSU_DOMAIN_CONTEXT to identify the root domain during its path/mount lookups;
 * this must equal KernelSU-Next's KERNEL_SU_CONTEXT ("u:r:ksu:s0"). Single
 * source of truth for the domain/file names.
 *
 * We keep these types minted rather than reusing the ROM's stock su /
 * adb_data_file, because a reused stock `su` type ends up under-powered here
 * (chmod EPERM, exec failures, zygisk fails to launch). The KSU-added types
 * are instead reported as absent on the userspace SELinux query path
 * (sel_write_context / sel_write_access / selinux_setprocattr), which never
 * touches the real domain, so root/manager/susfs/zygisk keep working.
 */
#ifndef _LINUX_KSU_DOMAIN_H
#define _LINUX_KSU_DOMAIN_H

#define KSU_DOMAIN_NAME		"ksu"
#define KSU_FILE_NAME		"ksu_file"
#define KSU_DOMAIN_CONTEXT	"u:r:" KSU_DOMAIN_NAME ":s0"
#define KSU_FILE_CONTEXT_STR	"u:object_r:" KSU_FILE_NAME ":s0"

#endif /* _LINUX_KSU_DOMAIN_H */
