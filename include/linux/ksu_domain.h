/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ksu_domain.h - KernelSU SELinux domain/type names.
 *
 * Single source of truth for the names. susfs uses KSU_DOMAIN_CONTEXT to
 * spot the root domain during its path/mount lookups, so it has to stay equal
 * to KernelSU-Next's KERNEL_SU_CONTEXT ("u:r:ksu:s0").
 *
 * Don't try reusing the ROM's stock su / adb_data_file types instead - the
 * stock su type is too weak here and you get chmod EPERM, exec failures and
 * zygisk refusing to launch.
 */
#ifndef _LINUX_KSU_DOMAIN_H
#define _LINUX_KSU_DOMAIN_H

#define KSU_DOMAIN_NAME		"ksu"
#define KSU_FILE_NAME		"ksu_file"
#define KSU_DOMAIN_CONTEXT	"u:r:" KSU_DOMAIN_NAME ":s0"
#define KSU_FILE_CONTEXT_STR	"u:object_r:" KSU_FILE_NAME ":s0"

#endif /* _LINUX_KSU_DOMAIN_H */
