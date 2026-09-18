#ifndef __KSU_H_SEPOLICY
#define __KSU_H_SEPOLICY

#include <linux/types.h>

#include "ss/policydb.h"

// Operation on types
bool ksu_type(struct policydb *db, const char *name, const char *attr);
bool ksu_attribute(struct policydb *db, const char *name);
bool ksu_permissive(struct policydb *db, const char *type);
bool ksu_enforce(struct policydb *db, const char *type);
bool ksu_typeattribute(struct policydb *db, const char *type, const char *attr);
bool ksu_exists(struct policydb *db, const char *type);

// Access vector rules
bool ksu_allow(struct policydb *db, const char *src, const char *tgt,
           const char *cls, const char *perm);
bool ksu_deny(struct policydb *db, const char *src, const char *tgt,
          const char *cls, const char *perm);
bool ksu_auditallow(struct policydb *db, const char *src, const char *tgt,
            const char *cls, const char *perm);
bool ksu_dontaudit(struct policydb *db, const char *src, const char *tgt,
           const char *cls, const char *perm);

// Extended permissions access vector rules
bool ksu_allowxperm(struct policydb *db, const char *src, const char *tgt,
            const char *cls, const char *range);
bool ksu_auditallowxperm(struct policydb *db, const char *src, const char *tgt,
             const char *cls, const char *range);
bool ksu_dontauditxperm(struct policydb *db, const char *src, const char *tgt,
            const char *cls, const char *range);

// Type rules
bool ksu_type_transition(struct policydb *db, const char *src, const char *tgt,
             const char *cls, const char *def, const char *obj);
bool ksu_type_change(struct policydb *db, const char *src, const char *tgt,
             const char *cls, const char *def);
bool ksu_type_member(struct policydb *db, const char *src, const char *tgt,
             const char *cls, const char *def);

// File system labeling
bool ksu_genfscon(struct policydb *db, const char *fs_name, const char *path,
          const char *ctx);

// compute_av delta table (userspace av-query reconciliation), defined in sepolicy.c
extern bool ksu_avc_delta_ready;
void ksu_avc_delta_init(u32 genuine_ntypes);
bool ksu_type_value_is_added(u32 type_value);
u32 ksu_avc_delta_lookup(u32 stype, u32 ttype, u16 tclass);

#endif