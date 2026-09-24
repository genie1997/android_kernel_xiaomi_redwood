#!/usr/bin/env bash
# Check whether our advertised manager UAPI can be bumped to match a given
# KernelSU-Next manager release without a real backport.
#
# The manager marks the kernel "supported" only when the UAPI integer it reads
# back (KSU_IOCTL_GET_INFO -> uapi_version) equals the one baked into the APK.
# That integer is only safe to raise if the manager-facing ioctl ABI (the structs
# and command numbers in uapi/) is otherwise unchanged. This diffs the two,
# ignoring cosmetic noise (comments, #define vs static const, whitespace, the
# version define itself, and field/enum *names*, since a rename keeps the layout)
# leaves any real change for review.
#
# Usage: ksun-manager-compat-check.sh [upstream-repo] [manager-ref]
#   upstream-repo  a local KernelSU-Next checkout
#   manager-ref    a manager tag; defaults to the newest v*.*.* tag
set -eu

here="$(cd "$(dirname "$0")" && pwd)"
our_uapi="$here/../../uapi"
up="${1:-$HOME/redwood-work/ksun-ref}"
ref="${2:-}"

[ -d "$up/.git" ] || { echo "not a git repo: $up" >&2; exit 2; }
git -C "$up" fetch --tags --quiet origin >/dev/null 2>&1 || true
[ -n "$ref" ] || ref="$(git -C "$up" tag | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -1)"

headers="supercall.h app_profile.h feature.h selinux.h sulog.h ksu.h"

# collapse a uapi header to a name-agnostic, spelling-agnostic ABI shape
NORM_PY='
import sys, re
s = sys.stdin.read()
s = re.sub(r"/\*.*?\*/", "", s, flags=re.S)                 # block comments
s = re.sub(r"//.*", "", s)                                  # line comments
# drop the version define itself (reported separately) in every spelling
s = re.sub(r"#ifndef\s+KERNEL_SU_UAPI_VERSION.*?#endif", "", s, flags=re.S)
s = re.sub(r"#define\s+KERNEL_SU_UAPI_VERSION[^\n]*", "", s)
s = re.sub(r"static\s+const\s+__u\d+\s+KERNEL_SU_UAPI_VERSION[^\n]*", "", s)
# static const __uNN NAME = VALUE;  ->  #define NAME VALUE
s = re.sub(r"static\s+const\s+__u\d+\s+(\w+)\s*=\s*([^;]+);", r"#define \1 \2", s)
out = []
for ln in s.splitlines():
    ln = ln.strip()
    if not ln:
        continue
    # inside a struct: "type name;" / "type name[N];" -> drop the field name
    if not ln.startswith("#"):
        # struct field: "type name;" / "type name[N];" -> drop the field name
        m = re.match(r"^([A-Za-z_][\w ]*?\**)\s+\w+(\s*\[[^\]]*\])?\s*;$", ln)
        if m:
            ln = (m.group(1).strip() + (m.group(2) or "")).strip() + ";"
        else:
            # enum member: "NAME = VALUE," / "NAME," -> keep the value, drop the name
            e = re.match(r"^[A-Za-z_]\w*\s*(=\s*[^,;{}()]+)?,?$", ln)
            if e:
                v = (e.group(1) or "").strip()
                ln = (v + ",") if v else ","
    out.append(re.sub(r"\s+", " ", ln))
sys.stdout.write("\n".join(out) + "\n")
'
normalize() { python3 -c "$NORM_PY"; }

echo "Manager repo:        $up"
echo "Manager ref:         $ref"
mgr_uapi="$(git -C "$up" show "$ref:uapi/supercall.h" | sed -nE 's/.*KERNEL_SU_UAPI_VERSION[^0-9]*([0-9]+).*/\1/p' | tail -1)"
our_adv="$(sed -nE 's/.*KSU_MANAGER_COMPAT_UAPI[^0-9]*([0-9]+).*/\1/p' "$here/../Kbuild" | tail -1)"
echo "Manager UAPI:        ${mgr_uapi:-?}"
echo "Our advertised UAPI: ${our_adv:-?}  (KSU_MANAGER_COMPAT_UAPI in kernel/Kbuild)"
echo

changed=0
for h in $headers; do
    a="$(normalize < "$our_uapi/$h")"
    b="$(git -C "$up" show "$ref:uapi/$h" | normalize)"
    if [ "$a" != "$b" ]; then
        changed=1
        echo "### wire-ABI change in uapi/$h  (ours < | manager >)"
        diff <(printf '%s\n' "$a") <(printf '%s\n' "$b") || true
        echo
    fi
done

if [ "$changed" -eq 0 ]; then
    echo "SAFE: manager-facing ABI identical. Set KSU_MANAGER_COMPAT_UAPI := $mgr_uapi"
else
    echo "REVIEW: a manager-facing struct/constant changed above. Confirm whether it"
    echo "        affects a command the manager issues before bumping; a real change"
    echo "        needs a backport, not just a version bump."
fi
