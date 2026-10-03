#!/usr/bin/env bash
# Fail loud instead of letting Kbuild's conditional sed -i backports rewrite source silently.
set -uo pipefail

# drivers/kernelsu is a symlink to KernelSU-Next/kernel, so this is their one shared file.
TREE="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
KBUILD="$TREE/drivers/kernelsu/Kbuild"
fail=0

note() { printf '%-6s %s\n' "$1" "$2"; }
ok()   { note "ok" "$1"; }
bad()  { note "FAIL" "$1"; fail=1; }

[ -f "$KBUILD" ] || { echo "!! no such file: $KBUILD" >&2; exit 2; }

# find every guard block that actually gates a sed -i, skipping ones that only gate a ccflag
guard_lines=$(awk '
/^ifneq \(\$\(shell grep/ {
    start = NR
    depth = 1
    has_sed = 0
    while ((getline nxt) > 0) {
        if (nxt ~ /^if(eq|neq) \(/) depth++
        else if (nxt ~ /^endif/) { depth--; if (depth == 0) break }
        if (nxt ~ /sed -i/) has_sed = 1
    }
    if (has_sed) print start
}
' "$KBUILD")

n=0
for lineno in $guard_lines; do
    n=$((n + 1))
    line=$(sed -n "${lineno}p" "$KBUILD")
    flag=$(grep -oP '(?<=grep )(-Eq|-q)' <<<"$line")
    rawpat=$(grep -oP "(?<=grep (-Eq|-q) )[\"'].*?[\"'](?= \\\$\(srctree\))" <<<"$line")
    pat="${rawpat:1:-1}"
    rel=$(grep -oP '(?<=\$\(srctree\)/)\S+(?=;)' <<<"$line")
    target="$TREE/$rel"
    label="guard $n ($rel: $pat)"
    if [ ! -f "$target" ]; then
        bad "$label - target file missing"
        continue
    fi
    if [ "$flag" = "-Eq" ]; then
        grep -Eq -- "$pat" "$target" && ok "$label" || bad "$label - sed -i would fire, rewriting $rel"
    else
        grep -q -- "$pat" "$target" && ok "$label" || bad "$label - sed -i would fire, rewriting $rel"
    fi
done

[ "$n" -eq 10 ] || bad "guard count drifted from the known 10 (found $n) - re-check this script against Kbuild"

# Pin the two version constants a build could otherwise silently diverge on.
grep -q '^KSU_VERSION_OVERRIDE ?= 33296$' "$KBUILD" && ok "KSU_VERSION_OVERRIDE pinned at 33296" || bad "KSU_VERSION_OVERRIDE default changed from 33296"
grep -q '^KSU_MANAGER_COMPAT_UAPI := 4$' "$KBUILD" && ok "KSU_MANAGER_COMPAT_UAPI pinned at 4" || bad "KSU_MANAGER_COMPAT_UAPI default changed from 4"

exit "$fail"
