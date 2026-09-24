# SPDX-License-Identifier: GPL-2.0
#
# Drop the KernelSU menu from the .config copy that becomes /proc/config.gz.
# Kconfig writes the block as a blank line, "#", "# KernelSU", "#", the
# symbols, then "# end of KernelSU", so matching CONFIG_KSU alone would leave
# the comments behind.  Bail out if anything survives rather than quietly
# shipping the leak again after a Kconfig change.

{ line[NR] = $0 }

END {
	for (i = 1; i <= NR && !last; i++) {
		if (line[i] == "# KernelSU" && line[i-1] == "#" && line[i-2] == "")
			first = i - 2
		else if (first && line[i] == "# end of KernelSU")
			last = i
	}

	for (i = 1; i <= NR; i++) {
		if (i >= first && i <= last)
			continue
		print line[i]
		if (line[i] ~ /^#? ?CONFIG_KSU/ || line[i] ~ /KernelSU/)
			left = line[i]
	}

	if (left) {
		print "ikconfig-filter: " left " survived the filter" > "/dev/stderr"
		exit 1
	}
}
