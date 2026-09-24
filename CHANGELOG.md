# Vajra

Custom kernel for Xiaomi `redwood` — the POCO X5 Pro 5G and Redmi Note 12 Pro Speed.
Linux 5.4.302, built on the Scarlet v6.0 base with Neutron Clang 24.

| | |
|---|---|
| Codenames | `redwood`, `redwoodin` — the installer accepts both |
| Defconfig | `vendor/xiaomi-qgki_defconfig` + `vendor/redwood.config` + `vendor/vajra.config` |
| Root | KernelSU-Next, compiled in — manual hooks, no kprobes |
| SuSFS | 2.3.0, compiled in |

---

## 2.0 — 24 September 2026

- SuSFS is updated to 2.3.0 — a big chunk of it was reworked this release.
- KernelSU-Next is updated. You'll need the KernelSU-Next 3.4.0 manager for this build; older
  managers won't work with it. Grab it from the KernelSU-Next releases page.
- Fixed a reboot that could panic the phone when you had modules installed.

## 1.0.2 — 19 September 2026

Installer fixes only, same kernel as 1.0.

- Fix the installer not finding the boot partition (the AnyKernel3 vars were lowercase).
- Fix `redwoodin` units being turned away at the device check.
- Pulled the broken `Vajra-1.0.zip` / `1.0.1.zip` — use this one instead.

## 1.0 — 18 September 2026

First release.

- KernelSU-Next compiled in — root the moment you flash, no ramdisk patch or separate boot image.
- SuSFS 2.2.0 compiled in (sus_path, sus_mount, sus_kstat, sus_map, open_redirect, uname/cmdline
  spoof, symbol hiding). The SuSFS module isn't needed.
- Add the `redwood` and `vajra` config fragments.

---

## Flashing

Franco Kernel Manager's built-in flasher, or `adb sideload Vajra-2.0.zip` from recovery.

It is an AnyKernel3 zip, kernel-only: it replaces the Image and leaves your ROM's ramdisk alone, so it
flashes on top of whatever redwood ROM you are already running. No wipe, no data loss.

- AOSP ROMs only — LineageOS, PixelOS and similar, Android 17 and below. Not made for MIUI or HyperOS.
- Flashing this roots your ROM. With root and an unlocked bootloader, banking, payment and some DRM
  apps may refuse to run. Go in knowing that.

## Managers

- KernelSU-Next manager — https://github.com/KernelSU-Next/KernelSU-Next/releases
- SuSFS module, optional — https://github.com/sidex15/susfs4ksu-module/releases/latest
  SuSFS is already in the kernel, so this is not needed for the basics. Add it only if you want the
  WebUI and manual control over what gets hidden.
- Do not stack other root-hiding modules such as Shamiko or Zygisk Assistant on top. They fight
  each other.

## If it does not boot

The platform reserves 4 MB of ramoops — 2 MB for the panic record, 2 MB for the Android log — so a
kernel panic leaves a backtrace behind instead of a mystery.

1. Do not power the phone off. That memory survives a reboot; it does not survive a power-off or a
   battery pull, and the log goes with it.
2. Reboot to recovery or fastboot and restore your previous `boot.img` to get a booting system back.
3. Pull the log from the failed boot and attach it to an issue:

```
adb shell su -c 'cat /sys/fs/pstore/dmesg-ramoops-0'
```

That file is the panic itself — the backtrace and the last thing the kernel did. `/sys/fs/pstore/pmsg-0`
holds the Android-side log from the same boot, if it got that far. There is no `console-ramoops` on
this device, the device tree does not reserve one, so `dmesg-ramoops-0` is the file that matters.

## Credits

Built on [Scarlet](https://github.com/Atom-X-Devs/scarlet_xiaomi_sm7325) by
[Tashfin Shakeer Rhythm](https://github.com/Tashar02) and
[Atom-X-Devs](https://github.com/Atom-X-Devs), from v6.0 (`6697b3ec`). This kernel is my own
modification on top of their tree — anything wrong with this build is mine to fix, not theirs.

SuSFS by [simonpunk](https://gitlab.com/simonpunk/susfs4ksu).
KernelSU-Next by the [KernelSU-Next team](https://github.com/KernelSU-Next/KernelSU-Next).
