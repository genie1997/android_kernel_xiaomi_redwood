# Vajra Kernel — Xiaomi redwood

Custom kernel for `redwood` (POCO X5 Pro 5G), based on the Scarlet v6.0 base with
KernelSU-Next and SuSFS.

Linux 5.4.302. Built with Neutron Clang 24.

## Features

- Scarlet v6.0 base, on 5.4.302
- KernelSU-Next (root built in, no ramdisk patch needed)
- SuSFS v2.3.0
- Compiled with Neutron Clang 24 (LLVM 24)

## Build

Neutron Clang in your `$PATH`, then:

```bash
export PATH="$HOME/toolchains/neutron-clang/bin:$PATH"
export KBUILD_BUILD_USER=genie KBUILD_BUILD_HOST=vajra

ARGS="ARCH=arm64 LLVM=1 LLVM_IAS=1 CROSS_COMPILE=aarch64-linux-gnu- CROSS_COMPILE_COMPAT=arm-linux-gnueabi-"

make -j$(nproc) O=out $ARGS vendor/xiaomi-qgki_defconfig
scripts/kconfig/merge_config.sh -O out -m out/.config \
    arch/arm64/configs/vendor/redwood.config arch/arm64/configs/vendor/vajra.config
make -j$(nproc) O=out $ARGS olddefconfig
make -j$(nproc) O=out $ARGS Image
```

The kernel image lands at `out/arch/arm64/boot/Image`.

## Flashing

Grab the AnyKernel3 zip from Releases and flash it in recovery, or with Franco Kernel Manager. It
patches the kernel into whatever boot image is already on the phone, so it works on top of any
redwood ROM without a wipe.

Built and tested on redwood. It should be fine on other redwood ROMs of the same Android
generation — flash it, and if something misbehaves open an issue with the ROM name.

Heads up: this kernel has KernelSU-Next in it, so flashing it roots the ROM you put it on. That's the
point, but don't flash it if you don't want root.

If it ever fails to boot, the kernel reserves 4 MB for ramoops, so the panic survives the reboot —
don't power the phone off, restore your old boot image, then send me
`/sys/fs/pstore/dmesg-ramoops-0`.

## Credits

- **[Scarlet](https://github.com/Atom-X-Devs/scarlet_xiaomi_sm7325)** by
  [Tashfin Shakeer Rhythm (@Tashar02)](https://github.com/Tashar02) and
  [Atom-X-Devs](https://github.com/Atom-X-Devs) — the base tree this is built on
- [KernelSU-Next](https://github.com/KernelSU-Next/KernelSU-Next)
- [SuSFS](https://gitlab.com/simonpunk/susfs4ksu) by simonpunk
- [Redwood-AOSP](https://github.com/Redwood-AOSP) — device/vendor trees

## License

GPL-2.0. See `COPYING`.
