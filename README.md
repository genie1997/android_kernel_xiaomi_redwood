# Vajra Kernel — Xiaomi redwood

Custom kernel for the Redmi Note 13 Pro 5G / POCO X5 Pro 5G (`redwood`), based on the
Scarlet v6.0 base with KernelSU-Next and SuSFS.

Linux 5.4.302. Built with Neutron Clang 24.

## Features

- Scarlet v6.0 base, on 5.4.302
- KernelSU-Next (root built in, no ramdisk patch needed)
- SuSFS
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

Grab the AnyKernel3 zip from Releases and flash it in recovery, or with the KernelSU-Next manager /
Franco Kernel Manager. It patches the kernel into whatever boot image is already on the phone, so it
works on top of any redwood ROM without a wipe.

Built and tested on redwood. It should be fine on other redwood ROMs of the same Android
generation — flash it, and if something misbehaves open an issue with the ROM name.

Heads up: this kernel has KernelSU-Next in it, so flashing it roots the ROM you put it on. That's the
point, but don't flash it if you don't want root.

## Credits

- Scarlet kernel — base tree
- [KernelSU-Next](https://github.com/KernelSU-Next/KernelSU-Next)
- [SuSFS](https://gitlab.com/simonpunk/susfs4ksu)
- [Redwood-AOSP](https://github.com/Redwood-AOSP) — device/vendor trees

## License

GPL-2.0. See `COPYING`.
