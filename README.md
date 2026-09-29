# Vajra Kernel

Custom kernel for the Xiaomi **redwood** (POCO X5 Pro 5G), with KernelSU-Next and SuSFS built in.

`Linux 5.4.302` · `Neutron Clang 24` · `arm64`

## Features

- **KernelSU-Next** — root the moment you flash, no ramdisk patching
- **SuSFS 2.3.0** — in the kernel, nothing extra to install
- Compiled with **Neutron Clang 24** (LLVM 24)

## Build

Put Neutron Clang in your `$PATH`, then:

```bash
export PATH="$HOME/toolchains/neutron-clang/bin:$PATH"

# reproducible build, per Documentation/kbuild/reproducible-builds.rst
export KBUILD_BUILD_USER=genie KBUILD_BUILD_HOST=vajra
export KBUILD_BUILD_TIMESTAMP="Mon Sep 29 00:00:00 UTC 2026"

# prefix-map on both C and assembly; the tree only rewrites __FILE__ for C
ARGS="ARCH=arm64 LLVM=1 LLVM_IAS=1 CROSS_COMPILE=aarch64-linux-gnu- CROSS_COMPILE_COMPAT=arm-linux-gnueabi- \
      KCFLAGS=-ffile-prefix-map=$PWD/= KAFLAGS=-ffile-prefix-map=$PWD/="

make -j$(nproc) O=out $ARGS vendor/xiaomi-qgki_defconfig
scripts/kconfig/merge_config.sh -O out -m out/.config \
    arch/arm64/configs/vendor/redwood.config arch/arm64/configs/vendor/vajra.config
make -j$(nproc) O=out $ARGS olddefconfig
make -j$(nproc) O=out $ARGS Image
```

The image lands at `out/arch/arm64/boot/Image`.

## Flashing

Grab the AnyKernel3 zip from **Releases** and flash it in recovery or with Franco Kernel Manager. It
patches the kernel into whatever boot image is already on the phone, so it works on top of any redwood
ROM without a wipe.

Flashing this roots the ROM you put it on — that is the point, but skip it if you do not want root.

If it ever fails to boot, the kernel reserves 4 MB for ramoops so the panic survives a reboot — do not
power off, restore your old boot image, then send `/sys/fs/pstore/dmesg-ramoops-0`.

## Credits

- **[Scarlet](https://github.com/Atom-X-Devs/scarlet_xiaomi_sm7325)** by
  [Tashfin Shakeer Rhythm (@Tashar02)](https://github.com/Tashar02) and
  [Atom-X-Devs](https://github.com/Atom-X-Devs) — the base tree (`6697b3ec`)
- [KernelSU-Next](https://github.com/KernelSU-Next/KernelSU-Next)
- [SuSFS](https://gitlab.com/simonpunk/susfs4ksu) by simonpunk
- [Redwood-AOSP](https://github.com/Redwood-AOSP) — device and vendor trees

## License

GPL-2.0. See `COPYING`.
