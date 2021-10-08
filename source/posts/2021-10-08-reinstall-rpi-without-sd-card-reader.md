#! title: "在没有 SD 读卡器的情况下重装树莓派为 Arch Linux ARM"

如果想将 VPS 重装为 Arch Linux，有一个知名项目可以选择：[vps2arch](https://gitlab.com/drizzt/vps2arch)。而树莓派则看起来并没有这样的项目，需要手动操作。

> It's simple: using ld.so from the Bootstrap chroot to launch the chroot tool.

根据 vps2arch 的 README，他的原理非常简单，只是使用 ld.so 进入 chroot。我也计划如法炮制。

我的树莓派 3B+ 之前安装的是 32bit 的 Raspbian OS，而我打算重装为 64bit 的 Arch Linux ARM，故无法使用新系统的可执行文件。

参考教程（[https://archlinuxarm.org/platforms/armv8/broadcom/raspberry-pi-3](https://archlinuxarm.org/platforms/armv8/broadcom/raspberry-pi-3)），我发现只需要将 tar 包解压到根目录即可完成安装，那么可以先解压到临时目录，再想办法移到根目录。

我认为 Linux 下应该有方法可以做到，直接在文件系统层面把某个文件夹的内容全部移到根目录，并把原根目录的内容移走，但是我并不知道这样的方法，所以只能自己瞎搞了。（当然还有一个办法，直接 tar 覆盖解压到根目录，理论上也能工作，但是我希望有一个干净的系统，不想要旧系统的残留，所以否决了这个方法）

先把 `/opt` `/root` `/home` 这类无关紧要的文件夹直接迁移。迁移 `/bin` 之后，只能使用 `/oldroot/bin/mv` 来移动文件夹。迁移 `/usr` 之后，需要加上 `LD_LIBRARY_PATH=/oldroot/usr/lib/XXX` 才能让 mv 正常运行。迁移 `/lib` 之后，由于 ld 没了，必须手动使用 `/oldroot/lib/ld-XXX /oldroot/bin/mv` 来移动文件夹。不过这时也已经做完了，重启即可进入新系统。