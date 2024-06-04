#!/bin/bash
#使用pahole制作BTF文件
#readelf -S vmlinux |grep BTF
#内核配置有CONFIG_DEBUG_INFO_BTF才会生成btf信息
#或者下载对应kernel-debuginfo
#kernel-debug-debuginfo是Kconfig里面开启了各种debug特性的版本的debuginfo
#kernel-debuginfo是普通正常线上运行的内核的debuginfo。

#install pahole
#download
git clone https://git.kernel.org/pub/scm/devel/pahole/pahole.git/
git submodule update --init --recursive

# make install
mkdir build && cd build
cmake -D__LIB=lib ..
make install

#从有BTF信息的vmlinux中提取BTF部分
pahole --btf_encode_detached "vmlinux.btf" vmlinux
