#!/bin/bash
cd "$DOS_BUILD_BASE""kernel/zuk/msm8996"
git apply $DOS_PATCHES_LINUX_CVES/0001-LinuxIncrementals/4.4/4.4.0209-0210.patch --exclude=Makefile
git apply $DOS_PATCHES_LINUX_CVES/0001-LinuxIncrementals/4.4/4.4.0233-0234.patch --exclude=Makefile
git apply $DOS_PATCHES_LINUX_CVES/0007-Accelerated_AES/3.10+/0016.patch
git apply $DOS_PATCHES_LINUX_CVES/0007-Accelerated_AES/3.10+/0020.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening/4.4/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening/4.4/0006.patch
#git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening/4.4/0011.patch
#git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening/4.4/0012.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening/4.4/0013.patch
#git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening/4.4/0014.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening/4.4/0015.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening/4.4/0018.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening/4.4/0019.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-7837/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-1583/^4.6.3/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-6187/^4.6.5/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-6693/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-6696/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-8394/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-16USB/ANY/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-16USB/ANY/0009.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-0610/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-0627/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-0627/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-9059/^4.11.1/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-9211/^4.11.2/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-13218/4.4/0018.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-13693/^4.12.9/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-13694/^4.12.9/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-14875/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-14883/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-18174/^4.7/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-18204/^4.14.2/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-1000252/^4.13.3/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-5897/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-8043/^4.15.8/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-9415/ANY/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-10323/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-13094/^4.17.3/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-21008/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-8912/^4.20.11/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-10622/ANY/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-12378/^5.1.5/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-12456/^5.1.5/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-12614/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-14763/^4.16.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-14896/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-14901/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-15217/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-15220/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-15221/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-16233/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-16234/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-16994/^5.0/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-17351/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19051/4.4/0010.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19051/^5.3.11/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19051/^5.3.11/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19054/^5.3.11/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19057/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19062/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19063/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19073/^5.3.11/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19074/^5.3.11/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19227/4.4/0005.patch
#git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19319/4.4/0017.patch
#git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19319/4.4/0018.patch
#git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19319/4.4/0019.patch
#git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19319/4.4/0020.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19332/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19447/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19947/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19965/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-20096/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-20810/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-20812/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-0009/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-0255/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-0543/4.4/0021.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-0543/4.4/0022.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-0543/4.4/0023.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-0543/4.4/0024.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-0543/4.4/0025.patch
#git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-1749/4.4/0009.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-2732/4.4/0013.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-8428/4.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-8647/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-8648/4.4/0013.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-8648/4.4/0014.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-8648/4.4/0015.patch
#git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-8992/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-9383/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-10711/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-10732/4.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-10766/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-10942/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-11494/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-11565/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-11608/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-11608/^5.6.1/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-11609/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-11668/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-12652/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-12653/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-12654/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-12656/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-12656/4.4/0009.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-12769/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-12770/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-12771/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-12826/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-13143/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-13974/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-14416/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-15393/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-UNKNOWN/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-UNKNOWN/ANY/0002.patch
editKernelLocalversion "-dos.p118"
cd "$DOS_BUILD_BASE"