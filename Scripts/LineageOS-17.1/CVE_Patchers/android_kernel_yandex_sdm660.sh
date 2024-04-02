#!/bin/bash
if cd "$DOS_BUILD_BASE""kernel/yandex/sdm660"; then
git apply $DOS_PATCHES_LINUX_CVES/0001-LinuxIncrementals/4.4/4.4.0209-0210.patch --exclude=Makefile
git apply $DOS_PATCHES_LINUX_CVES/0001-LinuxIncrementals/4.4/4.4.0233-0234.patch --exclude=Makefile
git apply $DOS_PATCHES_LINUX_CVES/0001-LinuxIncrementals/4.4/4.4.0242-0243.patch --exclude=Makefile
git apply $DOS_PATCHES_LINUX_CVES/0001-LinuxIncrementals/4.4/4.4.0251-0252.patch --exclude=Makefile
git apply $DOS_PATCHES_LINUX_CVES/0001-LinuxIncrementals/4.4/4.4.0288-0289.patch --exclude=Makefile
git apply $DOS_PATCHES_LINUX_CVES/0001-LinuxIncrementals/4.4/4.4.0298-0299.patch --exclude=Makefile
git apply $DOS_PATCHES_LINUX_CVES/0001-LinuxIncrementals/4.4/4.4.0300-0301.patch --exclude=Makefile
git apply $DOS_PATCHES_LINUX_CVES/0002-Misc_Fixes/4.4/0009.patch
git apply $DOS_PATCHES_LINUX_CVES/0002-Misc_Fixes-Steam/^6.0/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-allocsize/4.9/0015.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-allocsize/4.9/0020.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-bugon/4.4/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-bugon/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-canaries/4.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-canaries/4.4/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-misc/4.4/0014.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-misc/4.4/0016.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-random/4.9/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-ro/4.9/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-ro/4.9/0027.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-ro/4.9/0031.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-slab/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-slab/4.4/0012.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-slab/4.4/0016.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-slub/4.4/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/0009-rfc4941bis/ANY/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-7837/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-1583/^4.6/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-6187/^4.7/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-8394/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-10153/4.9/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-16USB/ANY/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-16USB/ANY/0009.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-0610/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-9059/4.9/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-9211/4.9/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-13218/4.4/0019.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-13693/^4.12.9/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-13694/^4.12.9/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-16644/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-17052/4.9/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-18174/^4.10/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-18204/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-1000252/^4.13/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-5897/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-8043/4.4/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-9415/ANY/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-10323/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-13094/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-21008/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-0146/4.4/0013.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-0146/4.4/0014.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-8912/^5.0/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-10220/4.4/0012.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-10220/4.4/0013.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-12378/^5.1.5/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-12456/^5.1.5/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-12614/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-14763/^5.1/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-14896/4.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-14901/4.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-15217/4.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-15220/4.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-15221/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-16232/4.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-16233/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-16234/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-16994/4.9/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-17351/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19051/4.4/0012.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19051/^5.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19054/4.4/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19057/4.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19060/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19061/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19062/4.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19063/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19073/4.4/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19074/4.4/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19227/4.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19318/4.4/0005.patch
#git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19319/4.4/0017.patch
#git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19319/4.4/0018.patch
#git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19319/4.4/0019.patch
#git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19319/4.4/0020.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19332/4.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19338/4.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19447/4.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19448/4.4/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19813/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19816/4.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19947/4.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19965/4.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-20096/4.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-20810/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-20812/4.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-0009/4.4/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-0255/4.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-0404/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-0423/4.4/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-0427/4.4/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-0429/4.4/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-0429/4.4/0009.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-0429/4.4/0010.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-0429/4.4/0011.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-0429/4.4/0013.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-0429/4.4/0014.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-0429/^4.14/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-0432/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-0433/4.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-0433/4.4/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-0433/4.4/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-0433/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-0444/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-0465/4.4/0009.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-0543/4.4/0021.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-0543/4.4/0022.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-0543/4.4/0023.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-0543/4.4/0024.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-0543/4.4/0025.patch
#git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-1749/4.4/0009.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-2732/4.4/0013.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-3702/4.4/0026.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-3702/4.4/0027.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-3702/4.4/0028.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-3702/4.4/0029.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-3702/4.4/0030.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-8428/4.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-8647/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-8648/4.4/0019.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-8648/4.4/0020.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-8648/4.4/0021.patch
#git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-8992/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-9383/4.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-10135/4.4/0010.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-10135/4.4/0011.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-10135/4.4/0012.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-10711/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-10732/4.4/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-10766/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-10942/4.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-11160/4.4/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-11239/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-11261/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-11262/ANY/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-11267/ANY/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-11267/ANY/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-11282/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-11286/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-11494/4.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-11565/4.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-11608/4.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-11609/4.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-11668/4.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-12352/3.6-^5.10/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-12352/ANY/0009.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-12652/4.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-12653/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-12654/4.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-12656/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-12656/4.4/0009.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-12769/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-12770/4.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-12771/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-12826/4.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-13143/4.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-13974/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-14305/4.4/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-14331/4.4/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-14351/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-14381/4.4/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-14386/3.10-^4.4/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-14390/4.4/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-14416/4.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-15393/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-15436/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-15437/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-16119/4.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-16119/^5.10/0002.patch
#git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-16166/4.4/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-24490/4.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-24588/4.4/0019.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-24588/4.4/0020.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-25211/4.4/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-25212/4.4/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-25284/4.4/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-25285/4.4/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-25643/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-25645/4.4/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-25668/4.4/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-25669/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-25670/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-25671/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-25672/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-25673/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-26088/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-26139/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-26147/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-26555/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-27066/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-27068/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-27784/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-27815/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-27825/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-28097/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-28915/4.4/0013.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-28915/4.4/0014.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-28915/4.4/0015.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-28974/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-29370/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-29374-alt/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-29374-alt/4.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-29374-alt/4.4/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-29374-alt/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-29568/4.4/0016.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-29568/4.4/0017.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-29568/4.4/0018.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-29568/4.4/0019.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-29568/4.4/0020.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-29569/4.4/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-29661/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-35508/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-35519/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-36158/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-36312/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-36516/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-36557/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-36694/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-UNKNOWN/ANY/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-0399/4.4/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-0512/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-0605/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-0695/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-0936/ANY/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-0936/ANY/0011.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-0937/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-0961/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-1048/4.1-^5.9/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-1955/ANY/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-1963/ANY/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-3178/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-3347/4.4/0046.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-3347/4.4/0047.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-3347/4.4/0048.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-3347/4.4/0049.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-3347/4.4/0050.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-3347/4.4/0051.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-3347/4.4/0052.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-3347/4.4/0053.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-3347/4.4/0054.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-3347/4.4/0055.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-3428/4.4/0012.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-3428/4.4/0013.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-3483/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-3542/4.9/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-3564/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-3573/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-3609/4.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-3612/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-3653/4.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-3655/4.4/0011.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-3655/^5.13/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-3659/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-3679/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-3715/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-3732/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-3753/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-3760/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-3772/4.4/0020.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-3772/4.4/0021.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-3896/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-4002/4.4/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-4149/4.4/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-4157/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-4202/4.4/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-4202/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-20261/4.4/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-20292/4.9/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-20320/4.9/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-20320/4.9/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-20321/4.4/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-20322/4.4/0009.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-21781/4.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-23133/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-23134/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-26930/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-26931/4.4/0010.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-26931/4.4/0011.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-26931/4.4/0012.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-26932/4.4/0016.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-26932/4.4/0017.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-26932/4.4/0018.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-26932/4.4/0019.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-26932/4.4/0020.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-27363/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-27365/4.4/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-27365/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-28038/4.4/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-28038/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-28660/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-28688/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-28713/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-28715/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-28964/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-28972/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-29154/4.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-30002/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-31916/4.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-32399/4.4/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-33656/4.4/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-33909/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-34693/4.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-34981/4.4/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-37576/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-37576/4.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-38160/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-38204/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-38205/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-38208/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-39634/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-39685/4.4/0010.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-39685/4.4/0011.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-39685/4.4/0012.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-39714/4.4/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-40490/3.9-^5.14/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-42008/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-43976/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-44879/^5.16/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-45485/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-45486/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-45868/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-46906/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-46909/^5.12/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-46912/^5.12/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-46932/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-46936/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-46939/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-46946/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-46955/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-46966/4.4/0005.patch
#git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-47006/4.9/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-47058/^5.12/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-47086/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-47114/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-47117/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-47118/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-47121/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-47122/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-47142/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-47145/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-47146/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-47149/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-47153/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-47166/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-47168/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-47169/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-47171/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-47173/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-47180/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-0435/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-0487/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-0494/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-0617/4.4/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-0617/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-0850/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-1011/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-1016/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-1184/4.4/0014.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-1198/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-1353/4.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-1516/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-1652/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-1679/^5.19/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-1729/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-1734/4.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-1836/4.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-1975/4.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-2153/^5.17/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-2318/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-2380/4.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-2588/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-2639/4.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-2663/4.4/0011.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-2663/4.4/0012.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-2978/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-3028/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-3061/^5.18/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-3111/4.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-3424/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-3524/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-3542/3.8-^6.0/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-3565/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-3594/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-3621/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-3628/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-3629/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-3635/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-3649/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-4378/4.4/0015.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-4662/4.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-20009/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-20141/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-20148/^5.15/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-20421/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-20422/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-20423/4.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-23039/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-23042/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-24958/4.4/0015.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-24958/4.4/0016.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-25258/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-25654/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-26966/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-27223/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-27950/^5.16/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-28356/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-28390/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-30594/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-32981/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-33740/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-33744/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-36123/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-36280/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-36879/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-36946/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-39188/4.4/0010.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-39842/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-40768/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-41849/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-41850/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-41858/4.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-42703/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-42895/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-42896/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-42896/4.4/0009.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-42896-extra/4.4/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-43750/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-45887/4.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-45919/4.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-45934/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-47929/4.4/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-48619/4.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-Misc4/4.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-0045/4.4/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-0394/4.4/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-0458/4.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-0590/4.4/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-0615/4.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-1073/4.4/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-1074/4.4/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-1095/4.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-1118/4.4/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-1206/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-1380/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-1513/4.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-1637/4.9/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-1670/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-1989/4.4/0011.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-1989/^6.3/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-1990/4.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-2162/4.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-2194/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-2248/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-2269/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-2985/4.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-3090/4.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-3106/4.4/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-3141/4.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-3159/4.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-3161/4.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-3212/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-3567/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-3772/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-3776/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-4128/4.4/0022.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-4128/4.4/0023.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-4128/4.4/0024.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-4385/4.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-4387/4.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-4459/4.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-4623/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-6270/^6.8/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-7192/4.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-20941/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-21656/4.4/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-23454/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-23455/4.4/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-23559/4.4/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-26545/4.4/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-28328/4.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-28584/4.4/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-28772/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-30772/4.4/0008.patch
#git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-31084/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-31085/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-32269/4.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-33059/ANY/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-33110/ANY/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-33120/ANY/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-34256/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-35001/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-35824/4.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-39192/4.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-39193/4.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-39194/4.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-40283/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-42752/^6.5/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-42754/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-45862/4.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-45863/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-46343/4.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-51780/4.4/0009.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-51781/4.4/0009.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-51782/4.4/0009.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52436/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52444/^6.7/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52445/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52449/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52469/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52475/4.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52478/4.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52507/4.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52566/4.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52594/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52598/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52599/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52602/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52603/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52604/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52605/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52615/4.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-0340/^6.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-0639/4.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-0775/4.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-1086/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-21468/ANY/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-22099/^6.8/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-24855/^6.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-24861/^6.8/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26600/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26624/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26625/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26633/4.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26635/4.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26651/^6.8/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-0429/4.4/0012.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-24586/4.4/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-29660/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-37159/4.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52601/4.4/0008.patch
editKernelLocalversion "-dos.p550"
else echo "kernel_yandex_sdm660 is unavailable, not patching.";
fi;
cd "$DOS_BUILD_BASE"
