#!/bin/bash
cd "$DOS_BUILD_BASE""kernel/google/msm-4.14"
git apply $DOS_PATCHES_LINUX_CVES/0001-LinuxIncrementals/4.14/4.14.0278-0279.patch --exclude=Makefile
git apply $DOS_PATCHES_LINUX_CVES/0001-LinuxIncrementals/4.14/4.14.0283-0284.patch --exclude=Makefile
git apply $DOS_PATCHES_LINUX_CVES/0003-syzkaller-Misc/ANY/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/0003-syzkaller-Misc2/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening/4.14/0057.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening/4.14/0058.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening/4.14/0059.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening/4.14/0060.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening/4.14/0061.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening/4.14/0062.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening/4.14/0063.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening/4.14/0064.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening/4.14/0065.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening/4.14/0066.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening/4.14/0067.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening/4.14/0068.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening/4.14/0069.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening/4.14/0070.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening/4.14/0071.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening/4.14/0072.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening/4.14/0073.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening/4.14/0074.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening/4.14/0075.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening/4.14/0076.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening/4.14/0077.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening/4.14/0078.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening/4.14/0079.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening/4.14/0081.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening/4.14/0082.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening/4.14/0083.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening/4.14/0084.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening/4.14/0085.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-7837/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-3695/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-18232/4.14/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-5897/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-9415/ANY/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-20855/^4.18/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-3874/ANY/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-9444/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-10520/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-11191/^5.0/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-11487/4.14/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-12378/^5.1.5/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-12455/^5.1.5/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-12456/^5.1.5/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-15291/4.14/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-16921/^4.16/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-18786/4.14/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19051/4.14/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19068/4.14/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19602/^5.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-20908/^5.2/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-15780/^5.8/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-16119/^5.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-29372/^5.7/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-BleedingToothExtras/^5.10/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-1963/ANY/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-3493/^5.10/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-4034/4.14/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-4159/4.14/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-28039/^5.11/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-33655/^5.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-33656/4.14/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-0494/4.14/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-0812/4.14/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-1012/4.14/0010.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-1184/4.14/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-1204/4.14/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-1204/4.14/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-1204/4.14/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-1204/4.14/0009.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-1204/4.14/0010.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-1419/4.14/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-1652/4.14/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-1679/4.14/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-1729/4.14/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-1734/4.14/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-1836/4.14/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-1966/4.14/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-1974/4.14/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-1975/4.14/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-2153/4.14/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-2153/4.14/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-2318/4.14/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-2588/4.14/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-2639/4.14/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-2991/4.14/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-3028/4.14/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-3061/^5.18/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-3239/4.14/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-3521/^6.0/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-3542/3.8-^6.0/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-3545/^5.19/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-3565/4.14/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-3577/4.14/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-3586/4.14/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-3594/4.14/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-3621/4.14/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-3629/4.14/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-3635/4.14/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-3646/4.14/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-3649/4.14/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-20369/4.14/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-20382/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-25724/ANY/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-26365/4.14/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-27950/^5.16/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-32981/4.14/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-33740/4.14/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-33741/4.14/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-33742/4.14/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-33744/4.14/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-36123/4.14/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-36879/4.14/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-36946/4.14/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-39188/4.14/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-39842/4.14/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-40307/4.14/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-40768/4.14/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-42703/4.14/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-42895/^6.1/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-43750/4.14/0002.patch
editKernelLocalversion "-dos.p124"
cd "$DOS_BUILD_BASE"