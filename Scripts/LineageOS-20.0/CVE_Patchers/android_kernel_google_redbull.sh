#!/bin/bash
if cd "$DOS_BUILD_BASE""kernel/google/redbull"; then
git apply $DOS_PATCHES_LINUX_CVES/0003-syzkaller-Misc/ANY/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/0003-syzkaller-Misc2/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/0005-Graphene-Deny_USB/4.19/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-allocsize/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-allocsize/4.19/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-allocsize/4.19/0012.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-allocsize/4.19/0017.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-allocsize/4.19/0022.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-bugon/4.19/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-bugon/4.19/0011.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-fortify/4.19/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-misc/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-misc/4.19/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-misc/4.19/0011.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-misc/4.19/0019.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-random/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-random/4.19/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-random/4.19/0013.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-random/4.19/0018.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-ro/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-ro/4.19/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-ro/4.19/0013.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-ro/4.19/0018.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-ro/4.19/0021.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-ro/4.19/0024.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-ro/4.19/0035.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-sanitize/4.19/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-sanitize/4.19/0010.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-sanitize/4.19/0016.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-sanitize/4.19/0018.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-slab/4.19/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-slab/4.19/0011.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-slab/4.19/0015.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-slab/4.19/0019.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-7837/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-3695/ANY/0001.patch
#git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-5873/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-5897/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-9415/ANY/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-3874/^5.1/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-9444/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-11191/^5.0/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-12378/^5.1.5/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-12379/^5.2/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-12380/^5.2/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-12381/^5.2/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-12455/^5.2/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-12456/^5.1.5/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-15291/4.19/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-18786/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19051/4.19/0010.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19068/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19602/^5.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-20908/^5.2/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-15780/^5.8/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-16119/^5.10/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-16119/^5.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-16120/^5.7/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-29372/^5.7/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-36782/^5.12/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-36783/^5.12/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-BleedingToothExtras/^5.10/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-1963/ANY/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-3493/^5.10/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-28039/^5.11/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-33630/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-46912/^5.12/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-46958/^5.12/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-46959/4.19/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-47082/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-47173/4.19/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-47209/^5.15/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-2873/4.19/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-3061/^5.18/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-3104/^5.18/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-3108/^5.16/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-3424/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-3545/4.19/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-3625/^5.19/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-3707/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-3903/^6.0/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-4382/^6.2/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-4662/4.19/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-20382/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-20571/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-27950/^5.16/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-36280/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-40982/4.19/0011.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-40982/4.19/0012.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-40982/4.19/0013.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-40982/4.19/0014.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-40982/4.19/0015.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-40982/4.19/0016.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-40982/4.19/0017.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-40982/4.19/0018.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-40982/4.19/0019.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-40982/4.19/0020.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-40982/4.19/0021.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-40982/4.19/0022.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-40982/4.19/0023.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-40982/4.19/0024.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-40982/4.19/0025.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-40982/4.19/0026.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-40982/4.19/0027.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-40982/4.19/0028.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-40982/4.19/0029.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-40982/4.19/0030.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-40982/4.19/0031.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-45886/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-45887/4.19/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-45919/4.19/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-45934/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-47929/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-48627/4.19/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-48639/^6.0/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-48663/^6.0/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-0030/^4.20/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-0045/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-0386/^6.2/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-0394/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-0458/4.19/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-0459/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-0461/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-0590/4.19/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-0615/4.19/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-1073/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-1074/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-1077/4.19/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-1078/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-1118/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-1206/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-1281/4.19/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-1380/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-1513/4.19/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-1670/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-1855/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-1859/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-1989/4.19/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-1989/4.19/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-1990/4.19/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-1998/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-2002/3.10-^6.3/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-2007/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-2162/4.19/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-2194/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-2248/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-2269/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-2483/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-2985/4.19/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-3090/4.19/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-3117/4.19/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-3141/4.19/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-3161/4.19/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-3212/4.19/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-3220/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-3358/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-3567/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-3609/4.19/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-3772/4.19/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-3776/4.19/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-3777/^6.5/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-4128/4.19/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-4128/4.19/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-4128/4.19/0009.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-4132/4.6-^6.2/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-4132/4.19/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-4133/^6.3/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-4134/^6.3/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-4244/4.19/0025.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-4622/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-4623/4.12-^6.5/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-4921/4.19/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-6270/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-6606/4.19/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-6932/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-7042/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-7192/4.19/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-21656/4.19/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-22386/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-23000/^5.16/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-23454/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-23455/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-23559/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-24851/ANY/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-25775/4.19/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-26545/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-28328/4.19/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-28541/qca-wifi-host-cmn/0001.patch --directory=drivers/staging/qca-wifi-host-cmn
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-28553/qca-wifi-host-cmn/0001.patch --directory=drivers/staging/qca-wifi-host-cmn
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-28554/ANY/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-30772/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-31083/^6.5/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-31084/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-31085/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-32233/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-32269/4.19/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-33106/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-33107/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-33114/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-34256/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-34324/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-35001/4.19/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-35788/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-35823/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-35824/4.19/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-35828/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-39189/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-39192/4.19/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-39193/4.19/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-39194/4.19/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-40283/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-42752/4.19/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-42754/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-42755/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-43513/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-45862/4.19/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-45863/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-45871/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-46343/4.19/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-47233/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-51042/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-51043/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-51780/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-51781/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-51782/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52436/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52437/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52439/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52443/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52444/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52445/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52449/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52464/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52469/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52470/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52475/4.19/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52477/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52478/4.19/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52486/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52504/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52507/4.19/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52510/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52527/4.19/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52528/4.19/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52566/4.19/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52574/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52583/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52594/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52595/^6.6/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52597/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52598/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52599/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52600/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52602/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52603/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52604/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52605/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52606/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52607/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52609/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52615/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52619/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52620/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52623/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52646/4.19/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52650/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-0340/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-0607/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-0639/4.19/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-0775/4.19/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-21468/ANY/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-22099/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-23849/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-24855/^6.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-24857/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-24861/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-25739/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26600/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26602/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26606/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26615/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26624/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26625/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26633/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26635/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26636/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26642/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26643/^6.8/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26645/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26651/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26654/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26663/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26664/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26671/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26675/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26679/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26696/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26697/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26704/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26720/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26722/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26735/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26744/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26751/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26752/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26754/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26760/^6.8/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26763/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26772/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26773/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26777/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26778/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26779/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26791/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26793/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26801/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26805/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26816/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26817/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26825/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26839/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26840/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26845/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26851/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26852/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26857/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26859/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26861/^6.8/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26874/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26875/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26880/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26883/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26884/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26889/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26894/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26900/^6.8/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26901/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26920/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26931/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26934/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26950/^6.8/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26951/^6.8/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26956/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26957/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26961/^6.7/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26965/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26966/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26969/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26972/^6.8/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26973/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26976/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26981/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26984/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26993/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26994/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26999/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27000/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27001/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27008/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27009/^6.9/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27013/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27024/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27028/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27033/^6.8/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27046/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27059/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27074/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27075/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27077/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27078/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27388/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52601/4.19/0002.patch
editKernelLocalversion "-dos.p372"
else echo "kernel_google_redbull is unavailable, not patching.";
fi;
cd "$DOS_BUILD_BASE"
