#!/bin/bash
if cd "$DOS_BUILD_BASE""kernel/google/msm-4.14"; then
git apply $DOS_PATCHES_LINUX_CVES/0003-syzkaller-Misc/ANY/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/0005-Graphene-Deny_USB/4.14/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-allocsize/4.14/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-allocsize/4.14/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-allocsize/4.14/0011.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-allocsize/4.14/0016.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-allocsize/4.14/0021.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-bugon/4.14/0010.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-fortify/4.14/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-misc/4.14/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-misc/4.14/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-misc/4.14/0010.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-misc/4.14/0018.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-misc/4.14/0021.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-random/4.14/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-random/4.14/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-random/4.14/0012.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-random/4.14/0017.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-ro/4.14/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-ro/4.14/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-ro/4.14/0012.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-ro/4.14/0017.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-ro/4.14/0028.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-ro/4.14/0030.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-ro/4.14/0032.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-ro/4.14/0038.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-sanitize/4.14/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-sanitize/4.14/0009.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-sanitize/4.14/0015.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-sanitize/4.14/0017.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-slab/4.14/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-slab/4.14/0010.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-slab/4.14/0014.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-slab/4.14/0018.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-unused/4.14/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-unused/4.14/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-7837/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-3695/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-5754/^4.19/0157.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-18232/4.14/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-5897/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-5995/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-9415/ANY/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-20855/^4.18/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-3874/^5.1/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-9444/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-10520/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-11191/^5.0/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-11487/4.14/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-12378/^5.1.5/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-12455/^5.2/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-12456/^5.1.5/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-15291/4.14/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-16921/^4.16/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-18786/4.14/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19051/4.14/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19068/4.14/0002.patch
#git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19252/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19602/^5.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-20908/^5.2/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-15780/^5.8/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-16119/^5.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-29372/^5.7/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-BleedingToothExtras/^5.10/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-1963/ANY/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-3493/^5.10/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-28039/^5.11/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-33624/4.19/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-46912/^5.12/0001.patch
#git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-46921/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-46958/^5.12/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-46998/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-46999/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-47058/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-47173/4.14/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-47209/^5.15/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-47234/^5.13/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-47266/^5.13/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-47346/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-47430/^5.15/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-47472/4.14/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-47583/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-47616/^5.16/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-47618/^5.16/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-3061/^5.18/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-4382/^6.2/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-20382/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-27950/^5.16/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-48671/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-48697/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-48781/^5.17/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-48825/^5.17/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-1077/4.19/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-1989/4.14/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-3777/^6.5/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-4881/4.19/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-6270/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-6606/4.19/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-21657/4.14/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-23000/^5.16/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-28554/ANY/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-31083/^6.5/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-33070/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-35823/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-43550/4.14/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-46838/4.19/0002.patch
#git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-51043/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52429/4.19/0007.patch
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
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52486/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52504/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52583/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52594/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52595/^6.6/0001.patch
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
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52623/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52650/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52670/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52685/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52693/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52699/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52707/^6.2/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52741/^6.2/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52746/^6.2/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52803/4.19/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52847/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52880/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52884/^6.5/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-0340/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-0607/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-1086/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-21468/ANY/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-22099/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-23849/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-24855/^6.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-24857/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-24861/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-25739/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26600/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26624/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26625/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26633/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26635/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26636/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26642/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26645/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26651/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26663/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26675/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26679/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26685/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26696/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26697/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26704/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26720/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26735/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26744/4.19/0002.patch
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
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26805/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26816/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26825/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26839/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26840/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26845/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26859/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26874/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26875/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26880/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26889/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26894/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26900/^6.8/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26901/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26917/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26920/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26934/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26956/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26957/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26961/^6.7/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26965/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26966/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26972/^6.8/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26973/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26981/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26993/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26999/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27000/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27001/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27008/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27009/^6.9/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27013/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27028/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27033/^6.8/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27059/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27074/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27075/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27388/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27393/^6.9/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27396/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27398/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27399/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27401/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27405/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27410/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27412/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27413/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27416/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27419/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27420/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27421/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27426/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27427/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27428/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27429/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27430/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-34027/^6.9/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35789/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35806/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35807/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35821/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35822/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35824/^6.8/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35825/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35828/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35830/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35849/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35877/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35879/^6.9/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35886/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35915/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35922/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35930/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35933/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35935/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35936/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35944/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35947/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35950/^6.9/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35954/^6.9/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35955/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35962/^6.9/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35969/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35978/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35982/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35997/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-36004/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-36016/4.19/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-36017/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-36286/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-36484/4.19/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-36886/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-36919/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-36933/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-36934/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-36940/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-36941/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-36946/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-36950/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-36954/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-36959/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-36960/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-36964/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-37078/4.19/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-37353/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-37356/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-38381/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-38549/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-38558/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-38559/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-38560/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-38565/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-38567/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-38578/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-38579/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-38589/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-38596/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-38599/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-38601/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-38612/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-38613/4.19/0003.patch
#git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-38618/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-38619/4.19/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-38621/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-38627/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-38633/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-38634/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-38637/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-38659/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-38780/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-39276/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-39292/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-39296/^6.9/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-39475/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-39480/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-39487/4.19/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-39489/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-39499/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-39501/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-39509/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-40902/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-40904/3.5-^6.10/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-40912/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-40917/^6.10/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-40923/^6.10/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-40941/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-40942/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-40943/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-40954/^6.10/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-40959/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-40968/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-40974/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-40978/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-40981/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-40984/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-40987/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-40988/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-40996/^6.10/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-41006/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-41012/4.19/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-41014/^6.10/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-41015/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-41016/^6.10/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-41017/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-41035/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-41041/^6.10/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-41044/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-41059/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-41063/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-41068/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-41072/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-41081/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-41089/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-41095/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-41097/4.12-^6.10/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-42077/^6.10/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-42089/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-42090/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-42094/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-42096/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-42097/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-42101/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-42102/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-42105/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-42106/4.12-^6.10/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-42115/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-42143/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-42148/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-42154/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-42157/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-42223/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-42224/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-12819/4.14/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52601/4.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27424/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27425/4.19/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-42104/4.19/0002.patch
editKernelLocalversion "-dos.p385"
else echo "kernel_google_msm-4.14 is unavailable, not patching.";
fi;
cd "$DOS_BUILD_BASE"
