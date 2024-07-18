#!/bin/bash
if cd "$DOS_BUILD_BASE""kernel/oneplus/sm8350"; then
git apply $DOS_PATCHES_LINUX_CVES/0003-syzkaller-Misc/ANY/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/0008-Graphene-Kernel_Hardening-misc/ANY/0015.patch
git apply $DOS_PATCHES_LINUX_CVES/0009-rfc4941bis/ANY/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-3695/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-0627/ANY/0002.patch
#git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-5873/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-9415/ANY/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-9444/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-15291/5.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-18786/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19068/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-11146/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-16119/^5.10/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-16119/^5.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-16120/^5.7/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-BleedingToothExtras/^5.10/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-3669/^5.14/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-28039/^5.11/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-39633/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-46912/^5.12/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-46958/^5.12/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-46959/5.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-46982/^5.13/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-47007/^5.12/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-47049/^5.12/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-47173/5.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-47209/^5.15/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-47228/^5.13/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-47234/^5.13/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-47266/5.4/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-47381/^5.14/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-47413/^5.15/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-47430/^5.15/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-47472/^5.15/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-47488/5.3-^5.15/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-47490/^5.15/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-47535/^5.16/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-47599/^5.15/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-47616/^5.16/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-47618/^5.16/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-0480/4.9-^5.14/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-3061/^5.18/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-3108/^5.16/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-3625/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-3903/^6.0/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-4662/5.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-20158/^5.15/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-27950/^5.16/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-48627/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-48655/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-48663/^6.0/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-48713/^5.17/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-48720/^5.17/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-48772/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-48781/^5.17/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-48785/^5.17/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-48812/^5.17/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-48825/^5.17/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-OctWirelessASB/^5.15/0009.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-0160/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-0386/^6.2/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-1989/5.4/0009.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-2166/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-3777/^6.5/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-4133/^6.3/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-4134/^6.3/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-4623/4.12-^6.5/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-4881/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-6270/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-7042/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-23000/^5.16/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-31083/^6.5/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-35826/^6.3/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-47233/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52429/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52434/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52435/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52437/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52486/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52504/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52561/^6.5/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52583/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52585/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52594/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52595/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52597/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52598/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52599/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52600/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52602/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52603/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52604/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52605/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52606/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52607/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52615/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52617/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52619/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52620/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52623/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52637/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52650/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52656/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52670/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52699/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52741/^6.2/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52773/^6.7/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52803/5.4/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52817/5.4/0005.patch
#git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52879/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52880/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52882/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52884/^6.5/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-0340/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-0607/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-0841/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-1086/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-22099/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-23849/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-24855/^6.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-24857/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-24861/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-24863/5.4/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-25739/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26581/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26595/^6.7/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26598/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26600/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26602/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26606/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26615/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26624/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26625/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26635/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26636/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26642/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26643/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26645/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26651/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26654/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26663/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26664/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26671/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26673/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26675/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26676/^6.8/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26679/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26684/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26685/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26687/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26696/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26697/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26702/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26704/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26720/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26722/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26735/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26736/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26748/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26749/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26751/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26752/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26754/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26760/^6.8/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26763/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26766/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26771/^6.8/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26772/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26773/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26777/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26778/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26779/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26780/^6.8/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26788/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26790/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26791/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26793/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26801/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26804/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26805/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26810/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26816/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26817/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26825/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26835/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26839/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26840/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26845/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26851/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26852/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26855/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26859/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26862/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26863/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26874/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26875/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26878/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26880/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26883/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26884/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26889/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26894/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26900/^6.8/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26901/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26904/5.4/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26908/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26910/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26917/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26920/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26926/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26931/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26934/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26935/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26937/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26956/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26957/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26961/^6.7/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26965/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26966/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26969/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26972/^6.8/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26973/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26976/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26981/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26984/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26993/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26994/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26999/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27000/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27001/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27008/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27009/^6.9/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27013/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27020/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27024/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27025/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27028/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27030/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27033/^6.8/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27038/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27043/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27044/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27046/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27059/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27065/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27074/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27075/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27076/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27077/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27078/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27388/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27393/^6.9/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27395/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27396/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27398/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27399/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27401/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27405/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27410/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27412/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27413/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27414/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27416/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27417/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27419/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27420/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27421/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27426/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27427/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27428/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27429/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27430/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27436/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27437/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-31076/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-34027/^6.9/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35789/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35805/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35806/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35807/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35812/^6.9/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35821/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35822/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35823/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35824/^6.8/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35825/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35828/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35830/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35833/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35847/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35849/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35852/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35853/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35854/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35855/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35876/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35877/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35879/^6.9/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35886/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35892/^6.9/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35893/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35897/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35898/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35899/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35900/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35902/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35915/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35922/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35925/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35930/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35933/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35935/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35936/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35944/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35947/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35950/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35954/^6.9/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35955/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35960/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35962/^6.9/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35969/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35973/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35978/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35982/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35984/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35997/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-36004/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-36006/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-36007/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-36016/5.4/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-36017/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-36020/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-36270/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-36286/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-36288/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-36883/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-36886/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-36902/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-36904/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-36905/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-36909/^6.8/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-36919/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-36933/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-36934/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-36940/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-36941/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-36946/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-36950/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-36954/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-36959/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-36960/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-36964/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-36971/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-36974/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-36978/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-37078/5.4/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-37353/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-37356/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-38381/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-38549/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-38552/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-38555/^6.9/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-38558/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-38559/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-38560/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-38565/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-38567/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-38578/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-38579/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-38583/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-38587/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-38589/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-38596/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-38598/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-38599/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-38601/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-38607/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-38612/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-38613/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-38618/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-38619/5.4/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-38621/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-38627/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-38633/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-38634/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-38637/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-38659/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-38661/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-38780/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-39276/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-39292/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-39296/^6.9/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-39301/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-39471/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-39475/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-39480/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-39487/5.4/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-39488/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-39489/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-39495/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-39499/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-39501/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-39502/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-39505/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-39506/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-39509/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-40901/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-40902/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-40904/3.5-^6.10/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-40905/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-40911/^6.10/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-40912/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-40917/^6.10/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-40923/^6.10/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-40932/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-40934/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-40941/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-40942/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-40943/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-40945/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-40954/^6.10/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-40958/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-40959/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-40960/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-40961/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-40963/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-40968/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-40974/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-40978/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-40980/5.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-40981/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-40984/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-40987/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-40988/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-40993/^6.1/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-40996/^6.10/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-41006/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-47472/5.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-47490/5.4/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-48783/^5.17/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2023-52601/5.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26750/^6.8/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-26812/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27424/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-27425/5.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2024-35812/5.4/0006.patch
editKernelLocalversion "-dos.p446"
else echo "kernel_oneplus_sm8350 is unavailable, not patching.";
fi;
cd "$DOS_BUILD_BASE"
