#!/bin/bash
cd "$DOS_BUILD_BASE""kernel/asus/fugu"
git apply $DOS_PATCHES_LINUX_CVES/0002-Misc_Fixes/ANY/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/0003-syzkaller-Misc/ANY/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/0003-syzkaller-Misc/ANY/0009.patch
git apply $DOS_PATCHES_LINUX_CVES/0003-syzkaller-Misc2/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/0003-syzkaller-Misc2/ANY/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/0006-Copperhead-Kernel_Hardening/3.10/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/0006-Copperhead-Kernel_Hardening/3.10/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/0006-Copperhead-Kernel_Hardening/3.10/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/0006-Copperhead-Kernel_Hardening/3.10/0009.patch
git apply $DOS_PATCHES_LINUX_CVES/0006-Copperhead-Kernel_Hardening/3.10/0010.patch
git apply $DOS_PATCHES_LINUX_CVES/0006-Copperhead-Kernel_Hardening/3.10/0011.patch
git apply $DOS_PATCHES_LINUX_CVES/0006-Copperhead-Kernel_Hardening/3.10/0012.patch
git apply $DOS_PATCHES_LINUX_CVES/0006-Copperhead-Kernel_Hardening/3.10/0013.patch
git apply $DOS_PATCHES_LINUX_CVES/0006-Copperhead-Kernel_Hardening/3.10/0014.patch
git apply $DOS_PATCHES_LINUX_CVES/0006-Copperhead-Kernel_Hardening/3.10/0015.patch
git apply $DOS_PATCHES_LINUX_CVES/0006-Copperhead-Kernel_Hardening/3.10/0016.patch
git apply $DOS_PATCHES_LINUX_CVES/0006-Copperhead-Kernel_Hardening/3.10/0017.patch
git apply $DOS_PATCHES_LINUX_CVES/0007-Accelerated_AES/3.10+/0011.patch
git apply $DOS_PATCHES_LINUX_CVES/0007-Accelerated_AES/3.10+/0012.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2013-2898/^3.11/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2013-2929/^3.12.2/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2013-2930/^3.12.2/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2013-4129/^3.10.3/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2013-4129/^3.10.3/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2013-4345/^3.11.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2013-4470/^3.12/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2013-4587/^3.12.5/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2013-6367/^3.12.5/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2013-6368/^3.12.5/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2013-6376/^3.12.5/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2013-6378/^3.12.1/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2013-6380/^3.12.1/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2013-6381/^3.12.1/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2013-7026/^3.12.2/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2013-7339/^3.12.8/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-0038/^3.13.2/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-0069/^3.13.5/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-0077/^3.13.10/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-0100/^3.13.6/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-0101/^3.13.6/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-0155/^3.14.1/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-0206/^3.15.1/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-1438/^3.12.8/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-1446/^3.12.8/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-1690/^3.12.8/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-1737/^3.14.3/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-1738/^3.14.3/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-1739/^3.13.6/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-2039/^3.13.5/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-2309/^3.13.6/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-2523/^3.13.6/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-2678/^3.14/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-3181/^3.16.3/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-3184/^3.16.2/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-3185/^3.16.2/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-3186/^3.16.3/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-3601/^3.16.1/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-3611/^3.17.2/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-3645/^3.12/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-3673/^3.17.2/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-3687/^3.17.2/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-3688/^3.17.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-4171/^3.15.1/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-4171/^3.15.1/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-4508/^3.15.1/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-4608/^3.15.2/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-4652/^3.15.2/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-4653/^3.15.2/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-4656/^3.15.2/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-4656/^3.15.2/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-4667/^3.15.2/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-4699/^3.15.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-4943/^3.15.6/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-5077/^3.15.8/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-5471/^3.16.1/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-7145/^3.16.3/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-7841/^3.17.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-7843/^3.17.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-7975/^3.17/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-8134/^3.18/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-8160/^3.18/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-8173/3.9-^3.13/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-8369/^3.17.2/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-8884/^3.17.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-9419/^3.18.1/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-9420/^3.18.1/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-9584/^3.18.2/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-9683/^3.18.2/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-9715/^3.14.5/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-9728/^3.18.2/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-9892/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-9900/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-9922/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-9922/3.10/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-0275/^4.1/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-1339/^4.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-1420/3.2-^3.19.1/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-1421/^3.18.8/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-2041/^3.19/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-2042/^3.19/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-2150/^3.19.1/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-2830/^3.19.2/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-3331/^3.19.3/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-4177/^4.0.5/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-5156/^4.2/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-5257/^4.2.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-5283/^4.2.3/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-5307/^4.2.6/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-6252/^4.1.5/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-6526/^4.0.2/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-6937/^4.2.3/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-7515/^4.4/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-7550/^4.3.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-7566/^4.4.1/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-7799/^4.2.3/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-7799/^4.2.3/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-8019/3.10/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-8215/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-8569/^4.3.3/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-8709/^4.4.1/0001.patch
#git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-8746/^4.2.2/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-8812/^4.5/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-8944/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-8955/^4.1/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-8967/^4.0/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-9289/^4.1.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-0758/^4.6/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-2085/^4.5/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-2117/^4.5.2/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-2185/^4.5.1/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-2186/^4.5.1/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-2187/^4.5.2/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-2188/^4.5.1/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-2188/^4.5.1/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-2384/^4.5/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-2438/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-2475/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-2543/^4.4.1/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-2544/^4.4.1/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-2545/^4.4.1/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-2549/^4.4.1/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-2782/^4.5/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-3070/^4.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-3136/^4.5.1/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-3137/^4.5.1/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-3138/^4.5.1/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-3140/^4.5.1/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-3689/^4.5.1/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-3857/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-4485/^4.5.5/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-4580/^4.5.5/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-4913/^4.5.5/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-5244/^4.6.3/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-5828/^4.6.3/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-5829/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-6480/^4.7/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-7097/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-7097/3.10/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-7117/^4.5.2/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-8453/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-8464/3.10/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-8633/^4.8.7/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-8646/^4.3.6/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-8650/^4.8.11/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-9083/^4.8.11/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-9178/^4.7.5/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-9576/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-9604/^4.11/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-9794/^4.7/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-10208/3.10-^3.16/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-16USB/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-16USB/ANY/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-16USB/ANY/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-0449/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-0537/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-0571/3.10/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-0573/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-0627/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-0630/3.10/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-0630/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-0648/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-0706/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-0710/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-0786/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-0791/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-0824/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-0861/3.10/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-0862/3.10/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-2618/3.10/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-2671/^4.10.8/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-5669/^4.9.12/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-5972/ANY/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-6074/^4.9.11/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-6345/^4.9.13/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-6348/^4.9.13/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-6951/^3.14.79/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-7184/^4.10.6/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-7184/^4.10.6/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-7261/^4.10.5/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-7308/^4.10.6/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-7472/^4.10.13/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-7487/^4.11.1/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-7541/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-7645/^4.10.11/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-8824/^4.14.3/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-8890/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-8925/^4.10.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-9242/^4.11.3/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-9984/^4.11.7/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-10663/3.10/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-11089/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-11090/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-11176/^4.11.9/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-11473/^4.12.2/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-11600/3.10/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-12153/3.2-^3.16/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-12762/^4.12/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-13167/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-13167/3.10/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-13167/3.10/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-13167/3.10/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-13167/3.10/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-13167/3.10/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-13168/3.10/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-13215/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-13216/3.10/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-13246/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-13292/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-13305/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-13694/^4.12.9/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-13695/^4.12.9/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-14106/^4.12/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-14489/^4.13.2/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-15265/^4.13/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-15837/ANY/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-15868/3.10/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-15868/3.10/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-16526/^4.13.6/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-16531/^4.13.6/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-16532/^4.13.11/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-16533/^4.13.8/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-16534/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-16535/^4.13.10/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-16537/^4.13.11/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-16538/^4.13.11/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-16538/^4.13.11/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-16643/3.5-^4.13.11/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-16645/^4.13.11/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-16650/^4.13.11/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-16939/3.10/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-17450/^4.14.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-17558/^4.14.5/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-17805/^4.14.8/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-17806/^4.14.8/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-18079/^4.12.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-18360/^4.11.3/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-18595/^4.14.11/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-1000111/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-1000252/^4.13.3/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-1000363/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-1000365/3.10/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-1000380/^4.11.5/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-1000410/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-1068/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-1068/ANY/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-1092/^4.15.15/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-5332/^4.14.13/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-5333/^4.14.13/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-5390/3.10/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-5390/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-5750/^4.14.15/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-7273/^4.15.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-7492/^4.14.7/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-7757/^4.15.7/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-8781/^4.15/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-9383/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-9389/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-9416/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-9516/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-9518/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-10021/^4.16/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-10087/^4.13/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-10124/^4.13/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-10675/^4.12.9/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-10876/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-10876/ANY/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-10879/3.10/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-10880/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-10881/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-10882/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-10883/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-10883/ANY/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-10902/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-10940/^4.16.6/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-11939/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-13053/^4.17.3/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-14634/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-14734/^4.17.11/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-15594/^4.18.1/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-16658/^4.18.6/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-18710/^4.19/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-20511/^4.18.11/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-20836/^4.20/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-1000199/^3.18/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-2001/^3.10/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-2054/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-2101/ANY/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-3459/^5.1/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-8912/^4.20.11/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-10142/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-10607/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-11486/^5.0.8/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-11833/^5.1.2/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-11884/^5.0.15/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-12456/^5.1.5/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-13631/^5.2.1/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-15098/^5.2.8/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-15212/^5.1.8/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-15213/^5.2.3/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-15216/^5.0.14/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-15807/^5.1.13/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-15926/^5.2.3/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-17052/^5.3.2/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-17133/^5.3.2/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-18806/^5.3.5/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19066/^5.3.11/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19073/^5.3.11/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19074/^5.3.11/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19524/^5.3.12/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19527/^5.2.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19536/^5.2.9/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19965/^5.4.6/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19966/^5.1.6/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-20054/^5.0.6/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-20054/^5.0.6/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-20096/^5.1/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-20636/^5.4.12/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-8649/^5.5.2/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-9383/^5.5.6/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-11565/^5.6.2/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/Untracked-02/ANY/772877_0001-usb-core-Fix-use-after-free-for-hub-usb-device.patch
git apply $DOS_PATCHES_LINUX_CVES/Untracked-02/ANY/797912_0001-usb-gadget-Fix-synchronization-issue-between-f_audio.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-2475/ANY/0001.patch
editKernelLocalversion "-dos.p343"
cd "$DOS_BUILD_BASE"
