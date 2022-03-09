#!/bin/bash
cd "$DOS_BUILD_BASE""kernel/asus/fugu"
git apply $DOS_PATCHES_LINUX_CVES/0002-Misc_Fixes/ANY/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/0003-syzkaller-Misc/ANY/0009.patch
git apply $DOS_PATCHES_LINUX_CVES/0003-syzkaller-Misc2/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/0006-AndroidHardening-Kernel_Hardening/3.10/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/0006-AndroidHardening-Kernel_Hardening/3.10/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/0006-AndroidHardening-Kernel_Hardening/3.10/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/0006-AndroidHardening-Kernel_Hardening/3.10/0009.patch
git apply $DOS_PATCHES_LINUX_CVES/0006-AndroidHardening-Kernel_Hardening/3.10/0010.patch
git apply $DOS_PATCHES_LINUX_CVES/0006-AndroidHardening-Kernel_Hardening/3.10/0011.patch
git apply $DOS_PATCHES_LINUX_CVES/0006-AndroidHardening-Kernel_Hardening/3.10/0012.patch
git apply $DOS_PATCHES_LINUX_CVES/0006-AndroidHardening-Kernel_Hardening/3.10/0013.patch
git apply $DOS_PATCHES_LINUX_CVES/0006-AndroidHardening-Kernel_Hardening/3.10/0014.patch
git apply $DOS_PATCHES_LINUX_CVES/0006-AndroidHardening-Kernel_Hardening/3.10/0015.patch
git apply $DOS_PATCHES_LINUX_CVES/0006-AndroidHardening-Kernel_Hardening/3.10/0016.patch
git apply $DOS_PATCHES_LINUX_CVES/0006-AndroidHardening-Kernel_Hardening/3.10/0017.patch
git apply $DOS_PATCHES_LINUX_CVES/0090-Unknown/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2012-2372/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2013-2929/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2013-2930/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2013-4129/^3.10.3/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2013-4129/^3.10.3/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2013-4312/3.10/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2013-4345/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2013-4470/^3.12/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2013-4563/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2013-4579/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2013-4587/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2013-6367/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2013-6368/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2013-6376/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2013-6378/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2013-6380/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2013-6381/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2013-6382/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2013-6885/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2013-7026/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2013-7266/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2013-7339/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2013-7421/3.10/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2013-7421/3.10/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2013-7421/3.10/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-0038/^3.13.2/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-0049/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-0055/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-0069/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-0077/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-0100/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-0101/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-0155/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-0181/3.10/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-0181/3.10/0009.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-0181/3.10/0010.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-0206/3.10/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-1438/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-1446/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-1690/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-1737/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-1738/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-2039/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-2309/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-2523/3.10/0003.patch
#git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-2568/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-2672/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-2673/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-2678/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-3122/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-3181/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-3183/3.10/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-3184/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-3186/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-3534/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-3601/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-3610/3.10/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-3610/3.10/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-3611/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-3645/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-3646/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-3673/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-3687/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-3688/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-3690/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-3917/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-4171/3.10/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-4171/3.10/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-4171/3.10/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-4508/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-4608/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-4652/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-4653/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-4667/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-4699/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-4943/3.10/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-5077/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-5471/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-6410/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-6416/3.10/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-6416/3.10/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-7145/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-7207/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-7283/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-7825/3.10/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-7841/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-7842/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-7843/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-7970/3.10/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-7975/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-8086/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-8134/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-8159/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-8160/3.10/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-8173/3.9-^3.13/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-8369/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-8480/^3.18/0001.patch
#git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-8559/3.10/0003.patch
#git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-8559/3.10/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-8884/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-9419/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-9420/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-9584/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-9585/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-9683/3.10/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-9710/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-9715/3.10/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-9728/3.18/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-9892/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2014-9900/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-0239/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-0275/^4.1/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-1339/^4.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-1420/3.2-^3.19.1/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-1421/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-2041/3.10/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-2042/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-2150/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-2666/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-2830/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-2925/3.10/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-2925/3.10/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-3212/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-3290/3.18/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-3290/3.18/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-3331/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-4002/3.10/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-4003/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-4036/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-4167/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-4177/3.18/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-4692/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-4700/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-5156/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-5257/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-5283/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-5307/3.18/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-5697/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-6252/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-6526/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-6937/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-7513/3.18/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-7515/^4.4/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-7550/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-7566/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-7799/3.10/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-7799/3.10/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-7833/3.10/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-7990/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-8215/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-8539/3.18/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-8543/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-8551/3.10/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-8551/3.10/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-8551/3.10/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-8551/3.10/0009.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-8551/3.10/0010.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-8553/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-8569/3.10/0002.patch
#git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-8746/3.18/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-8767/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-8785/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-8812/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-8944/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-8955/3.18/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-8962/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-8967/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-8970/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-9289/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-0758/3.18/0002.patch
#git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-1583/3.18/0008.patch
#git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-1583/3.18/0009.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-2053/3.18/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-2069/3.10/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-2069/3.10/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-2085/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-2117/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-2185/3.10/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-2186/3.10/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-2187/3.10/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-2384/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-2438/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-2543/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-2544/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-2545/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-2549/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-2550/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-2782/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-2847/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-3070/3.10/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-3136/3.10/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-3137/3.10/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-3138/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-3140/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-3157/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-3689/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-3857/3.10/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-3955/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-3961/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-4485/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-4565/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-4580/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-4913/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-4998/3.10/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-4998/3.10/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-5244/3.18/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-5828/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-6327/3.18/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-6480/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-7042/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-7117/^4.5.2/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-7425/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-8453/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-8464/3.10/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-8633/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-8645/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-8646/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-8650/3.10/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-8658/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-9083/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-9178/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-9555/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-9576/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-9576/3.10/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-9588/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-9604/3.10/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-10142/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-10208/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-10318/3.18/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-10741/3.18/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2016-partial-SMAP-bypass/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-16USB/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-16USB/ANY/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-16USB/ANY/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-0449/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-0537/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-0564/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-0627/3.18/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-0648/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-2583/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-2584/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-2618/3.10/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-2671/^4.10.8/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-5549/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-5669/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-5972/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-5986/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-6345/3.18/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-6348/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-6353/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-6951/^3.14.79/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-7184/3.10/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-7184/3.10/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-7261/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-7273/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-7294/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-7472/3.10/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-7482/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-7487/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-7533/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-7533/3.10/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-7645/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-8067/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-8068/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-8069/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-8824/3.10/0009.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-8924/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-8925/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-9242/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-9984/3.18/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-10911/3.18/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-11176/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-11473/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-11600/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-11600/3.10/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-12153/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-12762/3.18/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-13167/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-13167/3.10/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-13167/3.10/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-13167/3.10/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-13167/3.10/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-13167/3.10/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-13167/3.10/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-13168/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-13215/3.10/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-13216/3.10/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-13246/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-13273/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-13292/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-13305/3.10/0009.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-13694/^4.12.9/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-13695/3.18/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-14051/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-14106/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-14489/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-15102/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-15115/3.10/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-15121/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-15265/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-15274/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-15299/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-15649/3.10/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-15837/ANY/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-15868/3.10/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-15868/3.10/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-16525/3.10/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-16526/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-16527/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-16529/3.10/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-16531/3.10/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-16532/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-16533/3.10/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-16534/3.10/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-16535/3.10/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-16537/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-16538/3.18/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-16538/3.18/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-16643/3.5-^4.13.11/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-16644/3.18/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-16645/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-16650/3.18/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-16939/3.10/0009.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-16994/3.18/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-17450/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-17558/3.18/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-17712/3.10/0010.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-17805/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-17806/3.10/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-18017/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-18079/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-18208/3.18/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-18216/3.18/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-18270/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-18360/3.18/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-18509/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-18551/3.18/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-18595/3.18/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-1000111/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-1000251/3.18/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-1000252/^4.13.3/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-1000253/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-1000363/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-1000365/3.10/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2017-1000410/3.10/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-1068/3.10/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-1068/^4.16/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-1130/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-5332/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-5333/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-5344/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-5390/3.10/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-5390/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-5750/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-5803/3.10/0010.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-7492/3.18/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-7566/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-7755/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-7757/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-8781/3.18/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-8822/3.18/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-9383/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-9389/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-9416/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-9514/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-9515/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-9516/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-9518/3.10/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-9568/3.10/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-10021/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-10087/3.18/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-10124/3.18/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-10675/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-10876/3.10/0017.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-10878/3.18/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-10879/3.10/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-10879/3.10/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-10880/3.10/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-10881/3.10/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-10882/3.10/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-10883/3.18/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-10883/3.18/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-10902/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-10940/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-11506/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-11939/ANY/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-12232/3.10/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-12233/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-13053/3.10/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-13405/3.10/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-14634/3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-14734/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-15594/3.18/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-16276/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-16658/3.18/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-16885/3.10/0003.patch
#git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-17972/3.18/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-18710/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-19824/3.10/0008.patch
#git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-20169/3.18/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-20511/3.18/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-20836/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-1000199/3.10/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2018-1000204/3.18/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-2001/^3.10/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-2054/ANY/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-2101/3.10/0009.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-3459/3.10/0009.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-3460/3.10/0009.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-3701/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-3819/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-3837/^3.14/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-3846/3.18/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-7222/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-8912/3.10/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-9213/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-10142/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-10220/3.18/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-10220/3.18/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-10607/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-10638/3.18/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-11477/3.10/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-11478/3.10/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-11478/3.10/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-11479/3.10/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-11479/3.10/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-11486/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-11810/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-11833/^5.1.2/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-11884/3.10/0009.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-12456/^5.1.5/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-13631/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-13648/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-14284/3.18/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-14814/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-14821/3.18/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-14835/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-14896/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-15098/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-15212/3.18/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-15213/^5.2.3/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-15215/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-15216/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-15217/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-15218/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-15219/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-15291/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-15292/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-15505/3.18/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-15807/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-15926/3.18/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-16232/3.18/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-16233/3.18/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-17052/3.18/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-17053/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-17054/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-17055/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-17056/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-17133/3.18/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-17666/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-18806/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19051/3.18/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19051/4.4/0011.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19051/4.4/0012.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19056/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19062/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19063/3.18/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19066/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19073/3.18/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19074/3.18/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19227/3.18/0003.patch
#git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19319/4.4/0017.patch
#git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19319/4.4/0018.patch
#git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19319/4.4/0019.patch
#git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19319/4.4/0020.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19447/3.10/0009.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19448/3.18/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19524/3.10/0009.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19527/3.18/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19527/3.18/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19528/^5.4/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19528/^5.4/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19530/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19531/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19532/3.10/0009.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19533/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19536/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19537/3.18/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19947/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19965/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-19966/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-20054/3.18/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-20054/3.18/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-20096/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-20636/3.18/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-20812/3.18/0003.patch
#git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-0305/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-0404/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-0429/3.18/0001.patch
#git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-0429/4.4/0010.patch
#git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-0429/4.4/0011.patch
#git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-0429/4.4/0014.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-0431/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-0465/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-8647/3.18/0004.patch
#git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-8992/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-9383/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-10773/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-10942/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-11565/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-11608/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-11609/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-11668/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-12653/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-12654/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-12656/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-12656/4.4/0009.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-12770/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-13143/3.18/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-13974/3.18/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-14305/4.4/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-14314/3.18/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-14331/3.18/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-14386/3.10-^4.4/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-15393/3.18/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-15436/3.18/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-16119/4.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-25211/3.18/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-25643/3.18/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-25668/3.18/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-25669/3.18/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-25673/3.18/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-27066/3.18/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-27068/3.18/0002.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-27815/3.18/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-27825/3.18/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-28974/3.18/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-29371/3.18/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-29568/4.4/0020.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-29661/3.0-^3.10/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2020-36158/3.18/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-0399/3.18/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-0512/3.18/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-0695/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-0961/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-0961/4.4/0005.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-3178/3.18/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-3428/3.18/0001.patch
#git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-3428/4.4/0013.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-3483/3.18/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-3564/3.18/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-3573/3.18/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-3609/4.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-3612/3.18/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-3653/4.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-3655/4.4/0011.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-3655/^5.13/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-3753/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-3896/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-20261/^3.15/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-27363/3.18/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-27365/4.4/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-28713/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-28972/3.18/0007.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-31916/3.18/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-32399/3.18/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-33909/3.18/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-34693/3.18/0008.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-37576/4.4/0006.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-39714/4.4/0003.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-39715/ANY/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-42008/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2021-45095/4.4/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2022-0850/3.18/0001.patch
git apply $DOS_PATCHES_LINUX_CVES/Untracked-02/ANY/772877_0001-usb-core-Fix-use-after-free-for-hub-usb-device.patch
git apply $DOS_PATCHES_LINUX_CVES/Untracked-02/ANY/797912_0001-usb-gadget-Fix-synchronization-issue-between-f_audio.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2015-4002/3.10/0004.patch
git apply $DOS_PATCHES_LINUX_CVES/CVE-2019-14283/3.18/0004.patch
editKernelLocalversion "-dos.p594"
cd "$DOS_BUILD_BASE"
