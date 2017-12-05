#!/bin/bash
cd $base"kernel/google/msm"
git apply $cvePatches/CVE-2013-4738/ANY/0002.patch
git apply $cvePatches/CVE-2014-9781/ANY/0001.patch
git apply $cvePatches/CVE-2015-1593/ANY/0001.patch
git apply $cvePatches/CVE-2016-3857/ANY/0001.patch
git apply $cvePatches/CVE-2016-3894/ANY/0001.patch
git apply $cvePatches/CVE-2016-7117/^4.5/0002.patch
git apply $cvePatches/CVE-2016-8402/3.4/0001.patch
git apply $cvePatches/CVE-2016-8404/ANY/0001.patch
git apply $cvePatches/CVE-2017-0611/3.4/0001.patch
git apply $cvePatches/CVE-2017-0648/ANY/0001.patch
git apply $cvePatches/CVE-2017-0710/ANY/0001.patch
git apply $cvePatches/CVE-2017-0750/ANY/0001.patch
git apply $cvePatches/CVE-2017-0751/ANY/0001.patch
git apply $cvePatches/CVE-2017-0786/ANY/0001.patch
git apply $cvePatches/CVE-2017-11089/ANY/0001.patch
git apply $cvePatches/CVE-2017-11090/ANY/0001.patch
git apply $cvePatches/CVE-2017-12153/3.2-^3.16/0001.patch
git apply $cvePatches/CVE-2017-13080/ANY/0001.patch
git apply $cvePatches/CVE-2017-15265/^4.14/0001.patch
git apply $cvePatches/CVE-2017-16526/^4.13/0001.patch
git apply $cvePatches/CVE-2017-16532/^4.13/0001.patch
git apply $cvePatches/CVE-2017-16533/^4.13/0001.patch
git apply $cvePatches/CVE-2017-16535/^4.13/0001.patch
git apply $cvePatches/CVE-2017-16537/^4.13/0001.patch
git apply $cvePatches/CVE-2017-16650/ANY/0001.patch
git apply $cvePatches/CVE-2017-16USB/ANY/0001.patch
git apply $cvePatches/CVE-2017-16USB/ANY/0005.patch
git apply $cvePatches/CVE-2017-16USB/ANY/0006.patch
git apply $cvePatches/CVE-2017-8246/3.4/0002.patch
git apply $cvePatches/CVE-2017-8254/3.4/0001.patch
git apply $cvePatches/Untracked/ANY/0008-nfsd-check-for-oversized-NFSv2-v3-arguments.patch
cd $base
