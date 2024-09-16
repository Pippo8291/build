#!/bin/bash
#DivestOS: A mobile operating system divested from the norm.
#Copyright (c) 2015-2024 Divested Computing Group
#
#This program is free software: you can redistribute it and/or modify
#it under the terms of the GNU Affero General Public License as published by
#the Free Software Foundation, either version 3 of the License, or
#(at your option) any later version.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU Affero General Public License for more details.
#
#You should have received a copy of the GNU Affero General Public License
#along with this program.  If not, see <https://www.gnu.org/licenses/>.
umask 0022;
set -euo pipefail;
source "$DOS_SCRIPTS_COMMON/Shell.sh";

#Last verified: 2021-10-16

#Initialize aliases
#source ../../Scripts/init.sh

#Delete Everything and Sync
#resetWorkspace

#Apply all of our changes
#patchWorkspace

#Build!
#buildDevice [device]
#buildAll

#
#START OF PREPRATION
#
#Download some (non-executable) out-of-tree files for use later on
cd "$DOS_TMP_DIR";
if [ "$DOS_HOSTS_BLOCKING" = true ]; then wget --no-verbose "$DOS_HOSTS_BLOCKING_LIST" -N -O "$DOS_HOSTS_FILE"; fi;
cd "$DOS_BUILD_BASE";
#
#END OF PREPRATION
#

#
#START OF ROM CHANGES
#

#top dir
cp -r "$DOS_PREBUILT_APPS/Fennec_DOS-Shim" "$DOS_BUILD_BASE/packages/apps/"; #Add a shim to install Fennec DOS without actually including the large APK
cp -r "$DOS_PREBUILT_APPS/SupportDivestOS" "$DOS_BUILD_BASE/packages/apps/"; #Add the Support app
gpgVerifyDirectory "$DOS_PREBUILT_APPS/android_vendor_FDroid_PrebuiltApps/packages";
cp -r "$DOS_PREBUILT_APPS/android_vendor_FDroid_PrebuiltApps/." "$DOS_BUILD_BASE/vendor/fdroid_prebuilt/"; #Add the prebuilt apps
cp -r "$DOS_PATCHES_COMMON/android_vendor_divested/." "$DOS_BUILD_BASE/vendor/divested/"; #Add our vendor files

if enterAndClear "bionic"; then
applyPatch "$DOS_PATCHES_COMMON/android_bionic/0001-Wildcard_Hosts.patch"; #Support wildcards in cached hosts file (backport from 16.0+) (tdm)
applyPatch "$DOS_PATCHES/android_bionic/0001-HM-Use_HM.patch"; #(GrapheneOS)
applyPatch "$DOS_PATCHES/android_bionic/0002-Add_M_PURGE.patch"; #malloc: add M_PURGE mallopt flag
applyPatch "$DOS_PATCHES/android_bionic/0003-Add_random.h.patch"; #Add <sys/random.h>.
fi;

if enterAndClear "bootable/recovery"; then
git revert --no-edit eb98fde70a6e54a25408eb8c626caecf7841c5df; #Remove sideload cache, breaks with large files
git revert --no-edit ac258a4f4c4b4b91640cc477ad1ac125f206db02; #Resurrect dm-verity
sed -i 's/!= 2048/< 2048/' tools/dumpkey/DumpPublicKey.java; #Allow 4096-bit keys
sed -i 's/(!has_serial_number || serial_number_matched)/!has_serial_number/' recovery.cpp; #Abort package installs if they are specific to a serial number (GrapheneOS)
fi;

if enterAndClear "build/make"; then
git revert --no-edit ceb64cd86b1cf6be3b1214ace80d8260971f8877; #Re-enable the downgrade check
applyPatch "$DOS_PATCHES/android_build/0001-OTA_Keys.patch"; #Add correct keys to recovery for OTA verification (DivestOS)
applyPatch "$DOS_PATCHES/android_build/0002-Enable_fwrapv.patch"; #Use -fwrapv at a minimum (GrapheneOS)
applyPatch "$DOS_PATCHES/android_build/0003-verity-openssl3.patch"; #Fix VB 1.0 failure due to openssl output format change
sed -i '57i$(my_res_package): PRIVATE_AAPT_FLAGS += --auto-add-overlay' core/aapt2.mk; #Enable auto-add-overlay for packages, this allows the vendor overlay to easily work across all branches.
awk -i inplace '!/Email/' target/product/core.mk; #Remove Email
sed -i 's/2021-10-05/2024-09-05/' core/version_defaults.mk; #Bump Security String #XXX
fi;

if enterAndClear "build/soong"; then
applyPatch "$DOS_PATCHES/android_build_soong/0001-Enable_fwrapv.patch"; #Use -fwrapv at a minimum (GrapheneOS)
fi;

if enterAndClear "device/lineage/sepolicy"; then
git revert --no-edit 9c28a0dfb91bb468515e123b1aaf3fcfc007b82f; #neverallow violation - breaks backuptool
git revert --no-edit f1ad32105599a0b71702f840b2deeb6849f1ae80; #neverallow violation - breaks addons
git revert --no-edit c9b0d95630b82cd0ad1a0fc633c6d59c2cb8aad7 37422f7df389f3ae5a34ee3d6dd9354217f9c536; #neverallow violation - breaks update_engine
fi;

if enterAndClear "device/qcom/sepolicy"; then
applyPatch "$DOS_PATCHES/android_device_qcom_sepolicy/0001-Camera_Fix.patch"; #Fix camera on -user builds XXX: REMOVE THIS TRASH (DivestOS)
fi;

if enterAndClear "external/aac"; then
applyPatch "$DOS_PATCHES/android_external_aac/364027.patch"; #R_asb_2023-08 Increase patchParam array size by one and fix out-of-bounce write in resetLppTransposer().
fi;

if enterAndClear "external/chromium-webview"; then
git lfs pull; #Ensure the objects are available
fi;

if enterAndClear "external/dtc"; then
applyPatch "$DOS_PATCHES/android_external_dtc/342096.patch"; #P_asb_2022-10 libfdt: fdt_offset_ptr(): Fix comparison warnings
applyPatch "$DOS_PATCHES/android_external_dtc/344161.patch"; #P_asb_2022-11 Fix integer wrap sanitisation.
applyPatch "$DOS_PATCHES/android_external_dtc/345891.patch"; #P_asb_2022-12 libfdt: fdt_path_offset_namelen: Reject empty paths
fi;

if enterAndClear "external/expat"; then
applyPatch "$DOS_PATCHES/android_external_expat/337987.patch"; #Q_asb_2022-09 Prevent XML_GetBuffer signed integer overflow
applyPatch "$DOS_PATCHES/android_external_expat/337988-backport.patch"; #n-asb-2022-09 Prevent integer overflow in function doProlog
applyPatch "$DOS_PATCHES/android_external_expat/337989-backport.patch"; #n-asb-2022-09 Prevent more integer overflows
applyPatch "$DOS_PATCHES/android_external_expat/348649.patch"; #n-asb-2023-02 Fix overeager DTD destruction (fixes #649)
applyPatch "$DOS_PATCHES/android_external_expat/0001-Validate-parser-parameter-to-XML_UseForeignDTD.patch";
applyPatch "$DOS_PATCHES/android_external_expat/0002-expat.h-Fix-version-hint-on-XML_ERROR_INVALID_ARGUME.patch";
applyPatch "$DOS_PATCHES/android_external_expat/0003-Validate-parser-parameter-for-XML_ParseBuffer.patch";
applyPatch "$DOS_PATCHES/android_external_expat/0004-lib-Reject-negative-len-for-XML_ParseBuffer.patch";
applyPatch "$DOS_PATCHES/android_external_expat/0005-lib-Detect-integer-overflow-in-dtdCopy.patch";
applyPatch "$DOS_PATCHES/android_external_expat/0006-lib-Detect-integer-overflow-in-function-nextScaffold.patch";
applyPatch "$DOS_PATCHES/android_external_expat/0007-lib-Stop-leaking-opening-tag-bindings-after-closing-.patch";
fi;

if enterAndClear "external/freetype"; then
applyPatch "$DOS_PATCHES/android_external_freetype/360951.patch"; #R_asb_2023-07 Cherry-pick two upstream changes
fi;

if enterAndClear "external/hardened_malloc"; then
applyPatch "$DOS_PATCHES_COMMON/android_external_hardened_malloc/0001-Broken_Cameras-1.patch"; #Workarounds for Pixel 3 SoC era camera driver bugs (GrapheneOS)
applyPatch "$DOS_PATCHES_COMMON/android_external_hardened_malloc/0001-Broken_Cameras-2.patch"; #Expand workaround to all camera executables (DivestOS)
applyPatch "$DOS_PATCHES_COMMON/android_external_hardened_malloc/0002-Broken_Displays.patch"; #Add workaround for OnePlus 8 & 9 display driver crash (DivestOS)
applyPatch "$DOS_PATCHES_COMMON/android_external_hardened_malloc/0003-Broken_Audio.patch"; #Workaround for audio service sorting bug (GrapheneOS)
sed -i 's/34359738368/2147483648/' Android.bp; #revert 48-bit address space requirement
sed -i -e '76,78d;' Android.bp; #fix compile under A13
sed -i -e '22,24d;' androidtest/Android.bp; #fix compile under A12
awk -i inplace '!/vendor_ramdisk_available/' Android.bp; #fix compile under A11
rm -rfv androidtest; #fix compile under A11
sed -i -e '76,78d;' Android.bp; #fix compile under A10
awk -i inplace '!/ramdisk_available/' Android.bp; #fix compile under A10
git revert --no-edit 8974af86d12f7e29b54b5090133ab3d7eea0e519; #fix compile under A10
git revert --no-edit a28da3c65aed0528036da9ebd33e0c05b2c5884a; #fix compile under A9
mv include/h_malloc.h . ; #fix compile under A10
awk -i inplace '!/recovery_available/' Android.bp; #fix compile under A9
awk -i inplace '!/system_shared_libs/' Android.bp; #fix compile under A9
sed -i 's/c17/c11/' Android.bp; #fix compile under A9
sed -i 's/struct mallinfo info = {0};/struct mallinfo info = {};/' h_malloc.c; #fix compile under A8
fi;

if enterAndClear "external/libvpx"; then
applyPatch "$DOS_PATCHES_COMMON/android_external_libvpx/CVE-2023-5217.patch"; #VP8: disallow thread count changes
fi;

if enterAndClear "external/libxml2"; then
applyPatch "$DOS_PATCHES/android_external_libxml2/368053.patch"; #R_asb_2023-10 malloc-fail: Fix OOB read after xmlRegGetCounter
fi;

if enterAndClear "external/sonivox"; then
applyPatch "$DOS_PATCHES_COMMON/android_external_sonivox/391896.patch"; #n-asb-2024-05 Fix buffer overrun in eas_wtengine
fi;

if enterAndClear "external/svox"; then
git revert --no-edit 1419d63b4889a26d22443fd8df1f9073bf229d3d; #Add back Makefiles
fi;

if enterAndClear "external/webp"; then
sed -i '85i\ \ \ \ \ \ \ \ "src/utils/filters_utils.c",' Android.bp; #Fixup
fi;

if enterAndClear "external/zlib"; then
applyPatch "$DOS_PATCHES/android_external_zlib/351909.patch"; #P_asb_2023-03 Fix a bug when getting a gzip header extra field with inflate().
fi;

if enterAndClear "frameworks/av"; then
applyPatch "$DOS_PATCHES/android_frameworks_av/0001-HM-No_RLIMIT_AS.patch"; #(GrapheneOS)
applyPatch "$DOS_PATCHES/android_frameworks_av/358729.patch"; #n-asb-2023-06 Fix NuMediaExtractor::readSampleData buffer Handling
applyPatch "$DOS_PATCHES/android_frameworks_av/365962.patch"; #R_asb_2023-09 Fix Segv on unknown address error flagged by fuzzer test.
applyPatch "$DOS_PATCHES/android_frameworks_av/373949.patch"; #R_asb_2023-11 Fix for heap buffer overflow issue flagged by fuzzer test.
applyPatch "$DOS_PATCHES/android_frameworks_av/381886.patch"; #R_asb_2024-02 Update mtp packet buffer
applyPatch "$DOS_PATCHES/android_frameworks_av/385670.patch"; #P_asb_2024-03 Validate OMX Params for VPx encoders
applyPatch "$DOS_PATCHES/android_frameworks_av/385671.patch"; #P_asb_2024-03 Fix out of bounds read and write in onQueueFilled in outQueue
applyPatch "$DOS_PATCHES/android_frameworks_av/399771.patch"; #P_asb_2024-08 StagefrightRecoder: Disabling B-frame support
fi;

if enterAndClear "frameworks/base"; then
applyPatch "$DOS_PATCHES/android_frameworks_base/330961-backport.patch"; #P_asb_2022-05 Keyguard - Treat messsages to lock with priority
applyPatch "$DOS_PATCHES/android_frameworks_base/331108.patch"; #n-asb-2022-05 Always restart apps if base.apk gets updated.
applyPatch "$DOS_PATCHES/android_frameworks_base/332449.patch"; #n-asb-2022-06 Add an OEM configurable limit for zen rules
applyPatch "$DOS_PATCHES/android_frameworks_base/332757.patch"; #P_asb_2022-06 limit TelecomManager#registerPhoneAccount to 10; api doc update
applyPatch "$DOS_PATCHES/android_frameworks_base/332776.patch"; #P_asb_2022-06 Update GeofenceHardwareRequestParcelable to match parcel/unparcel format.
applyPatch "$DOS_PATCHES/android_frameworks_base/332778.patch"; #P_asb_2022-06 Fix security hole in GateKeeperResponse
#applyPatch "$DOS_PATCHES/android_frameworks_base/332779.patch"; #P_asb_2022-06 Prevent non-admin users from deleting system apps. REVERTED IN P_asb_2022-12
#applyPatch "$DOS_PATCHES/android_frameworks_base/334257-backport.patch"; #P_asb_2022-07 UserDataPreparer: reboot to recovery if preparing user storage fails #XXX
#applyPatch "$DOS_PATCHES/android_frameworks_base/334258-backport.patch"; #P_asb_2022-07 UserDataPreparer: reboot to recovery for system user only #XXX
applyPatch "$DOS_PATCHES/android_frameworks_base/334262.patch"; #P_asb_2022-07 Crash invalid FGS notifications
applyPatch "$DOS_PATCHES/android_frameworks_base/335117-backport.patch"; #P_asb_2022-08 Only allow system and same app to apply relinquishTaskIdentity
#applyPatch "$DOS_PATCHES/android_frameworks_base/335119.patch"; #P_asb_2022-08 Remove package title from notification access confirmation intent TODO: 335116 must be backported
applyPatch "$DOS_PATCHES/android_frameworks_base/335120.patch"; #P_asb_2022-08 Stop using invalid URL to prevent unexpected crash
applyPatch "$DOS_PATCHES/android_frameworks_base/335121-backport.patch"; #P_asb_2022-08 Only allow the system server to connect to sync adapters
#applyPatch "$DOS_PATCHES/android_frameworks_base/337990.patch"; #Q_asb_2022-09 Fix duplicate permission privilege escalation #XXX: needs getProtection() backport
applyPatch "$DOS_PATCHES/android_frameworks_base/337991.patch"; #Q_asb_2022-09 Parcel: recycle recycles
applyPatch "$DOS_PATCHES/android_frameworks_base/337992-backport.patch"; #Q_asb_2022-09 IMMS: Make IMMS PendingIntents immutable
#applyPatch "$DOS_PATCHES/android_frameworks_base/337993.patch"; #Q_asb_2022-09 Remove package name from SafetyNet logs #XXX: depends on 337990
applyPatch "$DOS_PATCHES/android_frameworks_base/344168.patch"; #P_asb_2022-11 Move accountname and typeName length check from Account.java to AccountManagerService.
applyPatch "$DOS_PATCHES/android_frameworks_base/344169.patch"; #P_asb_2022-11 switch TelecomManager List getters to ParceledListSlice
applyPatch "$DOS_PATCHES/android_frameworks_base/344170-backport.patch"; #P_asb_2022-11 Do not send new Intent to non-exported activity when navigateUpTo
applyPatch "$DOS_PATCHES/android_frameworks_base/344171-backport.patch"; #P_asb_2022-11 Do not send AccessibilityEvent if notification is for different user.
applyPatch "$DOS_PATCHES/android_frameworks_base/344172.patch"; #P_asb_2022-11 Trim any long string inputs that come in to AutomaticZenRule
applyPatch "$DOS_PATCHES/android_frameworks_base/344173.patch"; #P_asb_2022-11 Check permission for VoiceInteraction
applyPatch "$DOS_PATCHES/android_frameworks_base/344174-backport.patch"; #P_asb_2022-11 Do not dismiss keyguard after SIM PUK unlock
applyPatch "$DOS_PATCHES/android_frameworks_base/345893-backport.patch"; #P_asb_2022-12 Limit the size of NotificationChannel and NotificationChannelGroup
applyPatch "$DOS_PATCHES/android_frameworks_base/345894.patch"; #P_asb_2022-12 Prevent non-admin users from deleting system apps.
applyPatch "$DOS_PATCHES/android_frameworks_base/345895-backport.patch"; #P_asb_2022-12 Validate package name passed to setApplicationRestrictions.
applyPatch "$DOS_PATCHES/android_frameworks_base/345896-backport.patch"; #P_asb_2022-12 Include all enabled services when FEEDBACK_ALL_MASK. #XXX: uncertain backport
applyPatch "$DOS_PATCHES/android_frameworks_base/345897-backport.patch"; #P_asb_2022-12 [pm] forbid deletion of protected packages
applyPatch "$DOS_PATCHES/android_frameworks_base/345898-backport.patch"; #P_asb_2022-12 Fix NPE
applyPatch "$DOS_PATCHES/android_frameworks_base/345520.patch"; #n-asb-2022-12 Ignore malformed shortcuts
applyPatch "$DOS_PATCHES/android_frameworks_base/345901.patch"; #P_asb_2022-12 Fix permanent denial of service via setComponentEnabledSetting
applyPatch "$DOS_PATCHES/android_frameworks_base/345902-backport.patch"; #P_asb_2022-12 Add safety checks on KEY_INTENT mismatch.
applyPatch "$DOS_PATCHES/android_frameworks_base/347044.patch"; #P_asb_2023-01 Limit lengths of fields in Condition to a max length.
applyPatch "$DOS_PATCHES/android_frameworks_base/346949.patch"; #n-asb-2023-01 Disable all A11yServices from an uninstalled package.
applyPatch "$DOS_PATCHES/android_frameworks_base/347046.patch"; #P_asb_2023-01 Fix conditionId string trimming in AutomaticZenRule
applyPatch "$DOS_PATCHES/android_frameworks_base/347047-backport.patch"; #P_asb_2023-01 [SettingsProvider] mem limit should be checked before settings are updated
#applyPatch "$DOS_PATCHES/android_frameworks_base/347048-backport.patch"; #P_asb_2023-01 Revert "Revert "RESTRICT AUTOMERGE Validate permission tree size..." #XXX: uncertain backport
applyPatch "$DOS_PATCHES/android_frameworks_base/347049-backport.patch"; #P_asb_2023-01 [SettingsProvider] key size limit for mutating settings
applyPatch "$DOS_PATCHES/android_frameworks_base/347051-backport.patch"; #P_asb_2023-01 Add protections agains use-after-free issues if cancel() or queue() is called after a device connection has been closed.
applyPatch "$DOS_PATCHES/android_frameworks_base/349330.patch"; #P_asb_2023-02 Correct the behavior of ACTION_PACKAGE_DATA_CLEARED
applyPatch "$DOS_PATCHES/android_frameworks_base/349331.patch"; #P_asb_2023-02 Convert argument to intent in ChooseTypeAndAccountActivity
applyPatch "$DOS_PATCHES/android_frameworks_base/352086.patch"; #n-asb-2023-03 Revoke dev perm if app is upgrading to post 23 and perm has pre23 flag
applyPatch "$DOS_PATCHES/android_frameworks_base/354242-backport.patch"; #P_asb_2023-04 Context#startInstrumentation could be started from SHELL only now.
applyPatch "$DOS_PATCHES/android_frameworks_base/354243.patch"; #P_asb_2023-04 Checking if package belongs to UID before registering broadcast receiver
applyPatch "$DOS_PATCHES/android_frameworks_base/354244-backport.patch"; #P_asb_2023-04 Fix checkKeyIntentParceledCorrectly's bypass
applyPatch "$DOS_PATCHES/android_frameworks_base/354245.patch"; #P_asb_2023-04 Encode Intent scheme when serializing to URI string
applyPatch "$DOS_PATCHES/android_frameworks_base/355765-backport.patch"; #R_asb_2023-05 Checks if AccessibilityServiceInfo is within parcelable size.
applyPatch "$DOS_PATCHES/android_frameworks_base/355865.patch"; #n-asb-2023-05 Uri: check authority and scheme as part of determining URI path
applyPatch "$DOS_PATCHES/android_frameworks_base/355767.patch"; #R_asb_2023-05 Enforce stricter rules when registering phoneAccounts
applyPatch "$DOS_PATCHES/android_frameworks_base/358560-backport.patch"; #R_asb_2023-06 Check key intent for selectors and prohibited flags
applyPatch "$DOS_PATCHES/android_frameworks_base/358561-backport.patch"; #R_asb_2023-06 Handle invalid data during job loading.
applyPatch "$DOS_PATCHES/android_frameworks_base/358732-backport.patch"; #n-asb-2023-06 Prevent RemoteViews crashing SystemUi
applyPatch "$DOS_PATCHES/android_frameworks_base/360953-backport.patch"; #R_asb_2023-07 Sanitize VPN label to prevent HTML injection
applyPatch "$DOS_PATCHES/android_frameworks_base/360954-backport.patch"; #R_asb_2023-07 Limit the number of supported v1 and v2 signers
applyPatch "$DOS_PATCHES/android_frameworks_base/360962-backport.patch"; #R_asb_2023-07 Truncate ShortcutInfo Id
applyPatch "$DOS_PATCHES/android_frameworks_base/364029-backport.patch"; #R_asb_2023-08 ActivityManager#killBackgroundProcesses can kill caller's own app only
applyPatch "$DOS_PATCHES/android_frameworks_base/364033-backport.patch"; #R_asb_2023-08 Ensure policy has no absurdly long strings
applyPatch "$DOS_PATCHES/android_frameworks_base/364036-backport.patch"; #R_asb_2023-08 Verify URI permissions in MediaMetadata
applyPatch "$DOS_PATCHES/android_frameworks_base/364037.patch"; #R_asb_2023-08 Use Settings.System.getIntForUser instead of getInt to make sure user specific settings are used
applyPatch "$DOS_PATCHES/android_frameworks_base/364038-backport.patch"; #R_asb_2023-08 Resolve StatusHints image exploit across user.
applyPatch "$DOS_PATCHES/android_frameworks_base/365967.patch"; #R_asb_2023-09 Update AccountManagerService checkKeyIntentParceledCorrectly.
applyPatch "$DOS_PATCHES/android_frameworks_base/368055.patch"; #R_asb_2023-10 RingtoneManager: verify default ringtone is audio
applyPatch "$DOS_PATCHES/android_frameworks_base/368059.patch"; #R_asb_2023-10 Do not share key mappings with JNI object
applyPatch "$DOS_PATCHES/android_frameworks_base/368061.patch"; #R_asb_2023-10 Fix KCM key mapping cloning
applyPatch "$DOS_PATCHES/android_frameworks_base/368062-backport.patch"; #R_asb_2023-10 Disallow loading icon from content URI to PipMenu
applyPatch "$DOS_PATCHES/android_frameworks_base/368063.patch"; #R_asb_2023-10 Fixing DatabaseUtils to detect malformed UTF-16 strings
applyPatch "$DOS_PATCHES/android_frameworks_base/373953.patch"; #R_asb_2023-11 Use type safe API of readParcelableArray
applyPatch "$DOS_PATCHES/android_frameworks_base/373955.patch"; #R_asb_2023-11 [SettingsProvider] verify ringtone URI before setting
#applyPatch "$DOS_PATCHES/android_frameworks_base/377001-backport.patch"; #R_asb_2023-12 Visit Uris added by WearableExtender
applyPatch "$DOS_PATCHES/android_frameworks_base/377004-backport.patch"; #R_asb_2023-12 Drop invalid data.
applyPatch "$DOS_PATCHES/android_frameworks_base/377009.patch"; #R_asb_2023-12 Validate userId when publishing shortcuts
applyPatch "$DOS_PATCHES/android_frameworks_base/377011.patch"; #R_asb_2023-12 Adding in verification of calling UID in onShellCommand
applyPatch "$DOS_PATCHES/android_frameworks_base/379147-backport.patch"; #R_asb_2024-01 Truncate user data to a limit of 500 characters
applyPatch "$DOS_PATCHES/android_frameworks_base/379148-backport.patch"; #R_asb_2024-01 [CDM] Validate component name length before requesting notification access.
applyPatch "$DOS_PATCHES/android_frameworks_base/379149-backport.patch"; #R_asb_2024-01 Log to detect usage of whitelistToken when sending non-PI target
applyPatch "$DOS_PATCHES/android_frameworks_base/379150.patch"; #R_asb_2024-01 Fix vulnerability that allowed attackers to start arbitary activities
applyPatch "$DOS_PATCHES/android_frameworks_base/379136.patch"; #R_asb_2024-01 Fix ActivityManager#killBackgroundProcesses permissions
#applyPatch "$DOS_PATCHES/android_frameworks_base/381889-backport.patch"; #R_asb_2024-02 Unbind TileService onNullBinding #XXX: TileLifecycleManager.java:197.17: The method onNullBinding(ComponentName) of type TileLifecycleManager must override or implement a supertype method
applyPatch "$DOS_PATCHES/android_frameworks_base/385672.patch"; #P_asb_2024-03 Resolve custom printer icon boundary exploit.
applyPatch "$DOS_PATCHES/android_frameworks_base/385673.patch"; #P_asb_2024-03 Disallow system apps to be installed/updated as instant.
applyPatch "$DOS_PATCHES/android_frameworks_base/385674.patch"; #P_asb_2024-03 Close AccountManagerService.session after timeout.
applyPatch "$DOS_PATCHES/android_frameworks_base/389014-backport.patch"; #S_asb_2024-04 Fix security vulnerability that creates user with no restrictions when accountOptions are too long.
applyPatch "$DOS_PATCHES/android_frameworks_base/399075-backport.patch"; #Q_asb_2024-06 Added throttle when reporting shortcut usage
applyPatch "$DOS_PATCHES/android_frameworks_base/399076.patch"; #Q_asb_2024-06 Prevend user spoofing in isRequestPinItemSupported
applyPatch "$DOS_PATCHES/android_frameworks_base/394878.patch"; #P_asb_2024-06 Add more checkKeyIntent checks to AccountManagerService.
applyPatch "$DOS_PATCHES/android_frameworks_base/394879.patch"; #P_asb_2024-06 Adds additional sanitization for Zygote command arguments.
applyPatch "$DOS_PATCHES/android_frameworks_base/394880.patch"; #P_asb_2024-06 Check hidden API exemptions
applyPatch "$DOS_PATCHES/android_frameworks_base/394881-backport.patch"; #P_asb_2024-06 AccessibilityManagerService: remove uninstalled services from enabled list after service update.
applyPatch "$DOS_PATCHES/android_frameworks_base/394882.patch"; #P_asb_2024-06 Check permissions for CDM shell commands
applyPatch "$DOS_PATCHES/android_frameworks_base/397594.patch"; #P_asb_2024-07 Verify UID of incoming Zygote connections.
applyPatch "$DOS_PATCHES/android_frameworks_base/399769-backport.patch"; #P_asb_2024-08 Restrict USB poups while setup is in progress
applyPatch "$DOS_PATCHES/android_frameworks_base/399770.patch"; #P_asb_2024-08 Hide SAW subwindows
applyPatch "$DOS_PATCHES/android_frameworks_base/401373-backport.patch"; #S_asb_2024-09 Sanitized uri scheme by removing scheme delimiter
applyPatch "$DOS_PATCHES_COMMON/android_frameworks_base/0001-Browser_No_Location.patch"; #Don't grant location permission to system browsers (GrapheneOS)
applyPatch "$DOS_PATCHES_COMMON/android_frameworks_base/0003-SUPL_No_IMSI.patch"; #Don't send IMSI to SUPL (MSe1969)
applyPatch "$DOS_PATCHES_COMMON/android_frameworks_base/0004-Fingerprint_Lockout.patch"; #Enable fingerprint lockout after five failed attempts (GrapheneOS)
if [ "$DOS_SENSORS_PERM" = true ]; then applyPatch "$DOS_PATCHES/android_frameworks_base/0007-Sensors.patch"; fi; #Permission for sensors access (MSe1969)
sed -i 's/DEFAULT_MAX_FILES = 1000;/DEFAULT_MAX_FILES = 0;/' services/core/java/com/android/server/DropBoxManagerService.java; #Disable DropBox internal logging service
sed -i 's/DEFAULT_MAX_FILES_LOWRAM = 300;/DEFAULT_MAX_FILES_LOWRAM = 0;/' services/core/java/com/android/server/DropBoxManagerService.java;
sed -i 's/(notif.needNotify)/(true)/' location/java/com/android/internal/location/GpsNetInitiatedHandler.java; #Notify the user if their location is requested via SUPL
sed -i 's/return 16;/return 64;/' core/java/android/app/admin/DevicePolicyManager.java; #Increase default max password length to 64 (GrapheneOS)
sed -i 's/DEFAULT_STRONG_AUTH_TIMEOUT_MS = 72 \* 60 \* 60 \* 1000;/DEFAULT_STRONG_AUTH_TIMEOUT_MS = 12 * 60 * 60 * 1000;/' core/java/android/app/admin/DevicePolicyManager.java; #Decrease the strong auth prompt timeout to occur more often
sed -i 's/entry == null/entry == null || true/' core/java/android/os/RecoverySystem.java; #Skip strict update compatibiltity checks XXX: TEMPORARY FIX
sed -i 's/!Build.isBuildConsistent()/false/' services/core/java/com/android/server/am/ActivityManagerService.java; #Disable partition fingerprint mismatch warnings XXX: TEMPORARY FIX
hardenLocationFWB "$DOS_BUILD_BASE"; #Harden the default GPS config
#rm -rf packages/CompanionDeviceManager; #Used to support Android Wear (which hard depends on GMS)
rm -rf packages/Osu packages/Osu2; #Automatic Wi-Fi connection non-sense
rm -rf packages/PrintRecommendationService; #Creates popups to install proprietary print apps
fi;

if enterAndClear "frameworks/minikin"; then
applyPatch "$DOS_PATCHES/android_frameworks_minikin/345523.patch"; #n-asb-2022-12 Fix OOB read for registerLocaleList
applyPatch "$DOS_PATCHES/android_frameworks_minikin/345524.patch"; #n-asb-2022-12 Fix OOB crash for registerLocaleList
fi;

if enterAndClear "frameworks/native"; then
applyPatch "$DOS_PATCHES/android_frameworks_native/326752.patch"; #P_asb_2022-03 Check if the window is partially obscured for slippery enters
applyPatch "$DOS_PATCHES/android_frameworks_native/355772.patch"; #R_asb_2023-05 Check for malformed Sensor Flattenable
applyPatch "$DOS_PATCHES/android_frameworks_native/355773-backport.patch"; #R_asb_2023-05 Remove some new memory leaks from SensorManager
applyPatch "$DOS_PATCHES/android_frameworks_native/355774-backport.patch"; #R_asb_2023-05 Add removeInstanceForPackageMethod to SensorManager
applyPatch "$DOS_PATCHES/android_frameworks_native/365969-backport.patch"; #R_asb_2023-09 Allow sensors list to be empty
if [ "$DOS_SENSORS_PERM" = true ]; then applyPatch "$DOS_PATCHES/android_frameworks_native/0001-Sensors.patch"; fi; #Permission for sensors access (MSe1969)
fi;

if [ "$DOS_DEBLOBBER_REMOVE_IMS" = true ]; then
if enterAndClear "frameworks/opt/net/ims"; then
applyPatch "$DOS_PATCHES/android_frameworks_opt_net_ims/0001-Fix_Calling.patch"; #Fix calling when IMS is removed (DivestOS)
fi;
fi;

if enterAndClear "frameworks/opt/net/wifi"; then
#Fix an issue when permision review is enabled that prevents using the Wi-Fi quick tile (AndroidHardening)
#See https://github.com/AndroidHardening/platform_frameworks_opt_net_wifi/commit/c2a2f077a902226093b25c563e0117e923c7495b
sed -i 's/boolean mPermissionReviewRequired/boolean mPermissionReviewRequired = false/' service/java/com/android/server/wifi/WifiServiceImpl.java;
awk -i inplace '!/mPermissionReviewRequired = Build.PERMISSIONS_REVIEW_REQUIRED/' service/java/com/android/server/wifi/WifiServiceImpl.java;
awk -i inplace '!/\|\| context.getResources\(\).getBoolean\(/' service/java/com/android/server/wifi/WifiServiceImpl.java;
awk -i inplace '!/com.android.internal.R.bool.config_permissionReviewRequired/' service/java/com/android/server/wifi/WifiServiceImpl.java;
fi;

if enterAndClear "hardware/qcom/display"; then
applyPatch "$DOS_PATCHES_COMMON/android_hardware_qcom_display/CVE-2019-2306-msm8084.patch" --directory="msm8084"; #(Qualcomm)
applyPatch "$DOS_PATCHES_COMMON/android_hardware_qcom_display/CVE-2019-2306-msm8916.patch" --directory="msm8226";
applyPatch "$DOS_PATCHES_COMMON/android_hardware_qcom_display/CVE-2019-2306-msm8960.patch" --directory="msm8960";
applyPatch "$DOS_PATCHES_COMMON/android_hardware_qcom_display/CVE-2019-2306-msm8974.patch" --directory="msm8974";
applyPatch "$DOS_PATCHES_COMMON/android_hardware_qcom_display/CVE-2019-2306-msm8994.patch" --directory="msm8994";
#TODO: missing msm8909, msm8996, msm8998, sdm845
fi;

if enterAndClear "hardware/qcom/display-caf/apq8084"; then
applyPatch "$DOS_PATCHES_COMMON/android_hardware_qcom_display/CVE-2019-2306-apq8084.patch";
fi;

if enterAndClear "hardware/qcom/display-caf/msm8916"; then
applyPatch "$DOS_PATCHES_COMMON/android_hardware_qcom_display/CVE-2019-2306-msm8916.patch";
fi;

if enterAndClear "hardware/qcom/display-caf/msm8952"; then
applyPatch "$DOS_PATCHES_COMMON/android_hardware_qcom_display/CVE-2019-2306-msm8952.patch";
fi;

if enterAndClear "hardware/qcom/display-caf/msm8960"; then
applyPatch "$DOS_PATCHES_COMMON/android_hardware_qcom_display/CVE-2019-2306-msm8960.patch";
fi;

if enterAndClear "hardware/qcom/display-caf/msm8974"; then
applyPatch "$DOS_PATCHES_COMMON/android_hardware_qcom_display/CVE-2019-2306-msm8974.patch";
fi;

if enterAndClear "hardware/qcom/display-caf/msm8994"; then
applyPatch "$DOS_PATCHES_COMMON/android_hardware_qcom_display/CVE-2019-2306-msm8994.patch";
fi;

if enterAndClear "hardware/qcom/gps"; then
applyPatch "$DOS_PATCHES_COMMON/android_hardware_qcom_gps/0001-rollover.patch"; #Fix week rollover (jlask)
fi;

if enterAndClear "lineage-sdk"; then
awk -i inplace '!/WeatherManagerServiceBroker/' lineage/res/res/values/config.xml; #Disable Weather
if [ "$DOS_DEBLOBBER_REMOVE_AUDIOFX" = true ]; then awk -i inplace '!/LineageAudioService/' lineage/res/res/values/config.xml; fi; #Remove AudioFX
fi;

if enterAndClear "packages/apps/Bluetooth"; then
applyPatch "$DOS_PATCHES/android_packages_apps_Bluetooth/332758-backport.patch"; #P_asb_2022-06 Removes app access to BluetoothAdapter#setScanMode by requiring BLUETOOTH_PRIVILEGED permission.
applyPatch "$DOS_PATCHES/android_packages_apps_Bluetooth/332759-backport.patch"; #P_asb_2022-06 Removes app access to BluetoothAdapter#setDiscoverableTimeout by requiring BLUETOOTH_PRIVILEGED permission.
applyPatch "$DOS_PATCHES/android_packages_apps_Bluetooth/345907-backport.patch"; #P_asb_2022-12 Fix URI check in BluetoothOppUtility.java
applyPatch "$DOS_PATCHES/android_packages_apps_Bluetooth/349332-backport.patch"; #P_asb_2023-02 Fix OPP comparison
applyPatch "$DOS_PATCHES/android_packages_apps_Bluetooth/377014-backport.patch"; #R_asb_2023-12 Fix UAF in ~CallbackEnv
fi;

if enterAndClear "packages/apps/Contacts"; then
applyPatch "$DOS_PATCHES/android_packages_apps_Contacts/332760.patch"; #P_asb_2022-06 No longer export CallSubjectDialog
applyPatch "$DOS_PATCHES_COMMON/android_packages_apps_Contacts/0001-No_Google_Links.patch"; #Remove Privacy Policy and Terms of Service links (GrapheneOS)
applyPatch "$DOS_PATCHES_COMMON/android_packages_apps_Contacts/0003-Skip_Accounts.patch"; #Don't prompt to add account when creating a contact (CalyxOS)
applyPatch "$DOS_PATCHES_COMMON/android_packages_apps_Contacts/0004-No_GMaps.patch"; #Use common intent for directions instead of Google Maps URL (GrapheneOS)
fi;

if enterAndClear "packages/apps/Dialer"; then
applyPatch "$DOS_PATCHES/android_packages_apps_Dialer/332761.patch"; #P_asb_2022-06 No longer export CallSubjectDialog
fi;

if enterAndClear "packages/apps/KeyChain"; then
applyPatch "$DOS_PATCHES/android_packages_apps_KeyChain/334264.patch"; #P_asb_2022-07 Encode authority part of uri before showing in UI
fi;

if enterAndClear "packages/apps/LineageParts"; then
rm -rf src/org/lineageos/lineageparts/lineagestats/ res/xml/anonymous_stats.xml res/xml/preview_data.xml; #Nuke part of the analytics
applyPatch "$DOS_PATCHES/android_packages_apps_LineageParts/0001-Remove_Analytics.patch"; #Remove analytics (DivestOS)
cp -f "$DOS_PATCHES_COMMON/contributors.db" assets/contributors.db; #Update contributors cloud
fi;

if enterAndClear "packages/apps/Messaging"; then
applyPatch "$DOS_PATCHES_COMMON/android_packages_apps_Messaging/0001-null-fix.patch"; #Handle null case (GrapheneOS)
#applyPatch "$DOS_PATCHES_COMMON/android_packages_apps_Messaging/0002-missing-channels.patch"; #Add notification channels where missing (LineageOS)
fi;

if enterAndClear "packages/apps/PackageInstaller"; then
applyPatch "$DOS_PATCHES/android_packages_apps_PackageInstaller/344181.patch"; #P_asb_2022-11 Hide overlays on ReviewPermissionsAtivity
fi;

if enterAndClear "packages/apps/Nfc"; then
applyPatch "$DOS_PATCHES/android_packages_apps_Nfc/328346.patch"; #P_asb_2022-04 Do not set default contactless application without user interaction
applyPatch "$DOS_PATCHES/android_packages_apps_Nfc/332455-backport.patch"; #n-asb-2022-06 OOB read in phNciNfc_RecvMfResp()
applyPatch "$DOS_PATCHES/android_packages_apps_Nfc/346953-backport.patch"; #n-asb-2023-01 OOBW in Mfc_Transceive()
applyPatch "$DOS_PATCHES/android_packages_apps_Nfc/348653.patch"; #n-asb-2023-02 OOBW in phNciNfc_MfCreateXchgDataHdr
fi;

if enterAndClear "packages/apps/Settings"; then
applyPatch "$DOS_PATCHES/android_packages_apps_Settings/326758.patch"; #P_asb_2022-03 Fix bypass CALL_PRIVILEGED permission in AppRestrictionsFragment
applyPatch "$DOS_PATCHES/android_packages_apps_Settings/326759.patch"; #P_asb_2022-03 Add caller check to com.android.credentials.RESET
#applyPatch "$DOS_PATCHES/android_packages_apps_Settings/327099.patch"; #n-asb-2022-03 Add caller check to com.android.credentials.RESET
#applyPatch "$DOS_PATCHES/android_packages_apps_Settings/332763.patch"; #P_asb_2022-06 Prevent exfiltration of system files via user image settings. REVERTED IN P_asb_2022-12
applyPatch "$DOS_PATCHES/android_packages_apps_Settings/334265.patch"; #P_asb_2022-07 Fix LaunchAnyWhere in AppRestrictionsFragment
applyPatch "$DOS_PATCHES/android_packages_apps_Settings/335111.patch"; #P_asb_2022-08 Verify ringtone from ringtone picker is audio
applyPatch "$DOS_PATCHES/android_packages_apps_Settings/335114.patch"; #P_asb_2022-08 Fix Settings crash when setting a null ringtone
applyPatch "$DOS_PATCHES/android_packages_apps_Settings/335115.patch"; #P_asb_2022-08 Fix can't change notification sound for work profile.
#applyPatch "$DOS_PATCHES/android_packages_apps_Settings/335116.patch"; #P_asb_2022-08 Extract app label from component name in notification access confirmation UI #TODO: needs backport
applyPatch "$DOS_PATCHES/android_packages_apps_Settings/345911.patch"; #P_asb_2022-12 Prevent exfiltration of system files via avatar picker.
applyPatch "$DOS_PATCHES/android_packages_apps_Settings/345912-backport.patch"; #P_asb_2022-12 Add FLAG_SECURE for ChooseLockPassword and Pattern
applyPatch "$DOS_PATCHES/android_packages_apps_Settings/351914-backport.patch"; #P_asb_2023-03 FRP bypass defense in the settings app
applyPatch "$DOS_PATCHES/android_packages_apps_Settings/358568-backport.patch"; #R_asb_2023-06 Convert argument to intent in AddAccountSettings.
applyPatch "$DOS_PATCHES/android_packages_apps_Settings/365973-backport.patch"; #R_asb_2023-09 Prevent non-system IME from becoming device admin
applyPatch "$DOS_PATCHES/android_packages_apps_Settings/367639-backport.patch"; #n-asb-2023-10 Restrict ApnEditor settings
applyPatch "$DOS_PATCHES/android_packages_apps_Settings/401375-backport.patch"; #S_asb_2024-09 Limit wifi item edit content's max length to 500
applyPatch "$DOS_PATCHES/android_packages_apps_Settings/401377-backport.patch"; #S_asb_2024-09 Ignore fragment attr from ext authenticator resource
git revert --no-edit a96df110e84123fe1273bff54feca3b4ca484dcd; #Don't hide OEM unlock
applyPatch "$DOS_PATCHES/android_packages_apps_Settings/0001-Captive_Portal_Toggle.patch"; #Add option to disable captive portal checks (MSe1969)
if [ "$DOS_SENSORS_PERM" = true ]; then
applyPatch "$DOS_PATCHES/android_packages_apps_Settings/0005-Sensors-P1.patch"; #Permission for sensors access (MSe1969)
applyPatch "$DOS_PATCHES/android_packages_apps_Settings/0005-Sensors-P2.patch";
fi;
sed -i 's/private int mPasswordMaxLength = 16;/private int mPasswordMaxLength = 64;/' src/com/android/settings/password/ChooseLockPassword.java; #Increase default max password length to 64 (GrapheneOS)
sed -i 's/if (isFullDiskEncrypted()) {/if (false) {/' src/com/android/settings/accessibility/*AccessibilityService*.java; #Never disable secure start-up when enabling an accessibility service
fi;

if enterAndClear "packages/apps/SetupWizard"; then
applyPatch "$DOS_PATCHES/android_packages_apps_SetupWizard/0001-Remove_Analytics.patch"; #Remove analytics (DivestOS)
fi;

if enterAndClear "packages/apps/Trebuchet"; then
applyPatch "$DOS_PATCHES/android_packages_apps_Trebuchet/365974.patch"; #R_asb_2023-09 Fix permission issue in legacy shortcut
applyPatch "$DOS_PATCHES/android_packages_apps_Trebuchet/377015.patch"; #R_asb_2023-12 Fix permission bypass in legacy shortcut
fi;

if enterAndClear "packages/apps/TvSettings"; then
applyPatch "$DOS_PATCHES/android_packages_apps_TvSettings/358578.patch"; #R_asb_2023-06 Convert argument to intent in addAccount TvSettings.
fi;

if enterAndClear "packages/apps/Updater"; then
applyPatch "$DOS_PATCHES/android_packages_apps_Updater/0001-Server.patch"; #Switch to our server (DivestOS)
applyPatch "$DOS_PATCHES/android_packages_apps_Updater/0002-Tor_Support.patch"; #Add Tor support (DivestOS)
fi;

if enterAndClear "packages/apps/WallpaperPicker"; then
#TODO: Add back wallpapers
sed -i 's/req.touchEnabled = touchEnabled;/req.touchEnabled = true;/' src/com/android/wallpaperpicker/WallpaperCropActivity.java; #Allow scrolling
sed -i 's/mCropView.setTouchEnabled(req.touchEnabled);/mCropView.setTouchEnabled(true);/' src/com/android/wallpaperpicker/WallpaperCropActivity.java;
sed -i 's/WallpaperUtils.EXTRA_WALLPAPER_OFFSET, 0);/WallpaperUtils.EXTRA_WALLPAPER_OFFSET, 0.5f);/' src/com/android/wallpaperpicker/WallpaperPickerActivity.java; #Center aligned by default
fi;

if enterAndClear "packages/inputmethods/LatinIME"; then
applyPatch "$DOS_PATCHES_COMMON/android_packages_inputmethods_LatinIME/0001-Voice.patch"; #Remove voice input key (DivestOS)
applyPatch "$DOS_PATCHES_COMMON/android_packages_inputmethods_LatinIME/0002-Disable_Personalization.patch"; #Disable personalization dictionary by default (GrapheneOS)
fi;

if enterAndClear "packages/providers/ContactsProvider"; then
applyPatch "$DOS_PATCHES/android_packages_providers_ContactsProvider/335110.patch"; #P_asb_2022-08 enforce stricter CallLogProvider query
fi;

if enterAndClear "packages/providers/DownloadProvider"; then
applyPatch "$DOS_PATCHES/android_packages_providers_DownloadProvider/383567.patch"; #P_asb_2024-02 Consolidate queryChildDocumentsXxx() implementations
fi;

if enterAndClear "packages/providers/MediaProvider"; then
applyPatch "$DOS_PATCHES/android_packages_providers_MediaProvider/0001-External_Permission.patch"; #Fix permission denial (luca.stefani)
fi;

if enterAndClear "packages/providers/TelephonyProvider"; then
applyPatch "$DOS_PATCHES/android_packages_providers_TelephonyProvider/344182.patch"; #P_asb_2022-11 Check dir path before updating permissions.
applyPatch "$DOS_PATCHES/android_packages_providers_TelephonyProvider/364040-backport.patch"; #R_asb_2023-08 Update file permissions using canonical path
applyPatch "$DOS_PATCHES/android_packages_providers_TelephonyProvider/373957-backport.patch"; #R_asb_2023-11 Block access to sms/mms db from work profile.
fi;

if enterAndClear "packages/services/Telecomm"; then
applyPatch "$DOS_PATCHES/android_packages_services_Telecomm/332764.patch"; #P_asb_2022-06 limit TelecomManager#registerPhoneAccount to 10
applyPatch "$DOS_PATCHES/android_packages_services_Telecomm/344183.patch"; #P_asb_2022-11 switch TelecomManager List getters to ParceledListSlice
applyPatch "$DOS_PATCHES/android_packages_services_Telecomm/345913.patch"; #P_asb_2022-12 Hide overlay windows when showing phone account enable/disable screen.
applyPatch "$DOS_PATCHES/android_packages_services_Telecomm/347042.patch"; #P_asb_2023-01 Fix security vulnerability when register phone accounts.
applyPatch "$DOS_PATCHES/android_packages_services_Telecomm/355777-backport.patch"; #R_asb_2023-05 enforce stricter rules when registering phoneAccount
applyPatch "$DOS_PATCHES/android_packages_services_Telecomm/364041-backport.patch"; #R_asb_2023-08 Resolve StatusHints image exploit across user.
applyPatch "$DOS_PATCHES/android_packages_services_Telecomm/377016-backport.patch"; #R_asb_2023-12 Resolve account image icon profile boundary exploit.
applyPatch "$DOS_PATCHES/android_packages_services_Telecomm/401380-backport.patch"; #S_asb_2024-09 Unbind CS if connection is not created within 15 seconds. #XXX
fi;

if enterAndClear "packages/services/Telephony"; then
applyPatch "$DOS_PATCHES/android_packages_services_Telephony/347041-backport.patch"; #P_asb_2023-01 Prevent overlays on the phone settings
applyPatch "$DOS_PATCHES/android_packages_services_Telephony/365978-backport.patch"; #R_asb_2023-09 Fixed leak of cross user data in multiple settings.
applyPatch "$DOS_PATCHES/android_packages_services_Telephony/0001-PREREQ_Handle_All_Modes.patch"; #(DivestOS)
applyPatch "$DOS_PATCHES/android_packages_services_Telephony/0002-More_Preferred_Network_Modes.patch";
fi;

if enterAndClear "system/bt"; then
applyPatch "$DOS_PATCHES/android_system_bt/328347.patch"; #P_asb_2022-04 Security fix OOB read due to invalid count in stack/avrc/avrc_pars_ct
applyPatch "$DOS_PATCHES/android_system_bt/334266.patch"; #P_asb_2022-07 Security: Fix out of bound write in HFP client
applyPatch "$DOS_PATCHES/android_system_bt/334267.patch"; #P_asb_2022-07 Check Avrcp packet vendor length before extracting length
applyPatch "$DOS_PATCHES/android_system_bt/334268.patch"; #P_asb_2022-07 Security: Fix out of bound read in AT_SKIP_REST
applyPatch "$DOS_PATCHES/android_system_bt/335109.patch"; #P_asb_2022-08 Removing bonded device when auth fails due to missing keys
applyPatch "$DOS_PATCHES/android_system_bt/337995-backport.patch"; #Q_asb_2022-09 Fix OOB in bnep_is_packet_allowed
applyPatch "$DOS_PATCHES/android_system_bt/337996.patch"; #Q_asb_2022-09 Fix OOB in BNEP_Write
applyPatch "$DOS_PATCHES/android_system_bt/337997.patch"; #Q_asb_2022-09 Fix OOB in reassemble_and_dispatch
applyPatch "$DOS_PATCHES/android_system_bt/342097.patch"; #P_asb_2022-10 Fix potential interger overflow when parsing vendor response
applyPatch "$DOS_PATCHES/android_system_bt/344184.patch"; #P_asb_2022-11 Add negative length check in process_service_search_rsp
applyPatch "$DOS_PATCHES/android_system_bt/344185.patch"; #P_asb_2022-11 Add buffer in pin_reply in bluetooth.cc
applyPatch "$DOS_PATCHES/android_system_bt/345914.patch"; #P_asb_2022-12 Add length check when copy AVDTP packet
applyPatch "$DOS_PATCHES/android_system_bt/345915.patch"; #P_asb_2022-12 Added max buffer length check
applyPatch "$DOS_PATCHES/android_system_bt/345916.patch"; #P_asb_2022-12 Add missing increment in bnep_api.cc
applyPatch "$DOS_PATCHES/android_system_bt/345917.patch"; #P_asb_2022-12 Add length check when copy AVDT and AVCT packet
applyPatch "$DOS_PATCHES/android_system_bt/345918.patch"; #P_asb_2022-12 Fix integer overflow when parsing avrc response
applyPatch "$DOS_PATCHES/android_system_bt/347127.patch"; #P_asb_2023-01 Once AT command is retrieved, return from method.
applyPatch "$DOS_PATCHES/android_system_bt/347128.patch"; #P_asb_2023-01 AVRC: Validating msg size before accessing fields
#applyPatch "$DOS_PATCHES/android_system_bt/349334-backport.patch"; #P_asb_2023-02 Report failure when not able to connect to AVRCP XXX: doesn't compile
applyPatch "$DOS_PATCHES/android_system_bt/349335.patch"; #P_asb_2023-02 Add bounds check in avdt_scb_act.cc
applyPatch "$DOS_PATCHES/android_system_bt/351916.patch"; #P_asb_2023-03 Fix an OOB Write bug in gatt_check_write_long_terminate
applyPatch "$DOS_PATCHES/android_system_bt/351917.patch"; #P_asb_2023-03 Fix an OOB access bug in A2DP_BuildMediaPayloadHeaderSbc
applyPatch "$DOS_PATCHES/android_system_bt/351918.patch"; #P_asb_2023-03 Fix an OOB write in SDP_AddAttribute
applyPatch "$DOS_PATCHES/android_system_bt/354246.patch"; #P_asb_2023-04 Fix OOB access in avdt_scb_hdl_pkt_no_frag
applyPatch "$DOS_PATCHES/android_system_bt/354247.patch"; #P_asb_2023-04 Fix an OOB bug in register_notification_rsp
applyPatch "$DOS_PATCHES/android_system_bt/358580.patch"; #R_asb_2023-06 Prevent use-after-free of HID reports
applyPatch "$DOS_PATCHES/android_system_bt/358581-backport.patch"; #R_asb_2023-06 Revert "Revert "[RESTRICT AUTOMERGE] Validate buffer length in sdpu_build_uuid_seq""
applyPatch "$DOS_PATCHES/android_system_bt/358582.patch"; #R_asb_2023-06 Revert "Revert "Fix wrong BR/EDR link key downgrades (P_256->P_192)""
applyPatch "$DOS_PATCHES/android_system_bt/360969.patch"; #R_asb_2023-07 Fix gatt_end_operation buffer overflow
applyPatch "$DOS_PATCHES/android_system_bt/365979.patch"; #R_asb_2023-09 Fix an integer overflow bug in avdt_msg_asmbl
applyPatch "$DOS_PATCHES/android_system_bt/365980.patch"; #R_asb_2023-09 Fix integer overflow in build_read_multi_rsp
applyPatch "$DOS_PATCHES/android_system_bt/365981.patch"; #R_asb_2023-09 Fix potential abort in btu_av_act.cc
applyPatch "$DOS_PATCHES/android_system_bt/365982-prereq.patch"; #Fix reliable write
applyPatch "$DOS_PATCHES/android_system_bt/365982.patch"; #R_asb_2023-09 Fix UAF in gatt_cl.cc
applyPatch "$DOS_PATCHES/android_system_bt/377017.patch"; #R_asb_2023-12 Reject access to secure service authenticated from a temp bonding [1]
applyPatch "$DOS_PATCHES/android_system_bt/377018.patch"; #R_asb_2023-12 Reject access to secure services authenticated from temp bonding [2]
applyPatch "$DOS_PATCHES/android_system_bt/377019.patch"; #R_asb_2023-12 Reject access to secure service authenticated from a temp bonding [3]
applyPatch "$DOS_PATCHES/android_system_bt/377020-backport.patch"; #R_asb_2023-12 Reorganize the code for checking auth requirement
applyPatch "$DOS_PATCHES/android_system_bt/377021.patch"; #R_asb_2023-12 Enforce authentication if encryption is required
applyPatch "$DOS_PATCHES/android_system_bt/377023-backport.patch"; #R_asb_2023-12 Fix timing attack in BTM_BleVerifySignature
applyPatch "$DOS_PATCHES/android_system_bt/377030.patch"; #R_asb_2023-12 Fix OOB Write in pin_reply in bluetooth.cc
applyPatch "$DOS_PATCHES/android_system_bt/377031.patch"; #R_asb_2023-12 BT: Fixing the rfc_slot_id overflow
applyPatch "$DOS_PATCHES/android_system_bt/379154-prereq-1.patch"; #R_asb_2024-01 Fix addr_type overriding by btm_ble_process_adv_addr().
applyPatch "$DOS_PATCHES/android_system_bt/379154-prereq-2.patch"; #R_asb_2024-01 LE Advertising Report parsing enhancements
applyPatch "$DOS_PATCHES/android_system_bt/379154.patch"; #R_asb_2024-01 Fix some OOB errors in BTM parsing
applyPatch "$DOS_PATCHES/android_system_bt/381894-backport.patch"; #R_asb_2024-02 Fix an OOB bug in btif_to_bta_response and attp_build_value_cmd
applyPatch "$DOS_PATCHES/android_system_bt/381895.patch"; #R_asb_2024-02 Fix an OOB write bug in attp_build_read_by_type_value_cmd
#applyPatch "$DOS_PATCHES/android_system_bt/385675.patch"; #P_asb_2024-03 Fix OOB caused by invalid SMP packet length #XXX: needs to switch to `reason =` or backport `smp_int_data.status`
#applyPatch "$DOS_PATCHES/android_system_bt/385676-backport.patch"; #P_asb_2024-03 Fix an OOB bug in smp_proc_sec_req #XXX: alternatively forward-port 385236 & 385237
applyPatch "$DOS_PATCHES/android_system_bt/385677.patch"; #P_asb_2024-03 Reland: Fix an OOB write bug in attp_build_value_cmd
applyPatch "$DOS_PATCHES/android_system_bt/385678.patch"; #P_asb_2024-03 Fix a security bypass issue in access_secure_service_from_temp_bond
applyPatch "$DOS_PATCHES/android_system_bt/397596.patch"; #P_asb_2024-07 Fix an authentication bypass bug in SMP
applyPatch "$DOS_PATCHES/android_system_bt/399772-backport.patch"; #P_asb_2024-08 Fix heap-buffer overflow in sdp_utils.cc #XXX
fi;

if enterAndClear "system/ca-certificates"; then
rm -rf files; #Remove old certs
cp -r "$DOS_PATCHES_COMMON/android_system_ca-certificates/files" .; #Copy the new ones into place
fi;

if enterAndClear "system/core"; then
applyPatch "$DOS_PATCHES/android_system_core/332765.patch"; #P_asb_2022-06 Backport of Win-specific suppression of potentially rogue construct that can engage in directory traversal on the host.
if [ "$DOS_HOSTS_BLOCKING" = true ]; then cat "$DOS_HOSTS_FILE" >> rootdir/etc/hosts; fi; #Merge in our HOSTS file
git revert --no-edit a6a4ce8e9a6d63014047a447c6bb3ac1fa90b3f4; #Always update recovery
applyPatch "$DOS_PATCHES/android_system_core/0001-Harden.patch"; #Harden mounts with nodev/noexec/nosuid + misc sysctl changes (GrapheneOS)
applyPatch "$DOS_PATCHES/android_system_core/0002-HM-Increase_vm_mmc.patch"; #(GrapheneOS)
fi;

if enterAndClear "system/libfmq"; then
applyPatch "$DOS_PATCHES_COMMON/android_system_libfmq/399071.patch"; #Q_asb_2024-06 Use the values of the ptrs that we check
fi;

if enterAndClear "system/netd"; then
applyPatch "$DOS_PATCHES/android_system_netd/377024-backport.patch"; #R_asb_2023-12 Fix Heap-use-after-free in MDnsSdListener::Monitor::run #XXX
#applyPatch "$DOS_PATCHES/android_system_netd/0001-Fix_DNS_leaks.patch"; #Fix DNS leak in VPN lockdown mode when VPN is down (GrapheneOS) #XXX can break apps without relaxed variant backport
fi;

if enterAndClear "system/nfc"; then
applyPatch "$DOS_PATCHES/android_system_nfc/332767.patch"; #P_asb_2022-06 Double Free in ce_t4t_data_cback
applyPatch "$DOS_PATCHES/android_system_nfc/332458-backport.patch"; #n-asb-2022-06 Out of Bounds Read in nfa_dm_check_set_config
applyPatch "$DOS_PATCHES/android_system_nfc/344180-backport.patch"; #P_asb_2022-11 OOBW in phNxpNciHal_write_unlocked()
applyPatch "$DOS_PATCHES/android_system_nfc/353760-backport.patch"; #n-asb-2023-04 OOBW in nci_snd_set_routing_cmd()
fi;

if enterAndClear "system/sepolicy"; then
applyPatch "$DOS_PATCHES/android_system_sepolicy/0002-protected_files.patch"; #label protected_{fifos,regular} as proc_security (GrapheneOS)
git am "$DOS_PATCHES/android_system_sepolicy/0001-LGE_Fixes.patch"; #Fix -user builds for LGE devices (DivestOS)
patch -p1 < "$DOS_PATCHES/android_system_sepolicy/0001-LGE_Fixes.patch" --directory="prebuilts/api/26.0";
fi;

if enterAndClear "vendor/nxp/opensource/external/libnfc-nci"; then #keep in sync with system/nfc
applyPatch "$DOS_PATCHES/android_vendor_nxp_opensource_external_libnfc-nci/332771.patch"; #P_asb_2022-06 Double Free in ce_t4t_data_cback
applyPatch "$DOS_PATCHES/android_vendor_nxp_opensource_external_libnfc-nci/332458-backport.patch"; #n-asb-2022-06 Out of Bounds Read in nfa_dm_check_set_config
applyPatch "$DOS_PATCHES/android_vendor_nxp_opensource_external_libnfc-nci/332459-backport.patch"; #n-asb-2022-06 OOBR in nfc_ncif_proc_ee_discover_req()
applyPatch "$DOS_PATCHES/android_vendor_nxp_opensource_external_libnfc-nci/344190-backport.patch"; #P_asb_2022-11 OOBW in phNxpNciHal_write_unlocked()
applyPatch "$DOS_PATCHES/android_vendor_nxp_opensource_external_libnfc-nci/353760-backport.patch"; #n-asb-2023-04 OOBW in nci_snd_set_routing_cmd()
applyPatch "$DOS_PATCHES/android_vendor_nxp_opensource_external_libnfc-nci/360898-backport.patch"; #n-asb-2023-07 OOBW in rw_i93_send_to_upper()
fi;

if enterAndClear "vendor/nxp/opensource/packages/apps/Nfc"; then #keep in sync with packages/apps/Nfc
applyPatch "$DOS_PATCHES/android_vendor_nxp_opensource_packages_apps_Nfc/252808-backport.patch"; #n-asb-2019-08 Prevent OOB write in Mfc_Transceive
applyPatch "$DOS_PATCHES/android_vendor_nxp_opensource_packages_apps_Nfc/328348-backport.patch"; #P_asb_2022-04 Do not set default contactless application without user interaction
applyPatch "$DOS_PATCHES/android_vendor_nxp_opensource_packages_apps_Nfc/346953-backport.patch"; #n-asb-2023-01 OOBW in Mfc_Transceive()
applyPatch "$DOS_PATCHES/android_vendor_nxp_opensource_packages_apps_Nfc/348653.patch"; #n-asb-2023-02 OOBW in phNciNfc_MfCreateXchgDataHdr
fi;

if enterAndClear "vendor/lineage"; then
rm build/target/product/security/lineage.x509.pem; #Remove Lineage keys
rm -rf overlay/common/lineage-sdk/packages/LineageSettingsProvider/res/values/defaults.xml; #Remove analytics
rm -rf verity_tool; #Resurrect dm-verity
rm -rf overlay/common/frameworks/base/core/res/res/drawable-*/default_wallpaper.png; #Remove Lineage wallpaper
if [ "$DOS_HOSTS_BLOCKING" = true ]; then awk -i inplace '!/50-lineage.sh/' config/common.mk; fi; #Make sure our hosts is always used
awk -i inplace '!/PRODUCT_EXTRA_RECOVERY_KEYS/' config/common.mk; #Remove Lineage extra keys
awk -i inplace '!/security\/lineage/' config/common.mk; #Remove Lineage extra keys
awk -i inplace '!/WeatherProvider/' config/common.mk; #Remove Weather
awk -i inplace '!/config_multiuserMaximumUsers/' overlay/common/frameworks/base/core/res/res/values/config.xml; #Conflict
awk -i inplace '!/def_backup_transport/' overlay/common/frameworks/base/packages/SettingsProvider/res/values/defaults.xml; #Unset default backup provider
if [ "$DOS_DEBLOBBER_REMOVE_AUDIOFX" = true ]; then awk -i inplace '!/AudioFX/' config/common.mk; fi; #Remove AudioFX
sed -i 's/LINEAGE_BUILDTYPE := UNOFFICIAL/LINEAGE_BUILDTYPE := dos/' config/common.mk; #Change buildtype
echo 'include vendor/divested/divestos.mk' >> config/common.mk; #Include our customizations
cp -f "$DOS_PATCHES_COMMON/apns-conf.xml" prebuilt/common/etc/apns-conf.xml; #Update APN list
awk -i inplace '!/Eleven/' config/common.mk; #Remove Music Player
awk -i inplace '!/Exchange2/' config/common.mk; #Remove Email
cp -f "$DOS_PATCHES_COMMON/config_webview_packages.xml" overlay/common/frameworks/base/core/res/res/xml/config_webview_packages.xml; #Change allowed WebView providers
fi;
#
#END OF ROM CHANGES
#

#
#START OF DEVICE CHANGES
#
#none yet

#Make changes to all devices
cd "$DOS_BUILD_BASE";
find "hardware/qcom/gps" -name "gps\.conf" -type f -print0 | xargs -0 -n 1 -P 4 -I {} bash -c 'hardenLocationConf "{}"';
find "device" -name "gps\.conf*" -type f -print0 | xargs -0 -n 1 -P 4 -I {} bash -c 'hardenLocationConf "{}"';
find "vendor" -name "gps\.conf" -type f -print0 | xargs -0 -n 1 -P 4 -I {} bash -c 'hardenLocationConf "{}"';
find "device" -type d -name "overlay" -print0 | xargs -0 -n 1 -P 4 -I {} bash -c 'hardenLocationFWB "{}"';
if [ "$DOS_DEBLOBBER_REMOVE_IMS" = "false" ]; then find "device" -maxdepth 2 -mindepth 2 -type d -print0 | xargs -0 -n 1 -P 8 -I {} bash -c 'volteOverride "{}"'; fi;
find "device" -maxdepth 2 -mindepth 2 -type d -print0 | xargs -0 -n 1 -P 8 -I {} bash -c 'enableDexPreOpt "{}"';
find "device" -maxdepth 2 -mindepth 2 -type d -print0 | xargs -0 -n 1 -P 8 -I {} bash -c 'hardenUserdata "{}"';
find "kernel" -maxdepth 2 -mindepth 2 -type d -print0 | xargs -0 -n 1 -P 4 -I {} bash -c 'hardenDefconfig "{}"';
find "kernel" -maxdepth 2 -mindepth 2 -type d -print0 | xargs -0 -n 1 -P 8 -I {} bash -c 'updateRegDb "{}"';
cd "$DOS_BUILD_BASE";
deblobAudio;
removeBuildFingerprints;
hardenLocationSerials || true;
changeDefaultDNS; #Change the default DNS servers
removeUntrustedCerts || true;

#Tweaks for <2GB RAM devices
enableLowRam "device/asus/fugu";
#Tweaks for <3GB RAM devices
#enableLowRam "device/htc/flounder";
#enableLowRam "device/htc/flounder_lte";
#enableLowRam "device/lge/bullhead";
#Tweaks for 2GB/3GB RAM devices
#enableLowRam "device/asus/Z00T";
#Tweaks for <4GB RAM devices
#enableLowRam "device/huawei/angler";
#enableLowRam "device/google/dragon";

#Fix broken options enabled by hardenDefconfig()
[[ -d kernel/zte/msm8996 ]] && sed -i "s/CONFIG_STRICT_MEMORY_RWX=y/# CONFIG_STRICT_MEMORY_RWX is not set/" kernel/zte/msm8996/arch/arm64/configs/lineageos_*_defconfig; #Breaks on compile

sed -i 's/^YYLTYPE yylloc;/extern YYLTYPE yylloc;/' kernel/*/*/scripts/dtc/dtc-lexer.l* || true; #Fix builds with GCC 10
rm -v kernel/*/*/drivers/staging/greybus/tools/Android.mk || true;
#
#END OF DEVICE CHANGES
#
echo -e "\e[0;32m[SCRIPT COMPLETE] Primary patching finished\e[0m";
