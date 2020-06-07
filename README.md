![Timesys Vigiles](https://www.timesys.com/wp-content/uploads/vigiles-cve-monitoring.png "Timesys Vigiles")

What is meta-timesys?
=====================

This Yocto layer provides scripts for image manifest generation used for security monitoring and notification as part of the **[Timesys Vigiles](https://www.timesys.com/security/vigiles/)** product offering.


What is Vigiles?
================

Vigiles is a vulnerability management tool that provides build-time Yocto CVE Analysis of target images. It does this by collecting metadata about packages to be installed and uploading it to be compared against the Timesys CVE database.A high-level overview of the detected vulnerabilities is returned and a full detailed analysis can be viewed online.


Register (free) and download the API key to access the full feature set based on Vigiles Basic, Plus or Prime:
https://linuxlink.timesys.com/docs/wiki/engineering/LinuxLink_Key_File


Pre-Requisites
==============

A BitBake build environment is required for the Vigiles CVE Scanner to evaluate the potential risk of a target system. 

The fastest way to use the Vigiles CVE Scanner is to integrate it into your existing BSP (clone alongside other layers, add to bblayers.conf). 


If you do not already have an environment configured, please use the following to boot-strap a minimal setup.


### Review the Yocto system requirements here:

https://www.yoctoproject.org/docs/2.6/ref-manual/ref-manual.html#ref-manual-system-requirements

### Clone poky and meta-timesys

```sh
RELEASE=thud
git clone git://git.yoctoproject.org/poky.git -b $RELEASE
git clone https://github.com/TimesysGit/meta-timesys.git -b $RELEASE
```

### Activate yocto build environment (needed for manifest creation)

```sh
source poky/oe-init-build-env
```


Using Vigiles
=============

### Add meta-timesys to _conf/bblayers.conf_

Follow format of the file, just add meta-timesys after the default poky/meta, etc. 

```
BBLAYERS += "${TOPDIR}/../meta-timesys"
```


### Append _vigiles_ to **INHERIT** in _conf/local.conf_

```
INHERIT += "vigiles"
```

### Check an Image for CVEs

When you build any image, the Vigiles CVE Scanner will execute automatically:

```sh
bitbake core-image-minimal
```


### Review the Output

An overview will be printed to the console after the check is complete and a persistent local summary will be created in the 
_vigiles/\<image name\>/_ directory for that build. A symlink is created to the latest report at _vigiles/\<image name\>-report.txt_:

```sh
$ readlink vigiles/core-image-minimal-report.txt
core-image-minimal/core-image-minimal-2019-06-07_19.22.40-report.txt
```

_The output will differ based on whether you are running with a LinuxLink subscription or in Demo Mode_.


##### Subscription Mode Console Output
```
Vigiles: Requesting image analysis from LinuxLink ...


-- Vigiles CVE Report --

	View detailed online report at:
	  https://linuxlink.timesys.com/cves/reports/ODUzOA.D9xLIQ.KKiK2E76n---q6_-KmJrsZ9ap9Y

	Unfixed: 62 (0 RFS, 60 Kernel, 2 Toolchain)
	Unfixed, Patch Available: 7 (2 RFS, 0 Kernel, 5 Toolchain)
	Fixed: 0 (0 RFS, 0 Kernel, 0 Toolchain)
	High CVSS: 30 (2 RFS, 24 Kernel, 4 Toolchain)

	Local summary written to:
	  vigiles/core-image-minimal/core-image-minimal-2019-06-07_19.22.40-report.txt
```

##### Demo Mode Console Output
```
-- Vigiles Demo Mode Notice --
	No API keyfile was found, or the contents were invalid.

	Please see this document for API key information:
	https://linuxlink.timesys.com/docs/wiki/engineering/LinuxLink_Key_File

	The script will continue in demo mode, which will link you to temporarily available online results only.
	You will need to login or register for a free account in order to see the report.

	For more information on the security notification service, please visit:
	https://www.timesys.com/security/vulnerability-patch-notification/

Vigiles: Requesting image analysis from LinuxLink ...


-- Vigiles CVE Report --

	Complete online report at:
	  https://linuxlink.timesys.com/cves/reports/ODUyMA.D9wwnQ.9MTUnSVk6Xi-Q1kO0ea--e4wVJ4
	  NOTE: Running in Demo Mode will cause this URL to expire after one day.

-- Vigiles CVE Overview --

	Unfixed: 62
	Unfixed, Patch Available: 7
	Fixed: 0
	CPU: 0


	Local summary written to:
	  vigiles/core-image-minimal/core-image-minimal-2019-06-07_17.29.31-report.txt
```


Interpreting the Results
========================

### Console Output

A CVE summary is printed in both Subscription and Demo modes and contains the following. 

* "Unfixed" CVEs are existing CVEs that have been reported against packages to be installed.

* "Patch Available" CVEs have a fix available in the meta-timesys-security layer.
  If the layer is already included, then you may need to update your copy.

* "Fixed" CVEs are those that originally existed in packages to be installed, but have been fixed/mitigated by subsequent patches.

* "CPU" CVEs are filed against the hardware. They may be fixed or mitigated in other components such as the kernel or compiler.

* "High CVSS" (_Subscription Mode Only_) CVEs are those that are of utmost priority and require immediate attention, based on their Common Vulnerability Scoring System (v3) ranking.


Additionally, in Subscription Mode, the distribution of the vulnerabilities across system components will be displayed.


### Online Report

The Vigiles CVE online report specified in the output provides a dashboard interface for examining all known details about each CVE detected, including the affected version ranges, priority and existing mitigations.


### Local Summary

In both operating modes, the local summary will include the console output as well as descriptive information about the report instance. In Subscription Mode, additional information is included about each CVE that the scan detects, as well as any fixes that have been applied. This is an example from the reports generated above.

```
-- Recipe CVEs --
        Recipe:  glibc
        Version: 2.28
        CVE ID:  CVE-2019-9192
        URL:     https://nvd.nist.gov/vuln/detail/CVE-2019-9192
        CVSSv3:  7.5
        Vector:  NETWORK
        Status:  Unfixed

        Recipe:  glibc
        Version: 2.28
        CVE ID:  CVE-2016-10739
        URL:     https://nvd.nist.gov/vuln/detail/CVE-2016-10739
        CVSSv3:  5.3
        Vector:  LOCAL
        Status:  Unfixed, Patch Available
        Patched in meta-timesys-security commit(s):
        * bfb9cf83582e4cffd6c9cdbadddc68302fa350cc

        Recipe:  linux-yocto
        Version: 4.18.27
        CVE ID:  CVE-2019-9162
        URL:     https://nvd.nist.gov/vuln/detail/CVE-2019-9162
        CVSSv3:  7.8
        Vector:  LOCAL
        Status:  Unfixed
```


### CVE Manifest

The Vigiles CVE Scanner creates and sends a manifest describing your build to the LinuxLink Server. This manifest is located at

```sh
$ readlink vigiles/core-image-minimal-cve.json 
core-image-minimal/core-image-minimal-2019-09-09_23.08.28-cve.json
```

In the event that something goes wrong, or if the results seem incorrect, this file may offer insight as to why.
It's important to include this file with any support request.


Advanced Usage
==============


### Vigiles Whitelist

"Whitelist" Recipes and CVEs are listed in the "VIGILES_WHITELIST" variable. They are NOT included in the report.

The Whitelist can be adjusted in _conf/local.conf_ by appending **VIGILES_WHITELIST**:

```
VIGILES_WHITELIST += "\
	CVE-1234-ABCD \
"
```


### Kernel Config Filter

The Vigiles CVE Scanner can be configured to upload a Linux Kernel _.config_ file to LinuxLink along with the image manifest. This filter will reduce the number of kernel CVEs reported by removing those related to features which are not being built for your kernel. There are 2 ways to enable this feature -- Automatic Detection or Manual Specification

* Automatic Detection

This will use the _.config_ for the kernel specified in ```PREFERRED_PROVIDER_virtual/kernel``` once the yocto task ```do_configure``` is executed. 


```
VIGILES_KERNEL_CONFIG = "auto"
```


* Manual Specification

**NOTE: This must be a _full_ kernel config, not a defconfig!**

```
VIGILES_KERNEL_CONFIG = "/projects/kernel/linux-4.14-ts+imx-1.0/.config"
```


### Specifying a LinuxLink Key File

Full CVE reporting requires a LinuxLink License Key, though the Vigiles CVE Scanner will still execute in 
Demo Mode and produce an abbreviated report if one is not configured.

To use an alternate key, or a key in a non-default location, you can specify the location in _conf/local.conf_ with a statement like the following:

```
VIGILES_KEY_FILE = "/tools/timesys/linuxlink_key"
```

### Specifying a Product or Manifest

By default your manifest will be uploaded under the "Private Workspace" product on the Vigiles Dashboard.
To upload your manifest to a particular product or existing manifest on the Vigiles Dashboard, download the associated Dashboard Config to `~/timesys/dashboard_config`.
Dashboard Configs downloaded from the [Products page](https://linuxlink.timesys.com/vigiles/) will upload new manifests to the associated product with a default name.
The link can be found under the Actions column for each product. Note: Click on "New Product" if you have not yet created one.

To use an alternate config, or a config in a non-default location, you can specify the location in _conf/local.conf_ with a statement like the following:

```
VIGILES_DASHBOARD_CONFIG = "/tools/timesys/dashboard_config"
```


### Specifying Additional Packages to Check

In some cases, a BSP may want to include packages that are built outside of
the Bitbake/Yocto process. If this is required, ```VIGILES_EXTRA_PACKAGES```
may be used to specify one or more CSV (comma-separated-value) files that
describe the extra packages to include in the CVE check.

For example, one may set this in their local.conf:

```
VIGILES_EXTRA_PACKAGES = "${HOME}/projects/this-bsp/non-yocto/yocto-extra.csv"
```

or perhaps:

```
VIGILES_EXTRA_PACKAGES = " \
	${HOME}/projects/this-bsp/non-yocto/yocto-extra-boot.csv \
	${HOME}/projects/this-bsp/non-yocto/yocto-extra-ui.csv   \
"
```

##### CSV Format

The CSV files consist of an optional header and the following fields:

* Product - the CPE Name that packages use in CVEs
* (optional) Version - the version of the package used.
* (optional) License - the license of the package used

The following example shows the accepted syntax for expressing extra packages:

```sh
$ cat yocto-extra.csv
product,version,license
avahi,0.6
bash,4.0
bash,4.1,GPL 3.0
busybox,
udev,,"GPLv2.0+, LGPL-2.1+"
```


### Excluding Packages From the CVE Check

In some cases, a BSP may want to _exclude_ packages from the Vigiles Report;
for instance to condense the output by removing packages that are 'installed'
but have no files (e.g. packagegroups or those that only install data files).

This can be done by setting ```VIGILES_EXCLUDE``` to a space-separated list
of one or more CSV files that contain a list of packages to drop from the
generated manifest before it is submitted for the CVE check.

For example, in ```conf/local.conf```:

```
VIGILES_EXCLUDE = "${TOPDIR}/vigiles-exclude.csv"
```

And in ```${TOPDIR}/vigiles-exclude.csv```:


```
linux-libc-headers
opkg-utils
packagegroup-core-boot
```

>Note: filtering of packages is performed as the final step in constructing
>the manifest, after any additional packages are included.


Maintenance
===========

The Vigiles CVE Scanner and meta-timesys are maintained by [The Timesys Security team](mailto:vigiles@timesys.com).

For Updates, Support and More Information, please see:

[Vigiles Website](https://www.timesys.com/security/vigiles/)

and

[meta-timesys @ GitHub](https://github.com/TimesysGit/meta-timesys)

