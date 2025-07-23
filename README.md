What is meta-timesys?
=====================

This Yocto layer provides scripts for SBOM generation used for vulnerability monitoring and notification as part of the **[Vigiles](https://www.lynx.com/solutions/vulnerability-mitigation-management)** product offering.


What is Vigiles?
================

Vigiles is a vulnerability management tool that provides build-time Yocto CVE Analysis of target images. It does this by collecting metadata about packages to be installed and uploading it to be compared against the Vigiles CVE database.A high-level overview of the detected vulnerabilities is returned and a full detailed analysis can be viewed online.


To request a trial account, please get in touch with us at sales@timesys.com


Pre-Requisites
==============

A BitBake build environment is required for the Vigiles CVE Scanner to evaluate the potential risk of a target system. 

The fastest way to use the Vigiles CVE Scanner is to integrate it into your existing BSP (clone alongside other layers, add to bblayers.conf). 


If you do not already have an environment configured, please use the following to boot-strap a minimal setup.


### Review the Yocto system requirements here:

https://docs.yoctoproject.org/5.0/ref-manual/system-requirements.html#system-requirements

### Clone poky and meta-timesys

```sh
RELEASE=scarthgap
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


##### Console Output
```
Vigiles: Requesting image analysis ...


-- Vigiles CVE Report --

	View detailed online report at:
	  https://vigiles.lynx.com/cves/reports/ODUzOA.D9xLIQ.KKiK2E76n---q6_-KmJrsZ9ap9Y

	Unfixed: 62 (0 RFS, 60 Kernel, 2 Toolchain)
	Unfixed, Patch Available: 7 (2 RFS, 0 Kernel, 5 Toolchain)
	Fixed: 0 (0 RFS, 0 Kernel, 0 Toolchain)
	High CVSS: 30 (2 RFS, 24 Kernel, 4 Toolchain)

	Local summary written to:
	  vigiles/core-image-minimal/core-image-minimal-2019-06-07_19.22.40-report.txt
```


Interpreting the Results
========================

### Console Output

A CVE summary is printed and contains the following:

* "Unfixed" CVEs are existing CVEs that have been reported against packages to be installed.

* "Patch Available" CVEs have a fix available in the meta-timesys-security layer.
  If the layer is already included, then you may need to update your copy.

* "Fixed" CVEs are those that originally existed in packages to be installed, but have been fixed/mitigated by subsequent patches.

* "CPU" CVEs are filed against the hardware. They may be fixed or mitigated in other components such as the kernel or compiler.

* "High CVSS" CVEs are those that are of utmost priority and require immediate attention, based on their Common Vulnerability Scoring System (v3) ranking.

Additionally, the distribution of the vulnerabilities across system components will be displayed.


### Online Report

The Vigiles CVE online report specified in the output provides a dashboard interface for examining all known details about each CVE detected, including the affected version ranges, priority and existing mitigations.


### Local Summary

The local summary includes console output and descriptive information about the report instance. It also includes detailed information about each CVE detected during the scan and any fixes that have been applied. Below is an example from a generated report.

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

The Vigiles CVE Scanner creates and sends a manifest describing your build to the Vigiles Server. This manifest is located at

```sh
$ readlink vigiles/core-image-minimal-cve.json 
core-image-minimal/core-image-minimal-2019-09-09_23.08.28-cve.json
```

In the event that something goes wrong, or if the results seem incorrect, this file may offer insight as to why.
It's important to include this file with any support request.


Advanced Usage
==============

### Custom Manifest and Report Names

By default, the Vigiles Manifest and CVE Report files are named after the base
image that is built (from the Yocto variable "IMAGE_BASENAME"). This can be
overridden with by setting the configuration variable "VIGILES_MANIFEST_NAME" in _conf/local.conf_:

```
VIGILES_MANIFEST_NAME = "Custom-Build-Name"
```

Instead of e.g.

```
./vigiles
├── core-image-minimal/
├── core-image-minimal-cve.json
└── core-image-minimal-report.txt
```

.. this will be the result:

```
./vigiles
├── Custom-Build-Name/
├── Custom-Build-Name-cve.json -> Custom-Build-Name/Custom-Build-Name-2020-11-25_20.28.09-cve.json
└── Custom-Build-Name-report.txt -> Custom-Build-Name/Custom-Build-Name-2020-11-25_20.28.09-report.txt
```


### Vigiles Whitelist

"Whitelist" Recipes and CVEs are listed in the "VIGILES_WHITELIST" variable. They are NOT included in the report.

The Whitelist can be adjusted in _conf/local.conf_ by appending **VIGILES_WHITELIST**:

```
VIGILES_WHITELIST += "\
	CVE-1234-ABCD \
"
```


### Kernel Config Filter

The Vigiles CVE Scanner can be configured to upload a Linux Kernel _.config_ file along with the SBOM. This filter will reduce the number of kernel CVEs reported by removing those related to features which are not being built for your kernel. There are 2 ways to enable this feature -- Automatic Detection or Manual Specification

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


### U-Boot Config Filter

The Vigiles CVE Scanner can be configured to upload a U-Boot _.config_ file along with the SBOM. This filter will reduce the number of U-Boot CVEs reported by removing those related to features which are not being built for your U-Boot. There are 2 ways to enable this feature -- Automatic Detection or Manual Specification

* Automatic Detection

This will use the _.config_ for the U-Boot specified in ```PREFERRED_PROVIDER_virtual/bootloader``` once the Yocto task ```do_configure``` is executed. 


```
VIGILES_UBOOT_CONFIG = "auto"
```


* Manual Specification

**NOTE: This must be a _full_ U-Boot config, not a defconfig!**

```
VIGILES_UBOOT_CONFIG = "</projects/uboot/uboot-2020.04/.config>"
```


### Specifying a Vigiles API Key File

A Vigiles API Key is required to run the Vigiles CVE Scanner and generate CVE reports.

To use an alternate key, or a key in a non-default location, you can specify the location in _conf/local.conf_ with a statement like the following:

```
VIGILES_KEY_FILE = "/tools/timesys/linuxlink_key"
```

If set, this option can be overridden on the command line by setting the
environment variable VIGILES_KEY_FILE to the location of an alternate Key
File. This feature can be used by developers to use a personal/local key
without having to change a shared local.conf for a board.


### Specifying a Product or Manifest

By default your manifest will be uploaded to the top-level folder of your "Private Workspace" Product on the Vigiles Dashboard. This can be changed by downloading the "Dashboard Config" for an alternative Product and/or Folder and specifying it in your local.conf file.

If set, this option can be overridden on the command line by setting the
environment variable VIGILES_DASHBOARD_CONFIG to the location of an alternate
Dashboard Config file. This feature can be used by developers to use a
personal/local key without having to change a shared local.conf for a board.

>New Products can be defined by clicking on the "New Product" product link and specifying a name. To download the Dashboard Config for the top-level folder of that Product, click on the "Product Settings" link and you will see a preview of the dashboard config file. You can copy the contents and create the file for yourself or choose to download it with the buttons on the right.


>Once a new product is created, sub-folders may be created by clicking on the "Create Folder" and specifying a name. The Dashboard Config for that Folder (in that Product) may be downloaded by first clicking on/opening the Folder, then clicking the "Folder Settings" link and choosing to copy or download the config for that folder.

Dashboard Config files will be downloaded by default to e.g. ```"${HOME}/Downloads/<product name>_<folder name>_dashboard_config"```. Once moving and/or renaming it as necessary, you can control the behavior of Vigiles with meta-timesys by modifying ```conf/local.conf``` to set the appropriate variable:


```sh
VIGILES_DASHBOARD_CONFIG = "${HOME}/timesys/dashboard_config"
```


### Dynamic subfolder creation
If a Dashboard Config is used, a subfolder name can be specified for dynamic folder creation. Manifests will be uploaded to a subfolder with this name within the location specified in the Dashbord Config. If one does not exist, it will be created. This option will be overridden by the environment variable ```VIGILES_SUBFOLDER_NAME```. You can control the behavior of Vigiles with meta-timesys by modifying ```conf/local.conf``` to set the appropriate variable:

```sh
VIGILES_SUBFOLDER_NAME = "Release X.x"
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

In order to explicitly include packages which are built by the Bitbake/Yocto
process but for some reason not present in rootfs manifest (e.g.
some bootloader or custom firmware may be not picked up through the recursive
RDEPENDS for the image), ```VIGILES_EXTRA_BACKFILL``` may be used.

For example, one may set this in their local.conf:

```
VIGILES_EXTRA_BACKFILL = "some-firmware-package"
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


### Uploading the Manifest (Only)

In some cases, it may be desired to upload the Vigiles Manifest for a build
without generating a CVE Report. This can speed up build times and ease
reporting of automated bulk builds.

This behavior can be enabled by setting the boolean variable
```VIGILES_UPLOAD_ONLY``` to '1' or 'True' in ```conf/local.conf```


```
VIGILES_UPLOAD_ONLY = "1"
```

Instead of a text report and a link to the online report, a link to the
Vigiles Dashboard Product Workspace (as specified with
VIGILES_DASHBOARD_CONFIG) will be displayed, from where it can be then be
scanned by the Vigiles Service.


### Exclude packages with "CLOSED" License in SBOM

Packages that have a closed license are included in the SBOM by default.

To exclude these packages, set ```VIGILES_INCLUDE_CLOSED_LICENSES```
to "0" or "False" in ```conf/local.conf```.

```
VIGILES_INCLUDE_CLOSED_LICENSES = "0"
```


### Exclude native and build-only packages in SBOM

To exclude all packages except backfill packages (packages built during the BitBake process
but not listed in the SBOM, because they may not be a part of the final rootfs manifest or 
dependencies of its packages e.g., glibc) and packages present in rootfs
manifest, set VIGILES_SBOM_ROOTFS_MANIFEST_ONLY = "1"

**Note:** This might result in the SBOM which is not NTIA compliant.


### Disable SBOM and Report generation for initramfs image

SBOM and report generation for the initramfs image can be disabled in local conf.
Both Initramfs SBOM and report are generated by default if INITRAMFS_IMAGE is set.

To disable initramfs SBOM generation set VIGILES_DISABLE_INITRAMFS_SBOM = "1"

Note: If Generating initramfs SBOM is disabled it will disable initramfs report generation by default.

```
VIGILES_DISABLE_INITRAMFS_SBOM = "1"
```

To disable initramfs report generation only, set VIGILES_DISABLE_INITRAMFS_REPORT = "1"
```
VIGILES_DISABLE_INITRAMFS_REPORT = "1"
```

### Setting Error Level for Vigiles Errors

Users can configure the VIGILES_ERROR_LEVEL in conf/local.conf to control how errors related to vigiles check are logged. Depending on the specific use case, the error level can be set to `FATAL`, `ERROR`, `WARNING` or `INFO` to log error messages as bitbake's fatal, error, warn or plain logs. The default is set to `INFO`.

```
VIGILES_ERROR_LEVEL = "FATAL"
```

### Specifying ecosystems that should be used for generating report (Enterprise Vigiles Only)

Ecosystems could be specified to include ecosystem specific vulnerabilities into the vulnerability report.
This feature is currently available for Enterprise vigiles only.

To specify ecosystems to be used set VIGILES_ECOSYSTEMS to a comma seperated string of ecosystems

```
VIGILES_ECOSYSTEMS = "Linux, Maven, PyPI, Ubuntu:20.04:LTS"
```

To include all the ecosystems set VIGILES_ECOSYSTEMS to "all"

```
VIGILES_ECOSYSTEMS = "all"
```

Below is the list of valid ecosystems that can be used
```
AlmaLinux:
['AlmaLinux', 'AlmaLinux:8', 'AlmaLinux:9']

Alpine:
['Alpine', 'Alpine:v3.10', 'Alpine:v3.11', 'Alpine:v3.12', 'Alpine:v3.13', 'Alpine:v3.14', 'Alpine:v3.15', 'Alpine:v3.16',
 'Alpine:v3.17', 'Alpine:v3.18', 'Alpine:v3.19', 'Alpine:v3.2', 'Alpine:v3.20', 'Alpine:v3.3', 'Alpine:v3.4', 'Alpine:v3.5',
 'Alpine:v3.6', 'Alpine:v3.7', 'Alpine:v3.8', 'Alpine:v3.9']

Debian:
['Debian', 'Debian:10', 'Debian:11', 'Debian:12', 'Debian:13', 'Debian:3.0', 'Debian:3.1', 'Debian:4.0', 'Debian:5.0',
 'Debian:6.0', 'Debian:7', 'Debian:8', 'Debian:9']

Rocky:
['Rocky Linux', 'Rocky Linux:8', 'Rocky Linux:9']

Ubuntu:
['Ubuntu', 'Ubuntu:14.04:LTS', 'Ubuntu:16.04:LTS', 'Ubuntu:18.04:LTS', 'Ubuntu:20.04:LTS', 'Ubuntu:22.04:LTS', 'Ubuntu:23.10',
 'Ubuntu:24.04:LTS', 'Ubuntu:Pro:14.04:LTS', 'Ubuntu:Pro:16.04:LTS', 'Ubuntu:Pro:18.04:LTS', 'Ubuntu:Pro:20.04:LTS',
 'Ubuntu:Pro:22.04:LTS', 'Ubuntu:Pro:24.04:LTS']

Others:
['Android', 'Bitnami', 'CRAN', 'GIT', 'GSD', 'GitHub Actions', 'Go', 'Hackage', 'Hex', 'Linux', 'Maven', 'NuGet', 'OSS-Fuzz',
 'Packagist', 'Pub', 'PyPI', 'RubyGems', 'SwiftURL', 'UVI', 'crates.io', 'npm']

```


### Subscribe SBOM Report Notification (Enterprise Vigiles Only)

SBOM report notifications can be configured in `local.conf` using `VIGILES_NOTIFICATION_FREQUENCY`. This setting allows users to set notification frequency for their report
This feature is currently available for Enterprise vigiles only.

By default, it is empty (`""`), meaning no subscription setting will be applied

To enable notifications, set one of the following values:

```
"none", "daily", "weekly", "monthly"
```

For example, To enable weekly notifications, set:

```
VIGILES_NOTIFICATION_FREQUENCY = "weekly"
```


Maintenance
===========

The Vigiles CVE Scanner and meta-timesys are maintained by [The Lynx Security team](mailto:vigiles@timesys.com).

For Updates, Support and More Information, please see:

[Vigiles Website](https://www.lynx.com/solutions/vulnerability-mitigation-management)

and

[meta-timesys @ GitHub](https://github.com/TimesysGit/meta-timesys)

