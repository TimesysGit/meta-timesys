# Changelog

## [2.22.0+pyro] - 2025-04-18

### Added

* [feature] Add option to specify ecosystems for generating vulnerability report
* [feature] Added support to subscribe frequency for notification during manifest upload
* [vigiles.bbclass] Support extra backfill packages
* [vigiles.bbclass] Add option to exclude native and build-only packages
* [feature] Add VIGILES_ERROR_LEVEL to log vigiles related error messages

### Changed

* [docs] Remove references to free account registration
* [general] Improve version parsing for accurate reporting in the SBOM
* [tsmeta.bbclass] Add file locking to prevent concurrent access

### Fixed

* [vigiles.bbclass] Fix: Keyerror while updating runtime dependencies
* [checkcves.py] Handle KeyErrors when data is unavailable from upload API response
* [checkcves.py] Optimize ecosystem filtering when consecutive invalid entries occur
* [vigiles.bbclass] Optimize adding dependencies to fix leakages in final SBOM
* [vigiles.bbclass] Fix syntax issue in cpe_string

## [v2.21.0+pyro] - 2024-06-20

### Added

* [vigiles.bbclass] Add feature to disable sbom and report generation for initramfs image

### Fixed

* [checkcves.py] Fix API key parsing in 'check_linuxlink_key' function
* [vigiles.bbclass] Fix: Use correct variable name for whitelisting package cve

## [v2.20.0+pyro] - 2024-04-11

### Added

* [CHANGELOG.md] add changelog
* [vigiles.conf] add vigiles tool version - VIGILES_TOOL_VERSION

### Changed

* [vigiles.bbclass] populate info of packages included as build dependencies in SBOM
* [README.md] Update link to Yocto's Reference Manual 
* [vigiles.bbclass] add packages related to Trusted OS as components
* [checkcves.py] Display error message if invalid linuxlink key is used
* [checkcves.py] Display error message if dashboard config is invalid 

### Fixed

* [vigiles.bbclass] Report runtime dependencies against PN
* [vigiles. bbclass] Resolve circular dependency with meta-tegra

## [v2.19.0+pyro] - 2023-07-13

### Changed

* [vigiles.bbclass] add default values to mandatory fields in SBOM 

### Fixed

* [vigiles.bbclass] Rename function to avoid conflict between vigiles.bbclass and create-spdx.bbclass 
* [tsmeta.bbclass] Improve error handling in the get_manifest_pkgs() function for when the ""IMAGE_MANIFEST"" does not contain a valid path

## [v2.18.0+pyro] - 2023-06-02

### Added

* [vigiles.bbclass] Include build and runtime dependencies in generated SBOM 
* [vigiles.bbclass] Include package checksum in generated SBOM 
* [vigiles.bbclass] Add components to make SBOM NTIA minimum elements compliant 

### Changed

* [llapi] Implement retry handling for API calls 
* [vigiles.bbclass] Sort package dependencies and component_type

## [v2.17.0+pyro] - 2023-03-23

### Added

* [llapi] add enterprise vigiles support 
* [vigiles.bbclass] don't include packages with ""CLOSED"" License in the SBOM 
* [vigiles.bbclass] added VIGILES_INCLUDE_CLOSED_LICENSES config to toggle adding packages with ""CLOSED"" Licenses 
* [vigiles.bbclass] include closed license check to extra packages added through VIGILES_EXTRA_PACKAGES CSV files 

### Changed

* [vigiles.bbclass] warn for general exceptions while running checkcves 
* [tsmeta.bbclass] Get external u-boot version from Makefile for more accurate version string 
* [vigiles.conf] Set default value to VIGILES_INCLUDE_CLOSED_LICENSES as '1' to include packages with 'CLOSED' licenses by default

## [v2.16.0+pyro] - 2022-10-11

### Changed

* [README] added U-Boot config filter section 

### Fixed

* [bbclass] fix do_vigiles_uboot_config hang issue on external u-boot config

## [v2.15.1+pyro] - 2022-07-20

### Fixed

* [checkcves] remove arch_count and arch_cves from demo summary
* [llapi] remove deprecated parameter when loading json

## [v2.15.0+pyro] - 2022-05-11

### Added

* [bbclass] add package supplier
* [bbclass] add cpe_id to manifest 
* [bbclass] add package download location to manifest 

### Changed

* [llapi] use v1 api route for manifest upload 
* [kernel] Add extra check against falsely identifying package.
* [bbclass] truncate manifest name to 256 characters 
* [readme] update instructions for dashboard config

## [v2.14.0+pyro] - 2021-11-05

### Added

* added subfolder name option

### Removed

* [misc] Remove deprecated scripts and modules 

## [v2.13.1+pyro] - 2021-01-06

### Fixed

* [tsmeta] Make sure we don't rename libubootenv

## [v2.13.0+pyro] - 2020-12-09

### Added

* [bbclass] Add support for new backend features 

### Changed

* [llapi] Updates for new Vigiles Service / LinuxLink features

## [v2.12.0+pyro] - 2020-09-24

### Changed

* [u-boot] Gather u-boot metadata explicitly, rather than as dependency.
* [kernel] Use better checking for backfilling kernel dependencies

## [v2.11.0+pyro] - 2020-08-28

### Added

* [debug] Add VIGILES_DISABLE_CHECK flag to generate (but not submit) manifests. 
* Add SUMMARY from recipe into JSON output 
* Add HOMEPAGE from recipe into JSON output 
* [llapi] Add support for Folders via Dashboard Config. 
* [images] Add INITRAMFS_IMAGE to manifest if its set. 

### Changed

* [manifest] Add CVE_CHECK_WHITELIST to our own before submission.
* [images] Streamline task dependencies for multiple image manifests/reports 
* [layers] Clean up error path when getting git info fails. 
* [readme] Update for new Folder Config.

## [v2.10.1+pyro] - 2020-07-30

### Fixed

* [tsmeta] Fix for issues with host-installed Python 3.8 
* [u-boot] Fix for issues with host-installed Python 3.8 
* [vigiles-chevck] Fix for issues with host-installed Python 3.8 
* [do_vigiles_check] Make sure we use the host-installed python3

## [v2.10.0+pyro] - 2020-07-22

### Added

* [conf] Add dunfell to LAYERSERIES_COMPAT.  

### Removed

* [tsmeta] Remove PACKAGECONFIG variable handling.

## [v2.9.0+pyro] - 2020-06-11

### Added

* [feature] Add support for excluding packages via CSV files. 

### Fixed

* [layers] Fixups for gathering git repo info 
* [u-boot] Fixup for an unset PREFERRED_PROVIDERS_virtual/bootloader 
* [fixup] bb.info() -> bb.note().

## [v2.8.0+pyro] - 2020-05-06

### Added

* [feature] Add support for including extra packages via .csv files. 

### Fixed

* [tsmeta] Safeguard against recipes that don't have a layer 
* [tsmeta] Fixup str.split() parameter. 
* [extras] Fixup parsing and Readme to match LinuxLink behavior.

## [v2.7.0+pyro] - 2020-03-11

### Added

* [vigiles] Add support for uploading U-Boot configuration. 
* [tsmeta] Add License info to metadata and manifest. 

### Changed

* [vigiles/bbclass] Make config copying generic 
* [bbclass] Tweak dependencies to better support using rootfs manifests. 
* [pkg] Be sure to include extended runtime packages 
* [image] Make a missed-package-mapping a warning. 
* [tsmeta] Cleanup layer metadata 
* [tsmeta] Cleanup and fix git layer metadata 
* [bbclass] Cleanup vigiles_pkg() and streamline metadata 
* [tsmeta] Add timesys layer backfill. 
* [uboot] Check if virtual/bootloader is set before proceeding. 
* [tsmeta/layers] Filter current git branch better. 
* [tsmeta/layers] Do better check for valid git repo. 

### Removed

* [readme] Remove note about manual execution. 

### Fixed

* [bbclass] Change task articulation to prevent circular dependency 
* fixup bb.warning() -> bb.warn() 
* [bbclass] exists() -> lexists() for symlinks we control.

## [v2.6.0+pyro] - 2020-02-07

### Added

* Add dashboard config capability

### Changed

* [vigiles/kernel] Re-use helper for kernel version accuracy.

## [v2.5.0+pyro] - 2019-12-05

### Changed

* [tsmeta] Parse kernel Makefile for accurate cve_version inference. 

### Fixed

* [vigiles/kconfig] Make sure there is a kernel config file before copying

## [v2.4.0+pyro] - 2019-11-19

### Added

* [vigiles/config] Make kernel config auto-detection the default. 

### Changed

* [tsmeta] Remove existing tsmeta_dir on startup. 

### Fixed

* [vigiles/bbclass] Prevent racing against rm_work 
* [vigiles/tsmeta] Work around yocto bug for getting cve_version

## [v2.3.0+pyro] - 2019-09-13

### Added

* [scripts/imx] Add setup script for i.MX BSP's 
* [vigiles/manifest] Scrape patches for CVE info and send in manifest. 
* [vigiles/bbclass] Add kernel config auto-detection 

### Changed

* [config/whitelist] Make sure we don't overwrite local.conf settings. 
* [vigiles/tsmeta] Clean up src dictionary creation with oe library routines. 
* [vigiles] Update Readme. 
* [vigiles/bbclass] Sort patches and patched_cves in manifest. 
* [vigiles] Bump manifest version. 

### Fixed

* [vigiles/class] Add fixup to normalize u-boot cve_product name. 
* [vigiles/bbclass] Minor fixups for do_vigiles_{image,check}

## [v2.2.0+pyro] - 2019-07-03

### Added

* [tsmeta] Add debugging hook 
* [vigiles] Export proxies before running check.

### Changed

* [tsmeta] Add variables to collect for image metadata 
* [tsmeta] Re-factor + improve tsmeta_pn_list() 

### Fixed

* [vigiles] Re-fixup dependencies so we catch all images for a target

## [v2.1.0+pyro] - 2019-07-01

### Changed

* [vigiles] Backfill pn metadata with virtual/{bootloader,kernel,libc}
* [tsmeta] Also include patches ending in .diff 

### Fixed

* [tsmeta] Fixup parsing for (> 1) instance of '://' in URIs. """

## [v2.0.1+pyro] - 2019-07-01

### Fixed

* [tsmeta] 3 bug fixes

## [v2.0.0+pyro] - 2019-07-01

### Added

* [vigiles] Add task-based Yocto CVE Scanner 

### Changed

* [vigiles] Update README and file preamble in vigiles files. 
* [vigiles] Minor updates for release 

### Fixed

* [vigiles] README fixup. 
* [vigiles] Fix CVSSv2 -> CVSSv3 typos

## [v1.16.0+pyro] - 2019-02-11

### Added

* checkcves: Add -k option to upload kernel config with manifest

### Changed

* manifest: expand DISTRO_VERSION
* Update README for kernel config filter section and maintainers

## [v1.15.0+pyro] -  2018-08-27

### Added

* Add whitelist of recipes and CVEs to manifest 
* Print whitelisted recipes / CVE IDs in checkcves results 

### Changed

* include version without git revs even when cve_product isn't set

## [v1.14.0+pyro] - 2018-07-12

### Added

* checkcves: Print summary of results

## [v1.13.0+pyro] - 2018-06-25

### Added

* checkcves: report patches available in meta-timesys-security in results
* manifest: Include all files from SRC_URI that look like patches 
* Add SRCREV to manifest when there is one

## [v1.12.0+pyro] - 2018-04-26

### Removed

* Remove unused demos and mirroring config 

### Fixed

* llapi: Fix read call on HTTPResponse

## [v1.11.0+pyro] - 2018-03-09

### Added

* Add option to write results to file instead of stdout 

### Changed

* checkcves: Add image selection so that a second manifest step isn't needed
* Update README for manifest/checkcves changes

## [v1.10.0+pyro] - 2017-12-22

### Added

* Add CVE_PRODUCT to image manifest, bump manifest version 
* checkcves: take subscription arg, always show report URL

## [v1.9.0+pyro] - 2017-12-12

### Added

* Add README.md 

### Changed

* checkcves: Update no-sub message

## [v1.8.0+pyro] - 2017-12-05

### Added

* cvecheck: Support web-only results without a subscription

## [v1.7.0+pyro] - 2017-11-22

### Added

* Rework manifest.py for Pyro 

### Fixed

* Quiet stderr on git operations

## [v1.6.0+pyro] - 2017-11-10

### Changed

* update cve fields, add date

## [v1.5.0+pyro] - 2017-11-06

### Added

* Add manifest version

### Changed

* Move list of patched cves to be per package
* Check if image is valid before creating manifest
* Check if manifest contains packages before submitting 
* Update checkcve print based on result changes

## [v1.4.0+pyro] - 2017-10-13

### Changed

* Move generatePkgDepTreeData to backport.py from TimesysCooker
* Update layer git info in lib/utils.py
* General cleanup in lib/utils.py 
* Rewrite scripts/manifest.py to use Tinfoil 
* Move lib/ to scripts/lib

## [v1.3.0+pyro] - 2017-08-25

### Added

* Update for morty and python3

### Fixed

* Backport generatePkgDepTreeData fix
* checkcves: Don't exit silently when there were no results

## [v1.2.0+pyro] - 2017-07-28

### Changed

* checkcves: Update for new results format

## [v1.1.0+pyro] - 2017-07-25

### Added

* Add machine and distro version to manifest 
* Track CVEs that are already fixed by patches
* manifest: skip native

### Changed

* manifest: Don't dump output to the terminal

### Fixed

* manifest: Don't append patches more than once

## [v1.0.0+pyro] - 2017-06-14

### Changed

* Add script to check CVEs with LinuxLink
* Add premirrors to layer conf

## [v0.1.0+pyro] - 2017-06-02

### Added

* Initial commit: add layer.conf 
* mcc-pingpong: Add demo package 
* add vybrid-demo-mcc-pingpong image.
* add scripts for generating a json manifest 
* Add linuxlink API module to lib 

### Changed

* rename TIMESYS_MIRROR var to TIMESYS_REPO