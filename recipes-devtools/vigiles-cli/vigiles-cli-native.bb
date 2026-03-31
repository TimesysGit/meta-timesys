#####################################################################################
#
# recipes-devtools/vigiles-cli/vigiles-cli-native.bb - Recipe to download vigiles-cli
#
# Copyright (C) 2026 Lynx Software Technologies, Inc. All rights reserved.
#
# This source is released under the MIT License.
#
######################################################################################

SUMMARY = "Vigiles CLI tool to interact with Vigiles server"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://LICENSES/MIT.txt;md5=4582f62afbc1e801d09547e6d9544165"

SRC_URI = "git://github.com/TimesysGit/vigiles-cli.git;branch=main;protocol=https"
SRCREV = "5f47ff661f2fb578bd389aa786d780245fc32d8b"
PV = "1.9.0"

inherit python_setuptools_build_meta native

RDEPENDS:${PN} += "python3-requests-native python3-urllib3-native"
