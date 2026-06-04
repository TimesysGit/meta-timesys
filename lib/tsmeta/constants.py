###########################################################################
#
# lib/tsmeta/constants.py - Constants for meta-timesys scripts
#
# Copyright (C) 2026 Lynx Software Technologies, Inc. All rights reserved.
#
# This source is released under the MIT License.
#
###########################################################################


DOWNLOAD_SBOM_OPTIONS = {
    "cyclonedx": {
        "1.7": ("json", "xml"),
        "1.6": ("json", "xml"),
        "1.5": ("json", "xml"),
        "1.4": ("json", "xml"),
        "1.3": ("json", "xml"),
        "1.2": ("json", "xml"),
        "1.1": ("json", "xml"),
    },
    "spdx": {
        "3.0.1": ("json-ld",),
        "2.3": ("json", "xml", "yaml", "tag", "xlsx", "xls", "rdfxml"),
        "2.2": ("json", "xml", "yaml", "tag", "xlsx", "xls", "rdfxml"),
    },
    "spdx-lite": {
        "3.0.1": ("json-ld",),
        "2.3": ("json", "xml", "yaml", "tag", "xlsx", "xls", "rdfxml"),
        "2.2": ("json", "xml", "yaml", "tag", "xlsx", "xls", "rdfxml"),
    },
}
