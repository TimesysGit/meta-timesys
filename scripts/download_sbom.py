#!/usr/bin/env python3

#########################################################################################
#
# scripts/download_sbom.py - Converts SBOM format from Vigiles to standard SPDX/CycloneDX.
#
# Copyright (C) 2026 Lynx Software Technologies, Inc. All rights reserved.
#
# This source is released under the MIT License.
#
##########################################################################################


import argparse
import os
import sys

from checkcves import error, debug, _get_credentials, API_DOC
from lib.constants import DOWNLOAD_SBOM_OPTIONS
from lib import llapi


def get_usage():
    return('This script downloads the SBOM in given Specification, '
           'format and version from vigiles server.\n\n'
           'This requires a Vigiles API keyfile and '
           'an active Vigiles subscription.\n\n'
           'See this document for keyfile information:\n'
           '%s\n\n'
           % API_DOC)

def handle_cmdline_args():
    parser = argparse.ArgumentParser(description=get_usage())
    
    parser.add_argument('-K', '--keyfile', dest='llkey', required=True,
                        help='Location of Vigiles API key file')
    parser.add_argument('-t', '--sbom-token', dest='sbom_token', required=True,
                        help='Token of the SBOM to be converted into the specified format')
    parser.add_argument('-s', '--sbom-spec', dest='sbom_spec', default="cyclonedx",
                        choices=["spdx", "spdx-lite", "cyclonedx"],
                        help='SBOM specification like spdx, spdx-lite or cyclonedx')
    parser.add_argument('-v', '--sbom-version', dest='sbom_version', default="1.6",
                        help='SBOM version. Refer README.md for list of valid versions for each SBOM spec')
    parser.add_argument('-f', '--sbom-format', dest='sbom_file_format', default="json",
                        help='SBOM format. Refer README.md for list of valid formats for each SBOM spec')
    parser.add_argument('-o', '--outfile', metavar='FILE', required=True,
                        help='Path where the downloaded sbom will be saved')
    
    args = parser.parse_args()

    if os.path.isdir(args.outfile):
        parser.error("%s is a directory. Please provide a filepath" % args.outfile)
    
    download_options = DOWNLOAD_SBOM_OPTIONS[args.sbom_spec]
    valid_versions = tuple(download_options.keys())
    if args.sbom_version not in valid_versions:
        parser.error(
            "Invalid sbom version %s for %s. Choose from %s" % (
                args.sbom_version,
                args.sbom_spec,
                valid_versions
            ))

    valid_formats = download_options[args.sbom_version]
    if args.sbom_file_format not in valid_formats:
        parser.error(
            "Invalid file format %s for %s version %s. Choose from %s" % (
                args.sbom_file_format,
                args.sbom_spec,
                args.sbom_version,
                valid_formats
            ))
    return args


def download_sbom(args, email, key):
    payload = {
        'send_file': True,
        'sbom_format': args.sbom_spec,
        'file_format': args.sbom_file_format,
        'sbom_version': args.sbom_version
    }

    resource = '/api/v1/vigiles/manifests/%s' % args.sbom_token
    result = llapi.api_get(email, key, resource, payload, json=False)

    if not result or result.status != 200:
        error("Failed to download SBOM")
        sys.exit()

    with open(args.outfile, 'wb') as f:
        f.write(result.read()) 

    debug("SBOM downloaded successfully to: %s" % args.outfile)



if __name__ == '__main__':
    
    args = handle_cmdline_args()

    vgls_creds = _get_credentials(args.llkey, None, None)
    email = vgls_creds.get('email')
    key = vgls_creds.get('key')

    download_sbom(args, email, key)
