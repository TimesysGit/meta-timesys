#!/usr/bin/env python

import os
import sys
import json

from lib import llapi

NVD_BASE_URL = 'https://nvd.nist.gov/vuln/detail/'


def print_usage():
    apidoc = '%s/docs/wiki/engineering/LinuxLink_Key_File' % llapi.LINUXLINK_SERVER
    print('This script sends a json manifest file for an image to LinuxLink '
          'to check the CVE status of the recipes.\n\n'
          'It requires a LinuxLink API keyfile, and an active LinuxLink '
          'subscription. See this document for keyfile information:\n'
          '%s\n\n'
          'Usage: %s <manifestfile>'
          % (apidoc, sys.argv[0]))


def read_manifest(manifest_file):
    with open(manifest_file, 'rb') as f:
        manifest = ''.join(line.rstrip() for line in f)
    return manifest


def print_cves(result):
    for pkg,info in result.iteritems():
        for cve in info:
            print('\nRecipe:  %s' % pkg)
            print('CVE ID:  %s' % cve['cve_id'])
            print('URL:     %s%s' % (NVD_BASE_URL, cve['cve_id']))
            print('CVSS:    %s' % cve['cvss'])
            print('Status:  %s' % cve['status'])
            if cve['status'] == 'Fixed':
                patches = cve.get('fixedby')
                if patches:
                    print('Patched by:')
                    for patch in patches:
                        print('\t%s' % patch)


if __name__ == '__main__':
    resource = '/api/cves/reports/yocto/'
    home_dir = os.path.expanduser('~')
    key_file = os.getenv('KEY_FILE', '%s/timesys/linuxlink_key' % home_dir)

    try:
        manifest_file = sys.argv[1]
    except IndexError:
        print_usage()
        sys.exit(1)

    try:
        email, key = llapi.read_keyfile(key_file)
    except Exception as e:
        print('Error: %s\n' % e)
        print_usage()
        sys.exit(1)

    manifest = read_manifest(manifest_file)
    manifest_json=json.loads(manifest)
    if len(manifest_json['packages']) > 0:
        print('Requesting image analysis from LinuxLink ...')
        result = llapi.api_post(email, key, resource, {'manifest': manifest})
        result = result.get('cves', [])
        if not result:
            print('No results.')
        else:
            print_cves(result)
    else:
        print('No packages found in manifest.\nPlease confirm %s is a valid image' % manifest_json["image"])
