#!/usr/bin/env python

import os
import sys
import json

from lib import llapi

NVD_BASE_URL = 'https://nvd.nist.gov/vuln/detail/'
API_DOC = '%s/docs/wiki/engineering/LinuxLink_Key_File' % llapi.LINUXLINK_SERVER
INFO_PAGE = 'https://www.timesys.com/open-source-embedded/security-update-management/'


def print_usage():
    print('Usage: %s <manifest file>\n\n'
          'This script sends a json manifest file for an image to LinuxLink '
          'to check the CVE status of the recipes.\n\n'
          'Subscribing to notifications requires a LinuxLink API keyfile, and '
          'an active LinuxLink subscription.\n\n'
          'See this document for keyfile information:\n'
          '%s\n\n'
          % (sys.argv[0], API_DOC))


def print_demo_notice(bad_key=False):
    if bad_key:
        print('\nWarning: No API keyfile was found, or the contents were '
              'invalid.\n\n'
              'If you do have a LinuxLink subscription, please see this '
              'document for API key information:\n'
              '%s\n'
              % API_DOC)
    else:
        print('\nWarning: No active subscription for this account.\n')

    print('The script will continue in demo mode, which will link you to '
          'temporarily available online results only.\n'
          'You will not be able to subscribe for notifications!\n\n'
          'For more information on the security notification service, visit:\n'
          '%s\n'
          % INFO_PAGE)


def read_manifest(manifest_file):
    try:
        with open(manifest_file, 'rb') as f:
            manifest = ''.join(line.rstrip() for line in f)
    except (OSError, IOError, UnicodeDecodeError) as e:
        print('Error: Could not open manifest: %s' % e)
        sys.exit(1)
    return manifest


def print_cves(result, demo=False):
    if demo:
        report_url = '%s%s' % (llapi.LINUXLINK_SERVER, result['report_path'])
        print('CVE Summary:\n'
              '    Unfixed: %d\n'
              '    Fixed: %d\n\n'
              'View complete report online at:\n'
              '%s\n\n'
              'Note: The above URL will expire after one day.'
              % (result['unfixed_count'],
                 result['fixed_count'],
                 report_url))
        return

    for pkg, info in result.iteritems():
        for cve in info:
            print('\nRecipe:  %s' % pkg)
            print('Version: %s' % cve['version'])
            print('CVE ID:  %s' % cve['cve_id'])
            print('URL:     %s%s' % (NVD_BASE_URL, cve['cve_id']))
            print('CVSSv2:  %s' % cve['cvss'])
            print('Vector:  %s' % cve['vector'])
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
    demo = False

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

    # If there was no proper API keyfile, operate in demo mode.
    if not email or not key:
        demo = True
        resource += 'demo/'
        print_demo_notice(bad_key=True)

    manifest = read_manifest(manifest_file)
    manifest_json = json.loads(manifest)
    if len(manifest_json['packages']) > 0:
        print('Requesting image analysis from LinuxLink ...')
        result = llapi.api_post(email, key, resource, {'manifest': manifest})
        cves = result.get('cves', [])
        print('--------')
        print('Date: %s\n' % result['date'])
        if not cves:
            print('No results.')
        else:
            # If no subscription or bogus user/key, it will have fallen back to
            # demo mode to give results
            demo_result = result.get('demo', False)
            if not demo and demo_result:
                print_demo_notice()
                demo = demo_result
            print_cves(cves, demo=demo)
    else:
        print('No packages found in manifest.\n'
              'Please confirm that "%s" is a valid image'
              % manifest_json["image"])
