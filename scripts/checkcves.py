#!/usr/bin/env python

import argparse
import os
import sys
import json

from lib import llapi

NVD_BASE_URL = 'https://nvd.nist.gov/vuln/detail/'
API_DOC = '%s/docs/wiki/engineering/LinuxLink_Key_File' % llapi.LINUXLINK_SERVER
INFO_PAGE = 'https://www.timesys.com/open-source-embedded/security-update-management/'


def get_usage():
    return('This script sends a json manifest file for an image to LinuxLink '
           'to check the CVE status of the recipes.\n\n'
           'Subscribing to notifications requires a LinuxLink API keyfile, and '
           'an active LinuxLink subscription.\n\n'
           'See this document for keyfile information:\n'
           '%s\n\n'
           % API_DOC)


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
          'You will need to login or register for a free account in order to '
          'see the report.\n\n'
          'You can not subscribe for recurring CVE notifications without an '
          'active subscription!\n\n'
          'For more information on the security notification service, visit:\n'
          '%s\n'
          % INFO_PAGE)


def handle_cmdline_args():
    parser = argparse.ArgumentParser(description=get_usage())
    parser.add_argument('-s', '--subscribe',
                        help='Subscribe to weekly email reports for this manifest',
                        action='store_true',
                        default=False,
                        dest='subscribe')
    parser.add_argument('manifest', help='JSON image manifest file to check')
    return parser.parse_args()



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
        print('CVE Summary:\n'
              '    Unfixed: %d\n'
              '    Fixed: %d'
              % (result['unfixed_count'],
                 result['fixed_count']))
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


def print_url(result, demo=False):
    report_url = '%s%s' % (llapi.LINUXLINK_SERVER, result['report_path'])
    print('\nView the complete report online at:\n%s\n' % report_url)
    if demo:
        print('Note: The above URL will expire after one day.')


if __name__ == '__main__':
    resource = '/api/cves/reports/yocto/'
    home_dir = os.path.expanduser('~')
    key_file = os.getenv('KEY_FILE', '%s/timesys/linuxlink_key' % home_dir)
    demo = False
    args = handle_cmdline_args()

    try:
        email, key = llapi.read_keyfile(key_file)
    except Exception as e:
        print('Error: %s\n' % e)
        print(get_usage())
        sys.exit(1)

    # If there was no proper API keyfile, operate in demo mode.
    if not email or not key:
        demo = True
        resource += 'demo/'
        print_demo_notice(bad_key=True)

    manifest = read_manifest(args.manifest)
    manifest_json = json.loads(manifest)

    if len(manifest_json['packages']) == 0:
        print('No packages found in manifest.\n'
              'Please confirm that "%s" is a valid image'
              % manifest_json["image"])
        sys.exit(1)

    print('Requesting image analysis from LinuxLink ...')
    result = llapi.api_post(email, key, resource,
                            {'manifest': manifest,
                             'subscribe': args.subscribe})
    cves = result.get('cves', [])

    print('--------')
    print('Date: %s\n' % result['date'])
    if not cves:
        print('No results.')
        sys.exit(0)

    # If no LinuxLink subscription or bogus user/key, it will have fallen back
    # to demo mode
    demo_result = result.get('demo', False)
    if not demo and demo_result:
        print_demo_notice()
        demo = demo_result

    # If notification subscription was requested but there was no LinuxLink
    # account / seat:
    sub_result = result.get('subscribed', False)
    if args.subscribe:
        if not sub_result:
            print('Warning: Could not subscribe to weekly CVE report!\n'
                  'Please check that you have an active LinuxLink subscription.')
        else:
            print('Notice: You subscribed to weekly email notifications for '
                  'this report.\nMake sure that you are allowing update emails '
                  ' in your LinuxLink preferences.')

    print_cves(cves, demo=demo)
    print_url(result, demo=demo)
