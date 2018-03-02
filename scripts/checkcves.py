#!/usr/bin/env python
# Copyright (C) 2018 Timesys Corporation

import argparse
import os
import sys
import json
from distutils import spawn

from lib import llapi, manifest

NVD_BASE_URL = 'https://nvd.nist.gov/vuln/detail/'
API_DOC = '%s/docs/wiki/engineering/LinuxLink_Key_File' % llapi.LINUXLINK_SERVER
INFO_PAGE = 'https://www.timesys.com/open-source-embedded/security-update-management/'


def get_usage():
    return('This script sends a json manifest file for an image to LinuxLink '
           'to check the CVE status of the recipes. You may specify a manifest '
           'file, or generate one from a given image name.  If no image or '
           'manifest is specified, you will be prompted to select an image.\n\n'
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


def get_bb_root():
    bitbake = spawn.find_executable('bitbake')
    if bitbake is None:
        print('Error: bitbake not found in PATH. Do you need to source '
              'the environment (e.g. oe-init-build-env in poky)?')
        sys.exit(1)
    return os.path.abspath(os.path.join(os.path.dirname(bitbake), os.pardir))


def generate_manifest(im):
    print('\nAn image manifest will now be created for "%s".\n'
          'Please wait.\n' % im.target)
    manifest = im.generate()
    print ('Done.\n')
    return manifest


def handle_cmdline_args():
    parser = argparse.ArgumentParser(description=get_usage())
    parser.add_argument('-s', '--subscribe',
                        help='Subscribe to weekly email reports for this manifest',
                        action='store_true',
                        default=False,
                        dest='subscribe')
    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument('-l', '--list',
                             action='store_true',
                             default=False,
                             dest='list',
                             help='List available images and exit')
    input_group.add_argument('-i', '--image',
                             help='Image name to check')
    input_group.add_argument('-m', '--manifest',
                             help='Pre-generated JSON image manifest file to check',
                             metavar='FILE')
    return parser.parse_args()


def read_manifest(manifest_file):
    try:
        with open(manifest_file, 'r') as f:
            manifest_data = ''.join(line.rstrip() for line in f)
    except (OSError, IOError, UnicodeDecodeError) as e:
        print('Error: Could not open manifest: %s' % e)
        sys.exit(1)
    return manifest_data


def print_cves(result, demo=False):
    cves = result['cves']
    if demo:
        print('\n-- CVE Summary --\n'
              '\nUnfixed: %d\n'
              'Fixed: %d\n'
              'CPU: %d'
              % (cves['unfixed_count'],
                 cves['fixed_count'],
                 cves['arch_count']))
        print('\n"CPU" CVEs are filed against the hardware, and may be fixed '
              'or mitigated in other components such as the kernel or compiler.')
        return

    arch_cves = result.get('arch_cves', [])
    if arch_cves:
        print('\n\n-- CPU / Architecture CVEs --\n'
              '\nNote: These are CVEs which are filed against the hardware, '
              'and may be fixed or mitigated in other components such as the '
              'kernel or compiler.')
        for cve in arch_cves:
            print('\nCVE ID:  %s' % cve['cve_id'])
            print('URL:     %s%s' % (NVD_BASE_URL, cve['cve_id']))
            print('CVSSv2:  %s' % cve['cvss'])
            print('Vector:  %s' % cve['vector'])

    if cves:
        print('\n\n-- Recipe CVEs --')
        for pkg, info in cves.iteritems():
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

    if args.list:
        bb_root = get_bb_root()
        print('\nParsing images. This may take a moment.\n')
        im = manifest.ImageManifest(bb_root)
        print('\nThe following images were detected:\n')
        print('\n'.join(im.images))
        im.shutdown()
        sys.exit(1)

    # read or create image manifest
    if args.manifest:
        manifest_data = read_manifest(args.manifest)
        m = json.loads(manifest_data)
        if len(m['packages']) == 0:
            print('No packages found in manifest.\n')
            sys.exit(1)
    elif args.image:
        bb_root = get_bb_root()
        print('\nValidating image. This may take a moment.\n')
        im = manifest.ImageManifest(bb_root, args.image)
        if not im.validate_target():
            print('\nError: Unable to find image "%s".' % im.target)
            print('Specify one of the following images, or run without -i to '
                  'select one:\n')
            print('\n'.join(im.images))
            im.shutdown()
            sys.exit(1)
        manifest_data = generate_manifest(im)
        im.shutdown()
    else:  # prompt for image
        bb_root = get_bb_root()
        print('\nAfter parsing, you will be prompted to select an image.\n'
              'This may take a moment.\n')
        im = manifest.ImageManifest(bb_root)
        if not im.validate_target():
            menu = manifest.MenuSelect(
                {'title': 'Choose an Image',
                 'subtitle': ('A CVE report will be generated for '
                              'the selected image')},
                im.images)
            menu.show_menu()
            if menu.selected is not None:
                im.set_target(menu.selected)
            else:
                print('Error: Unable to find image "%s".\n' % im.target)
                im.shutdown()
                sys.exit(1)
        manifest_data = generate_manifest(im)
        im.shutdown()

    print('\nRequesting image analysis from LinuxLink ...\n')
    result = llapi.api_post(email, key, resource,
                            {'manifest': manifest_data,
                             'subscribe': args.subscribe})
    cves = result.get('cves', [])
    arch_cves = result.get('arch_cves', [])

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
                  'Please check that you have an active LinuxLink '
                  'subscription.\n')
        else:
            print('Notice: You subscribed to weekly email notifications for '
                  'this report.\nMake sure that you are allowing update emails '
                  'in your LinuxLink preferences.\n')

    print('-- Date Generated (UTC) --\n')
    print('%s' % result['date'])
    if not cves and not arch_cves:
        print('No results.')
        sys.exit(0)

    print_cves(result, demo=demo)
    print_url(result, demo=demo)
