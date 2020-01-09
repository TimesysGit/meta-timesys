#!/usr/bin/env python3

###########################################################
#
# scripts/checkcves.py - Online CVE Database Interface.
#
# Copyright (C) 2019 Timesys Corporation
#
#
# This source is released under the MIT License.
#
###########################################################

import argparse
import os
import sys
import json
from distutils import spawn

from lib import llapi, manifest

NVD_BASE_URL = 'https://nvd.nist.gov/vuln/detail/'
API_DOC = '%s/docs/wiki/engineering/LinuxLink_Key_File' % llapi.LINUXLINK_SERVER
INFO_PAGE = 'https://www.timesys.com/security/vulnerability-patch-notification/'

bogus_whitelist = "CVE-1234-1234"

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
    print('\n-- Vigiles Demo Mode Notice --', file=sys.stderr)

    if bad_key:
         print('\tNo API keyfile was found, or the contents were invalid.\n\n'
              '\tPlease see this document for API key information:\n'
              '\t%s\n' % API_DOC,
              file=sys.stderr)
    else:
        print('\tNo active subscription for this account.\n', file=sys.stderr)

    print('\tThe script will continue in demo mode, which will link you to '
            'temporarily available online results only.\n'
          '\tYou will need to login or register for a free account in order to '
            'see the report.\n', 
          file=sys.stderr)
    print('\tFor more information on the security notification service, '
            'please visit:\n'
          '\t%s\n' % INFO_PAGE,
          file=sys.stderr)


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
    parser.add_argument('-o', '--outfile',
                        help='Print results to FILE instead of STDOUT',
                        metavar='FILE')
    parser.add_argument('-k', '--kconfig',
                        help='Kernel .config (not defconfig) to submit for CVE filtering',
                        metavar='FILE',
                        dest='kconfig')
    parser.add_argument('-u', '--uboot-config',
                        help='U-Boot .config (not defconfig) to submit for CVE filtering',
                        metavar='FILE',
                        dest='uboot_config')
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




def print_cves(result, demo=False, outfile=None):
    arch_cves = result.get('arch_cves', [])
    if arch_cves:
        print('\n\n-- Architecture CVEs --', file=outfile)
        for cve in arch_cves:
            print('\n\tCVE ID:  %s' % cve['cve_id'], file=outfile)
            print('\tURL:     %s%s' % (NVD_BASE_URL, cve['cve_id']), file=outfile)
            print('\tCVSSv3:  %s' % cve['cvss'], file=outfile)
            print('\tVector:  %s' % cve['vector'], file=outfile)

    cves = result.get('cves', {})
    if cves:
        print('\n\n-- Recipe CVEs --', file=outfile)
        for pkg, info in cves.items():
            for cve in info:
                print('\n\tRecipe:  %s' % pkg, file=outfile)
                print('\tVersion: %s' % cve['version'], file=outfile)
                print('\tCVE ID:  %s' % cve['cve_id'], file=outfile)
                print('\tURL:     %s%s' % (NVD_BASE_URL, cve['cve_id']), file=outfile)
                print('\tCVSSv3:  %s' % cve['cvss'], file=outfile)
                print('\tVector:  %s' % cve['vector'], file=outfile)
                print('\tStatus:  %s' % cve['status'], file=outfile)
                patches = cve.get('fixedby')
                if patches:
                    if cve['status'] == 'Unfixed, Patch Available':
                        print('\tPatched in meta-timesys-security commit(s):',
                              file=outfile)
                    else:
                        print('\tPatched by:', file=outfile)
                    for patch in patches:
                        print('\t* %s' % patch, file=outfile)


def parse_cve_counts(counts, category):
    total = counts.get(category, 0)
    kernel = counts.get('kernel', {}).get(category, 0)
    toolchain = counts.get('toolchain', {}).get(category, 0)
    rfs = total - kernel - toolchain
    return {'total': total,
            'rfs': rfs,
            'kernel': kernel,
            'toolchain': toolchain}


def parse_cvss_counts(counts, severity):
    c = counts.get(severity)
    if c is None:
        return 0
    return c.get('unfixed', 0) + c.get('fixed', 0)


def print_summary(result, outfile=None):


    def show_header(f_out=outfile):
      print('\n-- Vigiles CVE Report --', file=f_out)

      report_url = '%s%s' % (llapi.LINUXLINK_SERVER, result['report_path'])

      print('\n\tView detailed online report at:\n'
              '\t  %s' % report_url, file=f_out)

      if (demo):
        print('\t  NOTE: Running in Demo Mode will cause this URL to expire '
          'after one day.', file=f_out)

    def show_subscribed_summary(f_out=outfile):
      counts = result.get('counts', {})
      unfixed = parse_cve_counts(counts, 'unfixed')
      unapplied = parse_cve_counts(counts, 'unapplied')
      fixed = parse_cve_counts(counts, 'fixed')

      cvss_counts = counts.get('cvss_counts', {})
      cvss_total = parse_cvss_counts(cvss_counts, 'high')
      cvss_kernel = parse_cvss_counts(cvss_counts.get('kernel', {}), 'high')
      cvss_toolchain = parse_cvss_counts(cvss_counts.get('toolchain', {}), 'high')
      cvss_rfs = cvss_total - cvss_kernel - cvss_toolchain

      print('\n\tUnfixed: {} ({} RFS, {} Kernel, {} Toolchain)'.format(
              unfixed['total'], unfixed['rfs'],
              unfixed['kernel'], unfixed['toolchain']),
            file=f_out)
      print('\tUnfixed, Patch Available: '
            '{} ({} RFS, {} Kernel, {} Toolchain)'.format(
              unapplied['total'], unapplied['rfs'],
              unapplied['kernel'], unapplied['toolchain']),
            file=f_out)
      print('\tFixed: {} ({} RFS, {} Kernel, {} Toolchain)'.format(
              fixed['total'], fixed['rfs'], fixed['kernel'], fixed['toolchain']),
            file=f_out)
      print('\tHigh CVSS: {} ({} RFS, {} Kernel, {} Toolchain)'.format(
              cvss_total, cvss_rfs, cvss_kernel, cvss_toolchain),
            file=f_out)

    def show_demo_summary(f_out=outfile):
      print('\n-- Vigiles CVE Overview --', file=f_out)
      print('\n\tUnfixed: %d\n'
      '\tUnfixed, Patch Available: %d\n'
      '\tFixed: %d\n'
      '\tCPU: %d'
      % (cves['unfixed_count'],
         cves['unapplied_count'],
         cves['fixed_count'],
         cves['arch_count'],),
            file=f_out)

    show_header(outfile)

    if not demo:
      show_subscribed_summary(outfile)
    else:
      show_demo_summary(outfile)

def print_foootnotes(f_out=None):
    print('\n-- Vigiles Footnotes --', file=f_out)
    print('\t* "CPU" CVEs are filed against the hardware.\n'
          '\t  They may be fixed or mitigated in other components such as '
                'the kernel or compiler.\n',
          file=f_out)

    print('\t* "Patch Available" CVEs have a fix available in the '
                'meta-timesys-security layer.\n'
          '\t  If the layer is already included, then you may need to '
                'update your copy.\n',
          file=f_out)

    print('\t* "Whitelist" Recipes and CVEs are listed in the '
                '"VIGILES_WHITELIST" variable.\n'
          '\t  They are NOT included in the report.\n',
      file=f_out)


def print_whitelist(wl, outfile=None):
    print('\n-- Vigiles CVE Whitelist --\n', file=outfile)
    if wl:
        for item in sorted(wl):
            print('\t* %s' % item, file=outfile)
    else:
            print('\t(Nothing is Whitelisted)', file=outfile)


if __name__ == '__main__':
    resource = '/api/cves/reports/yocto/'
    home_dir = os.path.expanduser('~')
    key_file = os.getenv('VIGILES_KEY_FILE', '%s/timesys/linuxlink_key' % home_dir)
    dashboard_config = os.getenv('VIGILES_DASHBOARD_CONFIG', '%s/timesys/dashboard_config' % home_dir)
    demo = False
    args = handle_cmdline_args()

    try:
        email, key = llapi.read_keyfile(key_file)
        # It is fine if either of these are none, they will just default
        product_token= llapi.read_dashboard_config(dashboard_config)
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

    if args.outfile:
        outfile = open(args.outfile, 'w')
    else:
        outfile = None

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

    manifest = json.loads(manifest_data)

    # If -k is specified, the given config file is submitted along with the
    # manifest to filter out irrelevant kernel CVEs
    if not args.kconfig:
        kernel_config = ''
    else:
        try:
            with open(args.kconfig, 'r') as kconfig:
                kernel_config = kconfig.read().strip()
        except (OSError, IOError, UnicodeDecodeError) as e:
            print('Error: Could not open kernel config: %s' % e)
            sys.exit(1)
        print('Vigiles: Kernel Config based filtering has been applied', file=sys.stderr)

    # U-Boot and SPL filtering works the same way as kernel config filtering
    if not args.uboot_config:
        uboot_config = ''
    else:
        try:
            with open(args.uboot_config, 'r') as uconfig:
                uboot_config = uconfig.read().strip()
        except (OSError, IOError, UnicodeDecodeError) as e:
            print('Error: Could not open U-Boot config: %s' % e)
            sys.exit(1)
        print('Vigiles: U-Boot Config based filtering has been applied', file=sys.stderr)

    request = {
      'manifest': manifest_data,
      'subscribe': args.subscribe,
      'product_token': product_token
    }

    if kernel_config:
      request['kconfig'] = kernel_config

    if uboot_config:
      request['uboot_config'] = uboot_config

    print('Vigiles: Requesting image analysis from LinuxLink ...\n', file=sys.stderr)

    result = llapi.api_post(email, key, resource, request)

    # the default list contains a harmless but bogus example CVE ID,
    # don't print it here in case that is confusing.
    whitelist = [ item for item in manifest.get('whitelist', []) 
      if not any(bogon == item for bogon in bogus_whitelist.split()) ]

    print('-- Vigiles CVE Scanner --\n\n'
            '\t%s\n\n' % INFO_PAGE, file=outfile)
    print('-- Date Generated (UTC) --\n', file=outfile)
    print('\t%s' % result['date'], file=outfile)

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
        print('\n-- Vigiles CVE Weekly Report --\n', file=outfile)
        if not sub_result:
            print('\tWarning: Could not subscribe to weekly CVE report!\n'
                '\t  Please check that you have an active LinuxLink '
                'subscription.\n', file=outfile)
        else:
            print('\tNotice: You subscribed to weekly email notifications for '
                  'this report.\n'
                  '\tMake sure that you are allowing update emails in your '
                  'LinuxLink preferences.\n', file=outfile)


    cves = result.get('cves', [])
    arch_cves = result.get('arch_cves', [])

    if not cves and not arch_cves:
        print('Vigiles: No results.. Exiting.')
        sys.exit(0)

    print_summary(result, outfile=outfile)

    if not demo:
      print_cves(result, demo=demo, outfile=outfile)
    print_whitelist(whitelist, outfile=outfile)
    print_foootnotes(f_out=outfile)

    if outfile is not None:
      print_summary(result)
      print('\n\tLocal summary written to:\n\t  %s' %
            os.path.relpath(outfile.name))
