#!/usr/bin/env python3

###########################################################
#
# scripts/checkcves.py - Online CVE Database Interface.
#
# Copyright (C) 2019 Timesys Corporation
# Copyright (C) 2025 Lynx Software Technologies, Inc. All rights reserved.
#
# This source is released under the MIT License.
#
###########################################################

import argparse
import os
import sys
import json
import urllib.parse
import logging

from lib import llapi

NVD_BASE_URL = 'https://nvd.nist.gov/vuln/detail/'
API_DOC = 'https://vigiles.lynx.com/docs/vigiles_api_key_file.html'
INFO_PAGE = 'https://www.lynx.com/solutions/vulnerability-mitigation-management'

bogus_whitelist = "CVE-1234-1234"

ALMALINUX = ['AlmaLinux', 'AlmaLinux:8', 'AlmaLinux:9']
ALPINE = ['Alpine', 'Alpine:v3.10', 'Alpine:v3.11', 'Alpine:v3.12', 'Alpine:v3.13', 'Alpine:v3.14', 'Alpine:v3.15', 'Alpine:v3.16', 'Alpine:v3.17', 'Alpine:v3.18', 'Alpine:v3.19', 'Alpine:v3.2', 'Alpine:v3.20', 'Alpine:v3.3', 'Alpine:v3.4', 'Alpine:v3.5','Alpine:v3.6', 'Alpine:v3.7', 'Alpine:v3.8', 'Alpine:v3.9']
DEBIAN = ['Debian', 'Debian:10', 'Debian:11', 'Debian:12', 'Debian:13', 'Debian:3.0', 'Debian:3.1', 'Debian:4.0', 'Debian:5.0', 'Debian:6.0', 'Debian:7', 'Debian:8', 'Debian:9']
ROCKY = ['Rocky Linux', 'Rocky Linux:8', 'Rocky Linux:9']
UBUNTU = ['Ubuntu', 'Ubuntu:14.04:LTS', 'Ubuntu:16.04:LTS', 'Ubuntu:18.04:LTS', 'Ubuntu:20.04:LTS', 'Ubuntu:22.04:LTS', 'Ubuntu:23.10', 'Ubuntu:24.04:LTS', 'Ubuntu:Pro:14.04:LTS', 'Ubuntu:Pro:16.04:LTS', 'Ubuntu:Pro:18.04:LTS', 'Ubuntu:Pro:20.04:LTS', 'Ubuntu:Pro:22.04:LTS', 'Ubuntu:Pro:24.04:LTS']
OTHERS = ['Android', 'Bitnami', 'CRAN', 'GIT', 'GSD', 'GitHub Actions', 'Go', 'Hackage', 'Hex', 'Linux', 'Maven', 'NuGet', 'OSS-Fuzz', 'Packagist', 'Pub', 'PyPI', 'RubyGems', 'SwiftURL', 'UVI', 'crates.io', 'npm']

ALL_ECOSYSTEMS = OTHERS + ALMALINUX + ALPINE + DEBIAN + ROCKY + UBUNTU

class InvalidDashboardConfig(BaseException):
    pass


class InvalidLinuxlinkKey(BaseException):
    pass

logger = logging.Logger("Vigiles")
logger.setLevel(logging.DEBUG)

# show logs in stdout
if not logger.hasHandlers():
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(levelname)s Vigiles: %(message)s"))
    logger.addHandler(handler)

def debug(msg):
    return logger.debug(msg)

def info(msg):
    return logger.info(msg)

def warn(msg):
    return logger.warning(msg)

def error(msg):
    return logger.error(msg)


def get_usage():
    return('This script sends a json manifest file for an image to Vigiles '
           'to check the CVE status of the recipes. You may specify a manifest '
           'file, or generate one from a given image name.  If no image or '
           'manifest is specified, you will be prompted to select an image.\n\n'
           'Subscribing to notifications requires a Vigiles API keyfile and '
           'an active Vigiles subscription.\n\n'
           'See this document for keyfile information:\n'
           '%s\n\n'
           % API_DOC)


def print_bad_keyfile_notice(keyfile):
    notice = f'API key doesn\'t exist at {keyfile}, or the contents were invalid.\n\n'

    notice += '\tPlease see this document for API key information:\n'
    notice += '\t%s\n\n' % API_DOC
    notice += '\tTo request a trial account, please get in touch with us at sales@timesys.com\n\n'
    notice += '\tFor more information on the vulnerability management service, please visit:\n'
    notice += '\t%s\n' % INFO_PAGE
    error(notice)
    sys.exit(1)


def handle_cmdline_args():
    parser = argparse.ArgumentParser(description=get_usage())
    parser.add_argument('-s', '--subscribe',
                        help='Set subscription frequency for sbom report notifications: "none", "daily", "weekly", "monthly"',
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

    parser.add_argument('-K', '--keyfile', dest='llkey',
                        help='Location of Vigiles API key file')
    parser.add_argument('-C', '--dashboard-config', dest='lldashboard',
                        help='Location of Vigiles Dashboard Config file')
    parser.add_argument('-F', '--subfolder-name', dest='subfolder_name',
                        help='Name of subfolder to upload to')

    parser.add_argument('-U', '--upload-only', dest='upload_only',
                        help='Upload the manifest only; do not wait for report.',
                        action='store_true', default=False)
    parser.add_argument('-m', '--manifest', required=True,
                        help='Pre-generated JSON image manifest file to check',
                        metavar='FILE')
    parser.add_argument('-e', '--ecosystems', dest='ecosystems', default="",
                        help='Comma separated string of ecosystems that should be \
                            used to include ecosystem specific vulnerabilities \
                            into the vulnerability report')
    return parser.parse_args()


def read_manifest(manifest_file):
    try:
        with open(manifest_file, 'r') as f:
            manifest_data = ''.join(line.rstrip() for line in f)
    except (OSError, IOError, UnicodeDecodeError) as e:
        error('Could not open manifest: %s' % e)
        sys.exit(1)
    return manifest_data


def print_cves(result, outfile=None):
    cves = result.get('cves', {})
    if cves:
        print('\n\n-- Recipe Vulnerabilities --', file=outfile)
        for pkg, info in cves.items():
            for cve in info:
                print('\n\tRecipe:  %s' % pkg, file=outfile)
                print('\tVersion: %s' % cve['version'], file=outfile)
                print('\tID:  %s' % cve['cve_id'], file=outfile)
                print('\tURL:     %s%s' % (NVD_BASE_URL, cve['cve_id']), file=outfile)
                print('\tCVSSv3:  %s' % cve['cvss'], file=outfile)
                print('\tVector:  %s' % cve['vector'], file=outfile)
                print('\tStatus:  %s' % cve['status'], file=outfile)
                patches = cve.get('fixedby')
                if patches:
                    if cve.get('status') == 'Unfixed, Patch Available':
                        print('\tPatched in meta-timesys-security commit(s):',
                              file=outfile)
                    else:
                        print('\tPatched by:', file=outfile)
                    for patch in patches:
                        print('\t* %s' % patch, file=outfile)


def print_ecosystem_vulns(result, outfile=None):
    vuln_keys = [
        "ASB",
        "CAN",
        "DLA",
        "DSA",
        "DTSA",
        "GHSA",
        "GO",
        "GSD",
        "GSD",
        "OSV",
        "PYSEC",
        "RUSTSEC",
        "UVI",
    ]
    for key in vuln_keys:
        vulns = result.get(key)
        if vulns:
            for pkg, info in vulns.items():
                for vuln in info:
                    print('\n\tRecipe:  %s' % pkg, file=outfile)
                    version = vuln.get('database_specific', {}).get('version')
                    if version:
                        print('\tVersion: %s' % version, file=outfile)
                    
                    print('\tID:      %s' % vuln.get('id'), file=outfile)
                    affected = vuln.get("affected", [])
                    sources = set()
                    for info in affected:
                        source = info.get("database_specific", {}).get("source")
                        if source and source not in sources:
                            sources.add(source)
                            print('\tURL:     %s' % source, file=outfile)
                    print('\tVector:  %s' % vuln.get('vector'), file=outfile)
                    print('\tStatus:  %s' % vuln.get('status', 'Unfixed'), file=outfile)


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


def print_report_header(result, f_out=None):
  from datetime import datetime, timezone

  report_time = result.get('date', datetime.now(timezone.utc).isoformat())

  print('-- Vigiles Vulnerability Scanner --\n\n'
          '\t%s\n\n' % INFO_PAGE, file=f_out)
  print('-- Date Generated (UTC) --\n', file=f_out)
  print('\t%s' % report_time, file=f_out)


def print_report_overview(result, f_out=None):
  report_path = result.get('report_path', '')
  product_path = result.get('product_path', '')

  if report_path:
    report_url = urllib.parse.urljoin(llapi.VigilesURL, report_path)
    print('\n-- Vigiles Vulnerability Report --', file=f_out)
    print('\n\tView detailed online report at:\n'
            '\t  %s' % report_url, file=f_out)
  elif product_path:
    product_url = urllib.parse.urljoin(llapi.VigilesURL, product_path)
    product_name = result.get('product_name', 'Default')
    print('\n-- Vigiles Dashboard --', file=f_out)
    print('\n\tThe manifest has been uploaded to the \'%s\' Product Workspace:\n\n'
            '\t  %s\n' % (product_name, product_url), file=f_out)


def print_summary(result, outfile=None):

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

    if 'counts' in result:
      show_subscribed_summary(outfile)


def print_foootnotes(f_out=None):
    print('\n-- Vigiles Footnotes --', file=f_out)
    print('\t* "CPU" Vulnerabilities are filed against the hardware.\n'
          '\t  They may be fixed or mitigated in other components such as '
                'the kernel or compiler.\n',
          file=f_out)

    print('\t* "Patch Available" Vulnerabilities have a fix available in the '
                'meta-timesys-security layer.\n'
          '\t  If the layer is already included, then you may need to '
                'update your copy.\n',
          file=f_out)

    print('\t* "Whitelist" Recipes and Vulnerabilities are listed in the '
                '"VIGILES_WHITELIST" variable.\n'
          '\t  They are NOT included in the report.\n',
      file=f_out)


def print_whitelist(wl, outfile=None):
    print('\n-- Vigiles Vulnerability Whitelist --\n', file=outfile)
    if wl:
        for item in sorted(wl):
            print('\t* %s' % item, file=outfile)
    else:
            print('\t(Nothing is Whitelisted)', file=outfile)


def check_dashboard_config(conf_dashboard, default_dc_used):
    err_prefix = "Invalid Dashboard Config."
    err_suffix = " Report will be generated in Private Workspace instead."
    
    try:
        with open(conf_dashboard, "r") as f:
            conf = json.load(f)
            if conf.get("product", conf.get("group")):
                if len(conf) > 1:
                    if conf.get("folder"):
                        return
                else:
                    return
            err_msg = err_prefix + err_suffix
    except FileNotFoundError:
        if default_dc_used:
            return
        err_msg = "Dashboard config doesn't exists at %s." %conf_dashboard + err_suffix
    except json.decoder.JSONDecodeError:
        err_msg = err_prefix + err_suffix
    except Exception as e:
        err_msg = "Unable to parse Dashboard config : %s." %e + err_suffix
    raise InvalidDashboardConfig(err_msg)


def check_linuxlink_key(key):
    
    try:
        with open(key, "r") as f:
            ll_key = json.load(f)
            parsed_key = ll_key.get("key", ll_key.get("organization_key"))
            if parsed_key and ll_key.get("email"):
                if len(ll_key) > 2:
                    is_enterprise = ll_key.get("enterprise", False)
                    if isinstance(is_enterprise, bool) :
                        return
                else:
                    return
            err_msg = "Invalid API key."
    except FileNotFoundError:
        err_msg = "API key doesn't exists at %s." %key
    except json.decoder.JSONDecodeError:
        err_msg = "Invalid API key."
    except Exception as e:
        err_msg = "Unable to parse API key: %s." %e
    raise InvalidLinuxlinkKey(err_msg)


def _get_credentials(kf_param, dc_param, sf_param):
    home_dir = os.path.expanduser('~')
    timesys_dir  = os.path.join(home_dir, 'timesys')

    kf_env = os.getenv('VIGILES_KEY_FILE', '')
    kf_default = os.path.join(timesys_dir, 'linuxlink_key')

    dc_env = os.getenv('VIGILES_DASHBOARD_CONFIG', '')
    dc_default = os.path.join(timesys_dir, 'dashboard_config')

    sf_env = os.getenv('VIGILES_SUBFOLDER_NAME', '')
    sf_default = ''

    default_dc_used = False
    if kf_env:
        debug("Using Key from Environment: %s" % kf_env)
        key_file = kf_env
    elif kf_param:
        debug("Using Key from Configuration: %s" % kf_param)
        key_file = kf_param
    else:
        debug("Trying Key Default: %s" % kf_default)
        key_file = kf_default

    if dc_env:
        debug("Using Dashboard Config from Environment: %s" % dc_env)
        dashboard_config = dc_env
    elif dc_param:
        debug("Using Dashboard Config Configuration: %s" % dc_param)
        dashboard_config = dc_param
    else:
        debug("Trying Dashboard Config Default: %s" % dc_default)
        dashboard_config = dc_default
        default_dc_used = True

    if sf_env:
        debug("Using Subfolder Name from Environment: %s" % sf_env)
        subfolder_name = sf_env
    elif sf_param:
        debug("Using Subfolder Name from Configuration: %s" % sf_param)
        subfolder_name = sf_param
    else:
        debug("Using Subfolder Name Default: %s" % sf_default)
        subfolder_name = sf_default

    vgls_creds = {}
    dashboard_tokens = {}

    try:
        check_linuxlink_key(key_file)
        key_info = llapi.read_keyfile(key_file)
        email = key_info.get('email', None)
        key = key_info.get('key', key_info.get('organization_key', None))
        is_enterprise = key_info.get('enterprise', False)
        if is_enterprise:
            llapi.VigilesURL = key_info.get('server_url', llapi.VigilesURL)

        # Validate dashboard config
        if email and key:
            check_dashboard_config(dashboard_config, default_dc_used)

            # It is fine if either of these are none, they will just default
            dashboard_tokens = llapi.read_dashboard_config(dashboard_config)
        
    except InvalidLinuxlinkKey as e:
        print_bad_keyfile_notice(key_file)
    except InvalidDashboardConfig as e:
        warn("%s\n" % e)
    except Exception as e:
        error("%s\n" % e)
        print(get_usage())
        sys.exit(1)
    
    vgls_creds = {
        'email': email,
        'key': key,
        'product_or_group': dashboard_tokens.get('product_or_group', ''),
        'folder': dashboard_tokens.get('folder', ''),
        'subfolder_name': subfolder_name,
        'is_enterprise': is_enterprise,
    }

    return vgls_creds

if __name__ == '__main__':
    resource = '/api/v1/vigiles/manifests'
    args = handle_cmdline_args()

    vgls_creds = _get_credentials(args.llkey, args.lldashboard, args.subfolder_name)
    email = vgls_creds.get('email')
    key = vgls_creds.get('key')
    is_enterprise = vgls_creds.get('is_enterprise')
    upload_only = args.upload_only

    if args.outfile:
        outfile = open(args.outfile, 'w')
    else:
        outfile = None

    manifest_data = read_manifest(args.manifest)
    m = json.loads(manifest_data)
    if len(m['packages']) == 0:
        error('No packages found in manifest.\n')
        sys.exit(1)

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
            error('Could not open kernel config: %s' % e)
            sys.exit(1)
        debug('Kernel Config based filtering has been applied')

    # U-Boot and SPL filtering works the same way as kernel config filtering
    if not args.uboot_config:
        uboot_config = ''
    else:
        try:
            with open(args.uboot_config, 'r') as uconfig:
                uboot_config = uconfig.read().strip()
        except (OSError, IOError, UnicodeDecodeError) as e:
            error('Could not open U-Boot config: %s' % e)
            sys.exit(1)
        debug('U-Boot Config based filtering has been applied')

    request = {
      'manifest': manifest_data,
      'group_token' if is_enterprise else 'product_token': vgls_creds.get('product_or_group', ''),
      'folder_token': vgls_creds.get('folder', ''),
      'subfolder_name': vgls_creds.get('subfolder_name', ''),
      'upload_only': upload_only,
    }

    if kernel_config:
      request['kernel_config'] = kernel_config

    if uboot_config:
      request['uboot_config'] = uboot_config

    ecosystems = []
    ecosystems_str = args.ecosystems.strip()
    if ecosystems_str:
        if is_enterprise:
            if ecosystems_str.lower() == "all":
                ecosystems = ALL_ECOSYSTEMS
            else:
                invalid_ecosystems = set()
                ecosystems = [esys.strip() for esys in ecosystems_str.split(",")]
                for ecosystem in ecosystems:
                    if ecosystem not in ALL_ECOSYSTEMS:
                        invalid_ecosystems.add(ecosystem)
                if invalid_ecosystems:
                    warn('Skipping invalid ecosystems: %s. Refer to README.md for valid ecosystems.' % ",".join(invalid_ecosystems))
                ecosystems = [e for e in ecosystems if e not in invalid_ecosystems]
            request['ecosystems'] = ",".join(ecosystems)
        else:
            warn('Ecosystems based scanning is available only for enterprise edition')

    subscribe = args.subscribe and args.subscribe.strip() or None
    valid_subscribe = ["none", "daily", "weekly", "monthly"]
    if subscribe:
        subscribe = subscribe.lower()
        if is_enterprise:
            if subscribe in valid_subscribe:
                request["subscribe"] = subscribe
            else:
                error('Invalid subscription frequency. Choose from: none, daily, weekly, monthly')
                sys.exit(1)
        else:
            warn('The subscribe option is currently only supported with the Enterprise edition')

    _image = manifest.get('image', '')
    _name = manifest.get('manifest_name', _image)
    info('Requesting image analysis for %s (%s) \n'
          % (_name, _image))

    result = llapi.api_post(email, key, resource, request)

    if not result:
      sys.exit(1)

    # the default list contains a harmless but bogus example CVE ID,
    # don't print it here in case that is confusing.
    whitelist = [ item for item in manifest.get('whitelist', []) 
      if not any(bogon == item for bogon in bogus_whitelist.split()) ]

    # If notification subscription was requested but there was no Enterprise Vigiles
    # account / seat:
    if subscribe in valid_subscribe and subscribe != "none":
        print(f'\n-- Vigiles Vulnerability {subscribe.capitalize()} Report --\n', file=outfile)
        if not is_enterprise:
            print(f'\tWarning: Could not subscribe to {subscribe} Vulnerability report!\n'
                '\t  Please check that you have an active Enterprise Vigiles '
                'subscription.\n', file=outfile)
        else:
            print(f'\tNotice: You subscribed to {subscribe} email notifications for '
                'this report.\n'
                '\tMake sure that you are allowing update emails in your '
                'Vigiles preferences.\n', file=outfile)

    print_report_header(result, outfile)
    print_report_overview(result, outfile)

    print_summary(result, outfile=outfile)

    print_cves(result, outfile=outfile)
    if is_enterprise and ecosystems:
        print_ecosystem_vulns(result, outfile=outfile)

    if not upload_only:
      print_whitelist(whitelist, outfile=outfile)
      print_foootnotes(f_out=outfile)

    if outfile is not None:
      print_report_overview(result)
      print_summary(result)
      print('\n\tLocal summary written to:\n\t  %s' %
            os.path.relpath(outfile.name))
