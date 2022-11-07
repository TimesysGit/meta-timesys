###########################################################
#
# classes/vigiles.bbclass - Yocto CVE Scanner
#
# Copyright (C) 2019 Timesys Corporation
#
#
# This source is released under the MIT License.
#
###########################################################

inherit tsmeta

require conf/vigiles.conf


addtask do_vigiles_pkg after do_packagedata before do_rm_work
do_vigiles_pkg[nostamp] = "1"
do_vigiles_pkg[rdeptask] += "do_unpack"
do_vigiles_pkg[rdeptask] += "do_packagedata"

SPDX_ORG ??= "OpenEmbedded ()"
SPDX_SUPPLIER ??= "Organization: ${SPDX_ORG}"


def _get_patched(src_patches):
    #
    # This is originally from cve-check.bbclass; input/output adapted for our needs.

    import re

    patched_dict = dict()

    cve_match = re.compile("CVE:( CVE\-\d{4}\-\d+)+")

    # Matches last CVE-1234-211432 in the file name, also if written
    # with small letters. Not supporting multiple CVE id's in a single
    # file name.
    cve_file_name_match = re.compile(".*([Cc][Vv][Ee]\-\d{4}\-\d+)")

    for patch_base, patch_file in src_patches.items():
        found_cves = list()

        # Check patch file name for CVE ID
        fname_match = cve_file_name_match.search(patch_file)
        if fname_match:
            cve = fname_match.group(1).upper()
            found_cves.append(cve)

        with open(patch_file, "r", encoding="utf-8") as f:
            try:
                patch_text = f.read()
            except UnicodeDecodeError:
                bb.plain("Failed to read patch %s using UTF-8 encoding"
                        " trying with iso8859-1" %  patch_file)
                f.close()
                with open(patch_file, "r", encoding="iso8859-1") as f:
                    patch_text = f.read()

        # Search for one or more "CVE: " lines
        for match in cve_match.finditer(patch_text):
            # Get only the CVEs without the "CVE: " tag
            cves = patch_text[match.start()+5:match.end()]
            for cve in cves.split():
                found_cves.append(cve)

        for cve in found_cves:
            entry = patched_dict.get(cve, list())
            if patch_base not in entry:
                entry.append(patch_base)
            patched_dict.update({cve: entry})

    return { key: sorted(patched_dict[key]) for key in sorted(patched_dict.keys()) }

def get_cpe_ids(cve_product, version):
    """
    Get list of CPE identifiers for the given product and version
    """

    version = version.split("+git")[0]

    cpe_ids = []
    for product in cve_product.split():
        # CVE_PRODUCT in recipes may include vendor information for CPE identifiers. If not,
        # use wildcard for vendor.
        if ":" in product:
            vendor, product = product.split(":", 1)
        else:
            vendor = "*"

        cpe_id = f'cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*'
        cpe_ids.append(cpe_id)
    return cpe_ids

python do_vigiles_pkg() {
    pn = d.getVar('PN')
    bpn = d.getVar('BPN')

    suffixes = d.getVar('SPECIAL_PKGSUFFIX').split()
    prefixes = ['nativesdk-']
    substrings = ['-cross-', '-source-']

    if (pn.endswith(tuple(suffixes)) or
        pn.startswith(tuple(prefixes)) or
        any(substr in pn for substr in substrings)):
        bb.debug(1, "Skipping extended PN %s [ %s ]" % (pn, bpn))
        return
    elif pn != bpn:
        bb.debug(2, "Keeping extended PN %s [ %s ]" % (pn, bpn))

    bb.build.exec_func("do_tsmeta_pkgvars", d)

    pn_vars = [
        'pn',
        'pv'
    ]
    src_vars = [
        'cve_check_ignore',
        'cve_product',
        'cve_version',
        'layer',
        'license',
        'recipe',
        'sources',
        'srcrev',
        'patched_cves',
        'summary',
        'homepage',
        'src_uri',
        'pkg_cpe_id',
    ]
    pn_dict = tsmeta_read_dictname_vars(d, 'pn', pn, pn_vars)
    manifest = tsmeta_read_dictname_vars(d, 'src', pn, src_vars)
    manifest['name'] = pn_dict['pn']
    manifest['version'] = pn_dict['pv']
    # Add cpe_id for each package in manifest to support spdx format
    manifest['cpe_id'] = manifest.get('pkg_cpe_id') or get_cpe_ids(manifest['cve_product'], manifest['cve_version'])
    manifest.pop('pkg_cpe_id')

    # Add download location in manifest json
    src_uri_list = manifest.pop('src_uri')
    for src_uri in src_uri_list:
        if not src_uri.startswith("file://"):
            manifest['download_location'] = src_uri
            break
    else:
        manifest['download_location'] = "UNKNOWN"

    sources = manifest.pop('sources')
    src_patches = sources.get('patches', {})
    if len(src_patches.keys()):
        patches = list(src_patches.keys())
        manifest['patches'] = sorted(patches)

        patched_dict = _get_patched(src_patches)

        if len(patched_dict):
            manifest['patched_cves'] = patched_dict

    if not len(manifest['srcrev']):
        manifest.pop('srcrev')
    if not len(manifest['patched_cves']):
        manifest.pop('patched_cves')

    tsmeta_write_dict(d, "cve", manifest)
}

def vigiles_get_build_dict(d):
    dict_in = dict (
            distro = dict (
                name = d.getVar('DISTRO'),
                vars = [ 'title', 'name', 'version', 'codename' ]
            ),
            image = dict (
                name = d.getVar('IMAGE_BASENAME'),
                vars = [ 'basename', 'link_name', 'name', 'pkgtype' ],
            ),
            machine = dict (
                name = d.getVar('MACHINE'),
                vars = [ 'title', 'arch' ],
            ),
            layers = dict (
                name = "layers",
                )
        )

    dict_out = { dict_name: tsmeta_get_dict(d, dict_name, dict_spec)
        for dict_name, dict_spec in dict_in.items() }

    return dict_out

def _get_imgdir(d_path, d_name):
    return os.path.join(d_path, d_name)

def _get_vout_path(d_path, f_name, max_len, tstamp, suffix):
    f_name = f_name [:max_len - len(suffix) - len(tstamp) - 2]
    f_name = f_name + "-" + tstamp + suffix
    return os.path.join(d_path, f_name)

def _get_vlink(d_path, f_name, max_len, suffix):
    f_name = f_name[:max_len - len(suffix) - 1] + suffix
    return os.path.join(d_path, f_name)

def vigiles_write_manifest(d, tdw_tag, dict_out):
    import json

    v_dir = d.getVar('VIGILES_DIR')
    m_max_len = int(d.getVar('VIGILES_MANIFEST_NAME_MAX_LENGTH'))
    v_tstamp = d.getVar('VIGILES_TIMESTAMP')

    # truncate manifest name to acceptable configured length
    _name = d.getVar('VIGILES_MANIFEST_NAME')[:m_max_len]
    _imgdirname = d.getVar('VIGILES_MANIFEST_NAME')[:m_max_len - 1]

    v_imgdir = _get_imgdir(v_dir, _imgdirname)
    bb.note("Creating Vigiles Image Directory at %s" % v_imgdir)
    bb.utils.mkdirhier(v_imgdir)

    f_path = _get_vout_path(v_imgdir, _name, m_max_len, v_tstamp, d.getVar('VIGILES_MANIFEST_SUFFIX'))
    with open(f_path, "w") as f_out:
        s = json.dumps(dict_out, indent=2, sort_keys=True)
        f_out.write(s)

    l_path = _get_vlink(v_dir, _name, m_max_len, d.getVar('VIGILES_MANIFEST_SUFFIX'))

    if os.path.lexists(l_path):
        os.remove(l_path)

    if os.path.exists(f_path):
        os.symlink(os.path.relpath(f_path, os.path.dirname(l_path)), l_path)


##
# We always want to include the kernel, bootlaoder and libc, which aren't
# always picked up through the recursive RDEPENDS for the image (e.g. if there's
# no package installed on the rootfs for the kernel or bootlaoder).
#
# Also see below for the manual dependencies added for do_vigiles_image() of
# their respective do_vigiles_pkg() tasks.
##
VIGILES_PREFERRED_BACKFILL = "\
    virtual/libc \
"

VIGILES_BACKFILL := "${@' '.join( \
    [ d.getVar('PREFERRED_PROVIDER_%s' % virt, True) or '' \
        for virt in d.getVar('VIGILES_PREFERRED_BACKFILL', True).split() ] \
)}"


##
#   Additional packages can be included in the manifest by setting
#    'VIGILES_EXTRA_PACKAGES' in local.conf, which is expected to be a list of
#    .csv files in the form of:
#       <product>, <version>, [<license>]
##
def _get_extra_packages(d):
    import csv
    import json
    from collections import defaultdict

    vgls_extra = d.getVar('VIGILES_EXTRA_PACKAGES') or ''
    extra_files = oe.utils.squashspaces(vgls_extra).split(' ')
    if not extra_files:
        bb.debug(2, "Vigiles: No Extra Packages.")
        return {}

    bb.debug(1, "Importing Extra Packages from %s" % extra_files)

    additional = {
        'additional_licenses': defaultdict(str),
        'additional_packages': defaultdict(dict)
    }

    extra_rows = []
    for extra_csv in extra_files:
        if not os.path.exists(extra_csv):
            print("Skipping Non-Existent Extras File: %s" % extra_csv)
            continue
        try:
            with open(extra_csv) as csv_in:
                reader = csv.reader(csv_in)
                for row in reader:
                    if not len(row):
                        continue
                    if row[0].startswith('#'):
                        continue

                    pkg = row[0].strip()
                    if len(row) > 1:
                        ver = row[1].strip()
                    else:
                        ver = ''
                    if len(row) > 2:
                        license = row[2].strip()
                    else:
                        license = 'unknown'
                    extra_rows.append([pkg,ver,license])
        except Exception as e:
            bb.warn("Vigiles Extras File: %s" % e)
            return {}

    if not extra_rows:
        return {}

    # Check for a CSV header of e.g. "package,version,license" and skip it
    header = extra_rows[0]
    if header[0].lower() == "product":
        extra_rows = extra_rows[1:]

    for row in extra_rows:
        pkg = row[0].replace(' ', '-')
        ver = row[1].replace(' ', '.')
        license = row[2]
        license_key = pkg + ver

        bb.debug(1, "Extra Package: %s, Version: %s, License: %s = %s" %
                 (pkg, ver, license_key, license))

        pkg_vers = set(additional['additional_packages'].get(pkg, []))
        pkg_vers.add(ver)

        additional['additional_packages'][pkg] = sorted(list(pkg_vers))
        additional['additional_licenses'][license_key] = license

    return additional


##
#   Packages can be excluded from the manifest by setting
#    'VIGILES_EXCLUDE' in local.conf, which is expected to be a list of
#    .csv files in the format of
#       <product>
##
def _filter_excluded_packages(d, vgls_pkgs):
    import csv

    vgls_excld_files = d.getVar('VIGILES_EXCLUDE') or ''
    excld_files = oe.utils.squashspaces(vgls_excld_files).split(' ')
    if not excld_files:
        return {}

    excld_pkgs = set()

    for excld_csv in excld_files:
        if not os.path.exists(excld_csv):
            bb.note("Vigiles: Skipping Non-Existent exclude-package File: %s" % excld_csv)
            continue
        bb.debug(1, "Vigiles: Importing Excluded Packages from %s" % excld_files)
        try:
            with open(excld_csv) as csv_in:
                reader = csv.reader(csv_in)
                for row in reader:
                    if not len(row):
                        continue
                    if row[0].startswith('#'):
                        continue

                    pkg = row[0].strip().lower()
                    excld_pkgs.add(pkg.replace(' ', '-'))
        except Exception as e:
            bb.warn("Vigiles: exclude-packages: %s" % e)
            return {}

    bb.debug(2, "Vigiles: Requested packages to exclude: %s" % list(excld_pkgs))

    pkg_matches = list(set([
        k
        for k, v in vgls_pkgs.items()
        if v['name'] in excld_pkgs
    ]))

    bb.debug(1, "Vigiles: Excluding Packages: %s" % sorted(pkg_matches))
    for pkg_key in pkg_matches:
        vgls_pkgs.pop(pkg_key)


def vigiles_image_collect(d):
    from datetime import datetime

    sys_dict = vigiles_get_build_dict(d)

    backfill_list = d.getVar('VIGILES_BACKFILL', True).split()

    boot_pn = d.getVar('VIGILES_UBOOT_PN') or \
        d.getVar('PREFERRED_PROVIDER_virtual/bootloader') or ''
    if boot_pn:
        backfill_list.append(boot_pn)

    kernel_pn = d.getVar('VIGILES_KERNEL_PN') or \
        d.getVar('PREFERRED_PROVIDER_virtual/kernel') or ''
    if kernel_pn:
        backfill_list.append(kernel_pn)

    initramfs_image = d.getVar('INITRAMFS_IMAGE', True)
    if initramfs_image:
        backfill_list.append(initramfs_image)
    rdep_list = tsmeta_pn_list(d)

    # This list() cast will remove duplicates if the backfill packages are
    # already present
    pn_list = list(sorted(backfill_list + rdep_list))

    vgls_pkgs = tsmeta_read_dictdir_files(d, "cve", pn_list)
    vigiles_ignored = set(
        oe.utils.squashspaces(d.getVar('VIGILES_WHITELIST') or "").split()
    )
    for pkg_name, pkg_dict in vgls_pkgs.items():
        pkg_ignored = pkg_dict.get('cve_check_ignore', [])
        if pkg_ignored:
            bb.debug(1, "Vigiles: Package: '%s' is ignoring %s" % (pkg_name, pkg_ignored))
        vigiles_ignored.update(pkg_ignored)

    # truncate manifest_name to acceptable configured length
    _name = d.getVar('VIGILES_MANIFEST_NAME')[:int(d.getVar('VIGILES_MANIFEST_NAME_MAX_LENGTH'))]

    dict_out = dict(
            date             = datetime.utcnow().isoformat(),
            distro           = sys_dict["distro"]["codename"],
            distro_version   = sys_dict["distro"]["version"],
            image            = sys_dict["image"]["basename"],
            layers           = sys_dict["layers"],
            machine          = sys_dict["machine"]["title"],
            manifest_version = d.getVar('VIGILES_MANIFEST_VERSION'),
            manifest_name    = _name,
            packages         = tsmeta_read_dictdir_files(d, "cve", pn_list),
            whitelist        = sorted(list(vigiles_ignored))
        )
    dict_out.update(_get_extra_packages(d))
    _filter_excluded_packages(d, dict_out['packages'])
    # Add package supplier
    for key in dict_out['packages'].keys():
        dict_out['packages'][key].update({'package_supplier': d.getVar('SPDX_SUPPLIER')})
    return dict_out

python do_vigiles_image() {
    bb.note("Collecting Vigiles Metadata")
    cve_manifest = vigiles_image_collect(d)

    bb.note("Writing Vigiles Metadata")
    vigiles_write_manifest(d, "cve", cve_manifest)
}

addtask do_vigiles_image after do_rootfs before do_image
do_vigiles_image[nostamp] = "1"
do_rootfs[nostamp] = "1"
do_rootfs[recrdeptask] += "do_vigiles_pkg"
do_rootfs[recideptask] += "do_vigiles_pkg"


def vigiles_image_depends(d):
    pn = d.getVar('PN')
    deps = list()
    if bb.data.inherits_class('image', d):
        backfill_pns = d.getVar('VIGILES_BACKFILL').split()
        deps = [ ':'.join([_pn, 'do_vigiles_pkg']) for _pn in backfill_pns ]

        boot_pn = d.getVar('VIGILES_UBOOT_PN') or \
            d.getVar('PREFERRED_PROVIDER_virtual/bootloader') or ''
        if boot_pn:
            deps.append('%s:do_vigiles_uboot_config' % boot_pn)

        kernel_pn = d.getVar('VIGILES_KERNEL_PN') or \
            d.getVar('PREFERRED_PROVIDER_virtual/kernel') or ''
        if kernel_pn:
            deps.append('%s:do_vigiles_kconfig' % kernel_pn)
            deps.append('%s:do_vigiles_pkg' % kernel_pn)

    return ' '.join(deps)


do_vigiles_image[depends] += " ${@vigiles_image_depends(d)} "


def _get_kernel_pf(d):
    bpn = d.getVar('PREFERRED_PROVIDER_virtual/kernel')
    cve_v = "unset"
    if bb.data.inherits_class('kernel', d):
        cve_v = _detect_kernel_version(d)
    else:
        kdict = tsmeta_read_dictname_vars(d, 'cve', bpn, ['name', 'cve_version'])
        cve_v = kdict.get('cve_version') or cve_v

    vgls_pf = '-'.join([bpn, cve_v])
    return vgls_pf


def _find_config(d, vgls_pf, config_in):
    import shutil

    vgls_timestamp = d.getVar('VIGILES_TIMESTAMP')

    vgls_config_full = '_'.join([vgls_pf, vgls_timestamp])
    config_fname = '.'.join([vgls_config_full, 'config'])
    config_lname = '.'.join([vgls_pf, 'config'])

    bb.debug(1, "Translation: %s -> %s" % (config_fname, config_lname))

    vigiles_config_dir = d.getVar('VIGILES_DIR_KCONFIG')
    vigiles_dir = d.getVar('VIGILES_DIR')
    config_out = os.path.join(vigiles_config_dir, config_fname)
    config_link = os.path.join(vigiles_dir, config_lname)

    if os.path.lexists(config_link):
        os.remove(config_link)

    if not config_in:
        return

    if config_in == 'auto':
        build_dir = os.path.relpath(d.getVar('B'))
        config_in = os.path.join(build_dir, '.config')

    if not os.path.exists(config_in):
        bb.warn("config does not exist, skipping.")
        bb.warn("config path: %s" % config_in)
        return

    if not os.path.exists(vigiles_config_dir):
        bb.utils.mkdirhier(vigiles_config_dir)

    bb.debug(1, "Copy: %s -> %s" %
             (os.path.relpath(config_in), os.path.relpath(config_out)))
    shutil.copy(config_in, config_out)

    bb.debug(1, "Link: %s -> %s" %
             (os.path.relpath(config_link), os.path.relpath(config_out)))
    os.symlink(os.path.relpath(config_out, vigiles_dir), config_link)


python do_vigiles_kconfig() {
    vgls_pf = _get_kernel_pf(d)
    config_in = d.getVar('VIGILES_KERNEL_CONFIG') or ''
    _find_config(d, vgls_pf, config_in)
}


python() {

    pn = d.getVar('PN')
    kernel_pn = d.getVar('VIGILES_KERNEL_PN') or \
        d.getVar('PREFERRED_PROVIDER_virtual/kernel') or ''

    if pn == kernel_pn:
        bb.build.addtask('do_vigiles_kconfig', 'do_savedefconfig', 'do_configure', d)
        d.appendVarFlag('do_vigiles_kconfig', 'depends', ' %s:do_configure' % pn)
}

do_vigiles_kconfig[nostamp] = "1"


def _get_uboot_pf(d):
    from oe import recipeutils as oe

    pn = d.getVar('PN')
    boot_pn = d.getVar('VIGILES_UBOOT_PN') or \
        d.getVar('PREFERRED_PROVIDER_virtual/bootloader') or ''

    if not boot_pn:
        return ''

    pv = tsmeta_read_dictname_single(d, 'pn', boot_pn, 'pv')
    if not pv:
        pv = 'unset'
    (bpv, pfx, sfx) = oe.get_recipe_pv_without_srcpv(pv, 'git')

    vgls_pf = '-'.join([boot_pn, bpv])
    return vgls_pf


python do_vigiles_uboot_config() {
    import shutil

    bb.build.exec_func("do_vigiles_pkg", d)

    if not bb.data.inherits_class('uboot-config', d):
        return

    # The following is needed to avoid a configuration conflict
    # when python3.8 is installed on the host system.
    if '_PYTHON_SYSCONFIGDATA_NAME' in os.environ:
        del os.environ['_PYTHON_SYSCONFIGDATA_NAME']

    vgls_pf = _get_uboot_pf(d)
    config_in = d.getVar('VIGILES_UBOOT_CONFIG') or ''

    vgls_timestamp = d.getVar('VIGILES_TIMESTAMP')

    vgls_config_full = '_'.join([vgls_pf, vgls_timestamp])
    config_fname = '.'.join([vgls_config_full, 'config'])
    config_lname = '.'.join([vgls_pf, 'config'])

    bb.debug(1, "Translation: %s -> %s" % (config_fname, config_lname))

    vigiles_config_dir = d.getVar('VIGILES_DIR_KCONFIG')
    vigiles_dir = d.getVar('VIGILES_DIR')
    config_out = os.path.join(vigiles_config_dir, config_fname)
    config_link = os.path.join(vigiles_dir, config_lname)

    if os.path.lexists(config_link):
        os.remove(config_link)

    if not config_in:
        return

    if not os.path.exists(vigiles_config_dir):
        bb.utils.mkdirhier(vigiles_config_dir)

    if os.path.exists(config_in):
        bb.debug(1, "Copy: %s -> %s" %
                 (os.path.relpath(config_in), os.path.relpath(config_out)))
        shutil.copy(config_in, config_out)
    elif config_in == 'auto':
        build_dir = os.path.relpath(d.getVar('B'))
        uboot_machine = d.getVar('UBOOT_MACHINE') or None
        config_dirs = set([build_dir])
        for cfg in uboot_machine.split():
            config_dirs.add(os.path.join(build_dir, cfg))

        config_files = []
        autoconf_files = []

        for ddd in config_dirs:
            dot_config = os.path.join(ddd, '.config')
            if os.path.exists(dot_config):
                config_files.append(dot_config)
            header = os.path.join(ddd, 'include', 'autoconf.mk')
            if os.path.exists(header):
                autoconf_files.append(header)

        config_set = set()
        config_preamble = list()
        for dot_config in config_files:
            try:
                with open(dot_config, 'r') as cfg_in:
                    f_data = [ f_line.rstrip() for f_line in cfg_in ]
                    config_preamble = f_data[0:3]
                    config_set.update([
                        f_line
                        for f_line in f_data[3:]
                        if f_line.startswith('CONFIG')
                        and f_line.endswith('=y')
                    ])
            except Exception as e:
                bb.warn("Could not read/parse U-Boot .config: %s" % e)

        for header in autoconf_files:
            try:
                with open(header, 'r') as cfg_in:
                    f_data = [ f_line.rstrip() for f_line in cfg_in ]
                    config_set.update([
                        f_line
                        for f_line in f_data
                        if f_line.startswith('CONFIG')
                        and f_line.endswith('=y')
                    ])
            except Exception as e:
                bb.warn("Could not read/parse U-Boot autoconf.mk: %s" % e)
        bb.debug(1, "Writing %d values to : %s" % (len(config_set), config_out))
        with open(config_out, 'w') as f_out:
            print('\n'.join(config_preamble), file=f_out, flush=True)
            print('\n'.join(sorted(list(config_set))), file=f_out, flush=True)
    else:
        bb.warn("config does not exist, skipping.")
        bb.warn("config path: %s" % config_in)
        return

    bb.debug(1, "Link: %s -> %s" %
             (os.path.relpath(config_link), os.path.relpath(config_out)))
    os.symlink(os.path.relpath(config_out, vigiles_dir), config_link)
}


python() {

    pn = d.getVar('PN')
    boot_pn = d.getVar('VIGILES_UBOOT_PN') or \
        d.getVar('PREFERRED_PROVIDER_virtual/bootloader') or ''

    if pn == boot_pn:
        bb.build.addtask('do_vigiles_uboot_config', 'do_rm_work', 'do_compile', d)
        d.appendVarFlag('do_vigiles_uboot_config', 'depends', ' %s:do_compile' % pn)
}

do_vigiles_uboot_config[nostamp] = "1"


python do_vigiles_check() {
    v_dir = d.getVar('VIGILES_DIR')
    m_max_len = int(d.getVar('VIGILES_MANIFEST_NAME_MAX_LENGTH'))
    v_tstamp = d.getVar('VIGILES_TIMESTAMP')

    # truncate manifest_name to acceptable configured length
    _name = d.getVar('VIGILES_MANIFEST_NAME')[:m_max_len]
    _imgdirname = d.getVar('VIGILES_MANIFEST_NAME')[:m_max_len - 1]

    v_imgdir = _get_imgdir(v_dir, _imgdirname)

    vigiles_in = _get_vlink(v_dir, _name, m_max_len, d.getVar('VIGILES_MANIFEST_SUFFIX'))
    vigiles_out = _get_vout_path(v_imgdir, _name, m_max_len, v_tstamp, d.getVar('VIGILES_REPORT_SUFFIX'))
    vigiles_link = _get_vlink(v_dir, _name, m_max_len, d.getVar('VIGILES_REPORT_SUFFIX'))

    # The following is needed to avoid a configuration conflict
    # when python3.8 is installed on the host system.
    if '_PYTHON_SYSCONFIGDATA_NAME' in os.environ:
        del os.environ['_PYTHON_SYSCONFIGDATA_NAME']

    vigiles_kconfig = os.path.join(d.getVar('VIGILES_DIR'),
                                   '.'.join([_get_kernel_pf(d), 'config']))
    vigiles_uconfig = os.path.join(d.getVar('VIGILES_DIR'),
                                   '.'.join([_get_uboot_pf(d), 'config']))

    bb.utils.export_proxies(d)

    def run_checkcves(d, cmd, args=[]):
        bb.debug(1, "Checking CVEs against Vigiles Database")
        bb.debug(1, "Using Manifest at: %s" % os.path.relpath(vigiles_in))
        bb.debug(1, "Writing Report to: %s" % os.path.relpath(vigiles_link))

        if os.path.exists(vigiles_kconfig):
            bb.debug(1, "Using Kernel Config: %s" % os.path.relpath(vigiles_kconfig))
            args = args + ['-k', vigiles_kconfig]

        if os.path.exists(vigiles_uconfig):
            bb.debug(1, "Using U-Boot Config: %s" % os.path.relpath(vigiles_uconfig))
            args = args + ['-u', vigiles_uconfig]

        vigiles_env = os.environ.copy()

        #
        # The following logic allows the Key File and Dashboard Config to be
        # overridden by the user's environment -- if a build system sets a
        # generic key in local.conf (e.g. for automated builds), but a
        # developer wants/needs to use their own private credentials, those can
        # set in the shell environment.
        # They are handled in following way -- forwarding the values from the
        # original shell environment, but still passing the local.conf values on
        # the command line -- for compatibility with other Vigiles implementations.
        _orig_env = d.getVar('BB_ORIGENV', False)
        vigiles_env['VIGILES_KEY_FILE'] = _orig_env.getVar('VIGILES_KEY_FILE') or ''
        vigiles_env['VIGILES_DASHBOARD_CONFIG'] = _orig_env.getVar('VIGILES_DASHBOARD_CONFIG') or ''
        vigiles_env['VIGILES_SUBFOLDER_NAME'] = _orig_env.getVar('VIGILES_SUBFOLDER_NAME') or ''

        conf_key = d.getVar('VIGILES_KEY_FILE')
        if conf_key:
            args = args + ['-K', conf_key]
        conf_dashboard = d.getVar('VIGILES_DASHBOARD_CONFIG')
        if conf_dashboard:
            args = args + ['-C', conf_dashboard]
        conf_subfolder_name = d.getVar('VIGILES_SUBFOLDER_NAME')
        if conf_subfolder_name:
            args = args + ['-F', conf_subfolder_name]

        vigiles_env['LINUXLINK_SERVER'] = _orig_env.getVar('LINUXLINK_SERVER') or ''

        _upload_only = bb.utils.to_boolean(d.getVar('VIGILES_UPLOAD_ONLY'), False)
        if _upload_only:
            args = args + ['-U']

        #
        # Vigiles uses python3, and needs to use the Host-installed instance
        #  to avoid racing against the removal of the Yocto-built native
        #  instance when 'INHERIT += rm_work' is used.
        #
        # Note that python3 is a required HOSTTOOL by the poky tree, as of the
        #  pyro release, so we don't need to do 'HOSTTOOLs += python3'.
        #  See poky/meta/conf/bitbake.conf for definition.
        env_path = vigiles_env.get('PATH').split(os.path.pathsep)
        hosttools_dir = d.getVar('HOSTTOOLS_DIR')

        env_path.insert(0, hosttools_dir)
        vigiles_env['PATH'] = os.path.pathsep.join(env_path)

        layerdir = d.getVar('VIGILES_LAYERDIR')
        path = os.path.join(layerdir, "scripts", cmd)

        args = [path] + args

        bb.debug(1, "Vigiles Command Line: %s" % (" ").join(args))
        bb.debug(1, "Vigiles: Using Path: %s" % vigiles_env.get('PATH'))
        return bb.process.run(args, env=vigiles_env)

    _check_disabled = bb.utils.to_boolean(d.getVar('VIGILES_DISABLE_CHECK'), False)
    if _check_disabled:
        bb.plain("Vigiles: Skipping Check for %s" % d.getVar('VIGILES_MANIFEST_NAME')[:int(d.getVar('VIGILES_MANIFEST_NAME_MAX_LENGTH'))])
        return

    bb.utils.mkdirhier(os.path.dirname(vigiles_out))

    try:
        check_out, _ = run_checkcves(d, "checkcves.py", 
            [ '-m', vigiles_in, '-o', vigiles_out ])
    except bb.process.CmdError as err:
        bb.error("Vigiles: failed to execute checkcves.py: %s" % err)
        return
    except bb.process.CmdError as err:
        bb.error("Vigiles: checkcves.py failed: %s" % err)
        return
    except bb.process.NotFoundError as err:
        bb.error("Vigiles: checkcves.py could not be found: %s" % err)
        return

    bb.plain(check_out)

    if os.path.lexists(vigiles_link):
        os.remove(vigiles_link)
    if os.path.exists(vigiles_out):
        os.symlink(os.path.relpath(vigiles_out, os.path.dirname(vigiles_link)), vigiles_link)
}


addtask do_vigiles_check after do_image before do_image_complete
do_vigiles_check[nostamp] = "1"
do_vigiles_check[vardepsexclude] = "BB_ORIGENV"
do_vigiles_check[network] = "1"
