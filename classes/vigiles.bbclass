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
        'cve_product',
        'cve_version',
        'layer',
        'license',
        'recipe',
        'sources',
        'srcrev',
        'patched_cves'
    ]
    pn_dict = tsmeta_read_dictname_vars(d, 'pn', pn, pn_vars)
    manifest = tsmeta_read_dictname_vars(d, 'src', pn, src_vars)
    manifest['name'] = pn_dict['pn']
    manifest['version'] = pn_dict['pv']

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


def vigiles_write_manifest(d, tdw_tag, dict_out):
    import json

    v_dir = "%s" % (d.getVar('VIGILES_DIR_IMAGE'))
    bb.note("Creating Vigiles Image Directory at %s" % v_dir)
    bb.utils.mkdirhier(v_dir)

    f_path = d.getVar('VIGILES_MANIFEST')
    with open(f_path, "w") as f_out:
        s = json.dumps(dict_out, indent=2, sort_keys=True)
        f_out.write(s)

    l_path = d.getVar('VIGILES_MANIFEST_LINK')
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
    virtual/kernel \
    virtual/bootloader \
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
    rdep_list = tsmeta_pn_list(d)

    # This list() cast will remove duplicates if the backfill packages are
    # already present
    pn_list = list(sorted(backfill_list + rdep_list))

    dict_out = dict(
            date             = datetime.utcnow().isoformat(),
            distro           = sys_dict["distro"]["codename"],
            distro_version   = sys_dict["distro"]["version"],
            image            = sys_dict["image"]["basename"],
            layers           = sys_dict["layers"],
            machine          = sys_dict["machine"]["title"],
            manifest_version = d.getVar('VIGILES_MANIFEST_VERSION'),
            packages         = tsmeta_read_dictdir_files(d, "cve", pn_list),
            whitelist        = (d.getVar('VIGILES_WHITELIST') or "").split(),
        )
    dict_out.update(_get_extra_packages(d))
    _filter_excluded_packages(d, dict_out['packages'])
    return dict_out

python do_vigiles_image() {
    bb.note("Collecting Vigiles Metadata")
    cve_manifest = vigiles_image_collect(d)

    bb.note("Writing Vigiles Metadata")
    vigiles_write_manifest(d, "cve", cve_manifest)
}

addtask do_vigiles_image after do_image_complete
do_vigiles_image[nostamp] = "1"
do_rootfs[nostamp] = "1"
do_vigiles_image[recrdeptask] += "do_vigiles_pkg"
do_vigiles_image[recideptask] += "do_vigiles_pkg"


def vigiles_image_depends(d):
    pn = d.getVar('PN')
    deps = list()
    if bb.data.inherits_class('image', d):
        backfill_pns = d.getVar('VIGILES_BACKFILL').split()
        deps = [ ':'.join([_pn, 'do_vigiles_pkg']) for _pn in backfill_pns ]
        _uboot = d.getVar('PREFERRED_PROVIDER_virtual/bootloader', True) or ''
        if _uboot:
            deps.append('%s:do_vigiles_uboot_config' % _uboot)

    return ' '.join(deps)


do_vigiles_image[depends] += "virtual/kernel:do_vigiles_kconfig"
do_vigiles_image[depends] += " ${@vigiles_image_depends(d)} "


def _get_kernel_pf(d):
    from oe import recipeutils as oe

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
    from oe import recipeutils as oe

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


do_vigiles_kconfig[depends] += "virtual/kernel:do_configure"

addtask do_vigiles_kconfig after do_configure before do_savedefconfig
do_vigiles_kconfig[nostamp] = "1"


def _get_uboot_pf(d):
    from oe import recipeutils as oe

    pn = d.getVar('PN')
    bpn = d.getVar('PREFERRED_PROVIDER_virtual/bootloader') or ''

    if not bpn:
        return bpn

    if bb.data.inherits_class('uboot-config', d) and pn == bpn:
        tsmeta_get_pn(d)

    pv = tsmeta_read_dictname_single(d, 'pn', bpn, 'pv')
    if not pv:
        pv = 'unset'
    (bpv, pfx, sfx) = oe.get_recipe_pv_without_srcpv(pv, 'git')

    vgls_pf = '-'.join([bpn, bpv])
    return vgls_pf


python do_vigiles_uboot_config() {
    import shutil
    from oe import recipeutils as oe

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
    if bb.data.inherits_class('uboot-config', d):
        pn = d.getVar('PN')
        bpn = d.getVar('PREFERRED_PROVIDER_virtual/bootloader') or ''

        if pn == bpn:
            bb.build.addtask('do_vigiles_uboot_config', 'do_rm_work', 'do_compile', d)
            d.appendVarFlag('do_vigiles_uboot_config', 'depends', ' %s:do_compile' % pn)
}

do_vigiles_uboot_config[nostamp] = "1"


python do_vigiles_check() {
    imgdir = d.getVar('VIGILES_DIR_IMAGE')

    vigiles_in = d.getVar('VIGILES_MANIFEST_LINK')
    vigiles_out = d.getVar('VIGILES_REPORT')
    vigiles_link = d.getVar('VIGILES_REPORT_LINK')
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
        vigiles_env['VIGILES_KEY_FILE'] = d.getVar('VIGILES_KEY_FILE')
        vigiles_env['VIGILES_DASHBOARD_CONFIG'] = d.getVar('VIGILES_DASHBOARD_CONFIG')

        layerdir = d.getVar('VIGILES_LAYERDIR')
        path = os.path.join(layerdir, "scripts", cmd)

        args = [path] + args

        bb.debug(1, "Vigiles Command Line: %s" % (" ").join(args))
        return bb.process.run(args, env=vigiles_env)

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

def vigiles_check_depends(d):
    pn = d.getVar('PN')
    deps = list()
    if bb.data.inherits_class('image', d):
        deps.append("%s:do_vigiles_image" % pn)
        d.appendVarFlag('do_build', 'depends', ' %s:do_vigiles_check' % pn)
    return ' '.join(deps)

do_vigiles_check[depends] += " ${@vigiles_check_depends(d)} "

addtask do_vigiles_check after do_vigiles_image
do_vigiles_check[nostamp] = "1"
