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


addtask do_vigiles_pkg after do_packagedata
do_vigiles_pkg[nostamp] = "1"
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

    if pn != bpn:
        bb.debug(1, "Skipping extended PN %s [ %s ]" % (pn, bpn))
        return

    bb.build.exec_func("do_tsmeta_pkgvars", d)

    dict_in = dict(
        pn = dict(
            name = pn,
            vars = [ 'pn', 'pv' ],
        ),
        recipe = dict(
            name = pn,
            vars = [ 'layer', 'recipe' ],
        ),
        src = dict(
            name = pn,
            vars = [ 'cve_product', 'cve_version', 'sources', 'srcrev', 'patched_cves' ],
        ),
    )

    dict_out = { dict_name: tsmeta_get_dict(d, dict_name, dict_spec)
        for dict_name, dict_spec in dict_in.items() }

    manifest = dict(
            cve_product  = dict_out["src"].get("cve_product"),
            cve_version  = dict_out["src"].get("cve_version"),
            layer        = dict_out["recipe"].get("layer"),
            name         = dict_out["pn"].get("pn"),
            recipe       = dict_out["recipe"].get("recipe"),
            srcrev       = dict_out["src"].get("srcrev"),
            version      = dict_out["pn"].get("pv"),
        )

    if not len(manifest["srcrev"]):
        manifest.pop("srcrev")

    src_patches = dict_out["src"]["sources"].get("patches", {})
    if len(src_patches.keys()):
        patches = list(src_patches.keys())
        manifest["patches"] = sorted(patches)

        patched_dict = _get_patched(src_patches)

        if len(patched_dict):
            manifest["patched_cves"] = patched_dict

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
    if os.path.exists(l_path):
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
            layers           = {
                sys_dict["layers"][conf_name].get('fs_name') : sys_dict["layers"][conf_name]
                    for conf_name in sys_dict["layers"].keys()
                },
            machine          = sys_dict["machine"]["title"],
            manifest_version = d.getVar('VIGILES_MANIFEST_VERSION'),
            packages         = tsmeta_read_dictdir_files(d, "cve", pn_list),
            whitelist        = (d.getVar('VIGILES_WHITELIST') or "").split(),
        )
    return dict_out

python do_vigiles_image() {
    bb.note("Collecting Vigiles Metadata")
    cve_manifest = vigiles_image_collect(d)

    bb.note("Writing Vigiles Metadata")
    vigiles_write_manifest(d, "cve", cve_manifest)
}

addtask do_vigiles_image
do_vigiles_image[nostamp] = "1"
do_vigiles_image[recrdeptask] += "do_vigiles_pkg"
do_vigiles_image[recideptask] += "do_vigiles_pkg"

def vigiles_image_depends(d):
    pn = d.getVar('PN')
    backfill_pns = d.getVar('VIGILES_BACKFILL').split()
    deps = [ ':'.join([pn, 'do_vigiles_pkg']) for pn in backfill_pns ]
    deps.append("virtual/kernel:do_vigiles_kconfig")
    return ' '.join(deps)


do_vigiles_image[depends] += " ${@vigiles_image_depends(d)} "


def _get_kernel_pf(d):
    from oe import recipeutils as oe

    cve_v = "unset"
    if bb.data.inherits_class('kernel', d):
        bpn = d.getVar('BPN')
        pv = d.getVar('PV')
        (bpv, pfx, sfx) = oe.get_recipe_pv_without_srcpv(pv, 'git')
        cve_v_env = d.getVar('CVE_VERSION')
        cve_v = cve_v_env if cve_v_env else bpv
    else:
        bpn = d.getVar('PREFERRED_PROVIDER_virtual/kernel')

    kdict = tsmeta_read_dictname_vars(d, 'cve', bpn, ['name', 'cve_version'])
    cve_v = kdict.get('cve_version') or cve_v

    vgls_pf = '-'.join([bpn, cve_v])
    return vgls_pf


python do_vigiles_kconfig() {
    import shutil
    from oe import recipeutils as oe

    build_dir = os.path.relpath(d.getVar('B'))
    kconfig_in = os.path.join(build_dir, '.config')

    vgls_pf = _get_kernel_pf(d)
    vgls_timestamp = d.getVar('VIGILES_TIMESTAMP')

    vgls_kconfig_full = '_'.join([vgls_pf, vgls_timestamp])
    kconfig_fname = '.'.join([vgls_kconfig_full, 'config'])
    kconfig_lname = '.'.join([vgls_pf, 'config'])

    bb.debug(1, "Translation: %s -> %s" % (kconfig_fname, kconfig_lname))

    vigiles_kconfig = d.getVar('VIGILES_DIR_KCONFIG')
    vigiles_dir = d.getVar('VIGILES_DIR')
    kconfig_out = os.path.join(vigiles_kconfig, kconfig_fname)
    kconfig_link = os.path.join(vigiles_dir, kconfig_lname)

    if not os.path.exists(vigiles_kconfig):
        bb.utils.mkdirhier(vigiles_kconfig)

    bb.debug(1, "Copy: %s -> %s" % (os.path.relpath(kconfig_in), os.path.relpath(kconfig_out)))
    shutil.copy(kconfig_in, kconfig_out)

    if os.path.exists(kconfig_link):
        os.remove(kconfig_link)
    bb.debug(1, "Link: %s -> %s" % (os.path.relpath(kconfig_link), os.path.relpath(kconfig_out)))
    os.symlink(os.path.relpath(kconfig_out, vigiles_dir), kconfig_link)
}


def vigiles_kconfig_depends(d)->str:
    deps = str()

    if bb.data.inherits_class('kernel', d):
        vigiles_kconfig = d.getVar("VIGILES_KERNEL_CONFIG") or ""
        if vigiles_kconfig == "auto":
            pn = d.getVar('PN')
            kpref = d.getVar('PREFERRED_PROVIDER_virtual/kernel')
            if pn == kpref:
                deps = ("%s:do_configure" % pn)
    return deps

do_vigiles_kconfig[depends] += " ${@vigiles_kconfig_depends(d)} "

addtask do_vigiles_kconfig after do_configure before do_savedefconfig
do_vigiles_kconfig[nostamp] = "1"


python do_vigiles_check() {
    imgdir = d.getVar('VIGILES_DIR_IMAGE')

    vigiles_in = d.getVar('VIGILES_MANIFEST_LINK')
    vigiles_out = d.getVar('VIGILES_REPORT')
    vigiles_link = d.getVar('VIGILES_REPORT_LINK')


    vigiles_kconfig = d.getVar("VIGILES_KERNEL_CONFIG") or ""
    if vigiles_kconfig == "auto":
        kconfig_lname = '.'.join([_get_kernel_pf(d), 'config'])
        kconfig_path = os.path.join(d.getVar('VIGILES_DIR'), kconfig_lname)
        vigiles_kconfig = kconfig_path if os.path.exists(kconfig_path) else ""

    bb.utils.export_proxies(d)

    def run_checkcves(d, cmd, args=[]):
        bb.debug(1, "Checking CVEs against Vigiles Database")
        bb.debug(1, "Using Manifest at: %s" % os.path.relpath(vigiles_in))
        bb.debug(1, "Writing Report to: %s" % os.path.relpath(vigiles_link))

        if vigiles_kconfig:
            bb.debug(1, "Using Kernel Config: %s" % os.path.relpath(vigiles_kconfig))
            args = args + ['-k', vigiles_kconfig]

        vigiles_env = os.environ.copy()
        vigiles_env['VIGILES_KEY_FILE'] = d.getVar('VIGILES_KEY_FILE')

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

    if os.path.exists(vigiles_link):
        os.remove(vigiles_link)
    if os.path.exists(vigiles_out):
        os.symlink(os.path.relpath(vigiles_out, os.path.dirname(vigiles_link)), vigiles_link)
}

def vigiles_check_depends(d):
    pn = d.getVar('PN')
    deps = list()
    if bb.data.inherits_class('image', d):
        deps.append("%s:do_vigiles_image" % pn)
    return ' '.join(deps)

do_vigiles_check[depends] += " ${@vigiles_check_depends(d)} "

addtask do_vigiles_check before do_rootfs
do_vigiles_check[nostamp] = "1"
