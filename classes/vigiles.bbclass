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
            vars = [ 'cve_product', 'cve_version', 'sources', 'srcrev' ],
        ),
    )

    dict_out = { dict_name: tsmeta_get_dict(d, dict_name, dict_spec)
        for dict_name, dict_spec in dict_in.items() }

    manifest = dict(
            cve_product  = dict_out["src"].get("cve_product"),
            cve_version  = dict_out["src"].get("cve_version"),
            layer        = dict_out["recipe"].get("layer"),
            name         = dict_out["pn"].get("pn"),
            patches      = dict_out["src"]["sources"].get("patches", []),
            recipe       = dict_out["recipe"].get("recipe"),
            srcrev       = dict_out["src"].get("srcrev"),
            version      = dict_out["pn"].get("pv"),
        )

    if not len(manifest["srcrev"]):
        manifest.pop("srcrev")
    if not len(manifest["patches"]):
        manifest.pop("patches")

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

do_vigiles_image[depends] += " ${@' '.join( \
    [ '%s:do_vigiles_pkg' % pn for pn in \
        d.getVar('VIGILES_BACKFILL', True).split() ] \
)} "



python do_vigiles_check() {
    imgdir = d.getVar('VIGILES_DIR_IMAGE')

    vigiles_in = d.getVar('VIGILES_MANIFEST_LINK')
    vigiles_out = d.getVar('VIGILES_REPORT')
    vigiles_link = d.getVar('VIGILES_REPORT_LINK')

    bb.utils.export_proxies(d)

    def run_checkcves(d, cmd, args=[]):
        bb.debug(1, "Checking CVEs against Vigiles Database")

        vigiles_kconfig = (d.getVar('VIGILES_KERNEL_CONFIG') or "")
        if vigiles_kconfig:
            args = args + ['-k', vigiles_kconfig]

        vigiles_env = os.environ.copy()
        vigiles_env['VIGILES_KEY_FILE'] = d.getVar('VIGILES_KEY_FILE')

        layerdir = d.getVar('VIGILES_LAYERDIR')
        path = os.path.join(layerdir, "scripts", cmd)

        args = [path] + args

        bb.debug(1, "Vigiles Command Line: %s" % (" ").join(args))
        return bb.process.run(args, env=vigiles_env)

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
    bb.utils.mkdirhier(os.path.dirname(vigiles_out))

    if os.path.exists(vigiles_link):
        os.remove(vigiles_link)
    if os.path.exists(vigiles_out):
        os.symlink(os.path.relpath(vigiles_out, os.path.dirname(vigiles_link)), vigiles_link)
}

addtask do_vigiles_check
do_vigiles_check[nostamp] = "1"


python() {
    pn = d.getVar('PN')

    if bb.data.inherits_class('image', d):
        d.appendVarFlag('do_vigiles_check', 'depends', " %s:do_vigiles_image" % pn)
        d.appendVarFlag('do_build', 'depends', " %s:do_vigiles_check" % pn)
}
