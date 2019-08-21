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

    return patched_dict


python do_vigiles_pkg() {
    pn = d.getVar('PN', True )
    bpn = d.getVar('BPN', True )

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
        manifest["patches"] = patches

        patched_dict = _get_patched(src_patches)

        if len(patched_dict):
            manifest["patched_cves"] = patched_dict

    tsmeta_write_dict(d, "cve", manifest)
}

def vigiles_get_build_dict(d):
    dict_in = dict (
            distro = dict (
                name = d.getVar('DISTRO', True ),
                vars = [ 'title', 'name', 'version', 'codename' ]
            ),
            image = dict (
                name = d.getVar('IMAGE_BASENAME', True ),
                vars = [ 'basename', 'link_name', 'name', 'pkgtype' ],
            ),
            machine = dict (
                name = d.getVar('MACHINE', True ),
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

    v_dir = "%s" % (d.getVar('VIGILES_DIR_IMAGE', True ))
    bb.note("Creating Vigiles Image Directory at %s" % v_dir)
    bb.utils.mkdirhier(v_dir)

    f_path = d.getVar('VIGILES_MANIFEST', True )
    with open(f_path, "w") as f_out:
        s = json.dumps(dict_out, indent=2, sort_keys=True)
        f_out.write(s)

    l_path = d.getVar('VIGILES_MANIFEST_LINK', True )
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
            manifest_version = d.getVar('VIGILES_MANIFEST_VERSION', True ),
            packages         = tsmeta_read_dictdir_files(d, "cve", pn_list),
            whitelist        = (d.getVar('VIGILES_WHITELIST', True ) or "").split(),
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
    imgdir = d.getVar('VIGILES_DIR_IMAGE', True )

    vigiles_in = d.getVar('VIGILES_MANIFEST_LINK', True )
    vigiles_out = d.getVar('VIGILES_REPORT', True )
    vigiles_link = d.getVar('VIGILES_REPORT_LINK', True )

    bb.utils.export_proxies(d)

    def run_checkcves(d, cmd, args=[]):
        bb.debug(1, "Checking CVEs against Vigiles Database")

        vigiles_kconfig = (d.getVar('VIGILES_KERNEL_CONFIG', True ) or "")
        if vigiles_kconfig:
            args = args + ['-k', vigiles_kconfig]

        vigiles_env = os.environ.copy()
        vigiles_env['VIGILES_KEY_FILE'] = d.getVar('VIGILES_KEY_FILE', True )

        layerdir = d.getVar('VIGILES_LAYERDIR', True )
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


def vigiles_image_depends(d):
    pn = d.getVar('PN', True )
    return "%s:do_vigiles_image" % pn if bb.data.inherits_class('image', d) else ""
do_vigiles_check[depends] += " ${@vigiles_image_depends(d)} "

addtask do_vigiles_check before do_rootfs
do_vigiles_check[nostamp] = "1"

python() {
    if bb.data.inherits_class('kernel', d):
        # Forward-compatibility with later renditions of kernel.bbclass
        d.setVar('CVE_PRODUCT', 'linux_kernel')
}
