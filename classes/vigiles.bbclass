###########################################################
#
# classes/vigiles.bbclass - Yocto CVE Scanner
#
# Copyright (C) 2019 Timesys Corporation
# Copyright (C) 2025 Lynx Software Technologies, Inc. All rights reserved.
#
# This source is released under the MIT License.
#
###########################################################

inherit tsmeta

require conf/vigiles.conf


addtask do_vigiles_pkg after do_packagedata before do_rm_work
do_vigiles_pkg[nostamp] = "1"
do_vigiles_pkg[rdeptask] += "do_packagedata"
do_vigiles_pkg[depends] += "${PN}:do_vigiles_patchmeta"

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

        with open(patch_file, "r") as f:
            try:
                patch_text = f.read()
            except UnicodeDecodeError:
                bb.plain("Failed to open patch %s (possible encoding error)"
                        %  patch_file)

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
    import re

    version = version.split("+git")[0]
    match = re.match(r"^(.*?)[~-]([a-zA-Z].*)$", version)
    if match:
        version = match.group(1)
        update = match.group(2)
    else:
        update = "*"

    cpe_ids = []
    for product in cve_product.split():
        # CVE_PRODUCT in recipes may include vendor information for CPE identifiers.
        # If not, use wildcard for vendor.
        if ":" in product:
            vendor, product = product.split(":", 1)
        else:
            vendor = "*"

        cpe_id = 'cpe:2.3:a:%s:%s:%s:%s:*:*:*:*:*:*' % (vendor, product, version, update)
        if validate_cpe_ids(cpe_id):
            cpe_ids.append(cpe_id)
        else:
            bb.plain("For package %s, could not generate CPE ID." % cve_product)

    return cpe_ids

def validate_cpe_ids(cpe_id):
    """
    Validates a CPE 2.3 string using regex.
    Returns True if valid, else False.
    """
    import re
    return bool(re.search(
        r"^cpe:2\.3:[aho](?::(?:[a-zA-Z0-9!\"#$%&'()*+,\\\-_.\/;<=>?@\[\]^`{|}%\+]|\\:)+){10}$",
        cpe_id
    ))

def vigiles_get_build_dependencies(d):
    taskdepdata = d.getVar("BB_TASKDEPDATA", True)
    current_pn = d.getVar("PN", True)
    task_name = "do_collect_build_deps"
    dep_dict = {
        'pn': current_pn,
        'deps': sorted(set([
            dep[0] for dep in taskdepdata.values()
            if dep[0] != current_pn and dep[1] == task_name 
            ]))
        }

    tsmeta_write_dict(d, "build_deps", dep_dict)

vigiles_get_build_dependencies[vardepsexclude] += "BB_TASKDEPDATA"

python do_collect_build_deps() {
    vigiles_get_build_dependencies(d)
    vigiles_collect_pkg_info(d)
}

addtask do_collect_build_deps after do_package do_packagedata before do_populate_sdk do_build do_rm_work
do_collect_build_deps[nostamp] = "1"
do_collect_build_deps[deptask] = "do_collect_build_deps"

def vigiles_collect_package_providers(d):
    import oe.packagedata
    providers = {}

    taskdepdata = d.getVar("BB_TASKDEPDATA", False)
    current_pn = d.getVar("PN", True)
    deps = sorted(set(
        dep[0] for dep in taskdepdata.values() if dep[0] != current_pn
    ))
    deps.append(current_pn)

    for dep_pn in deps:
        recipe_data = oe.packagedata.read_pkgdata(dep_pn, d)
        for pkg in recipe_data.get("PACKAGES", "").split():
            pkg_data = oe.packagedata.read_subpkgdata_dict(pkg, d)
            rprovides = set(n for n, _ in bb.utils.explode_dep_versions2(pkg_data.get("RPROVIDES", "")).items())
            rprovides.add(pkg)

            for r in rprovides:
                providers[r] = pkg

    return providers

vigiles_collect_package_providers[vardepsexclude] += "BB_TASKDEPDATA"


def parse_rdeps(pkg, rdep_dict):
    def _split_ver(s):
        ver = s.split('(', 1)[-1].split(')', 1)[0].strip()
        return ver if ver != s else ''

    rdeps = rdep_dict.get(pkg, {}).get("rdepends", [])
    out = {}
    if len(rdeps) > 1:
        for r in rdeps[1:]:
            dep_pkg = r.split()[0]
            out[dep_pkg] = _split_ver(r)
    return out

python do_collect_runtime_deps() {
    is_native = bb.data.inherits_class("native", d) or bb.data.inherits_class("cross", d)
    providers = vigiles_collect_package_providers(d)
    pn = d.getVar("PN", True)
    if not is_native:
        bb.build.exec_func("read_subpackage_metadata", d)
        for package in d.getVar("PACKAGES", True).split():
            localdata = bb.data.createCopy(d)
            pkg_name = d.getVar("PKG:%s" % package, True) or d.getVar("PKG_%s" % package, True) or package
            localdata.setVar("PKG", pkg_name)
            localdata.setVar('OVERRIDES', d.getVar("OVERRIDES", False) + ":" + package)
            
            deps = bb.utils.explode_dep_versions2(localdata.getVar("RDEPENDS", True) or "")
            rdeps = set()  
            for dep, _ in deps.items():
                if dep in rdeps:
                    continue

                if dep not in providers:
                    continue

                dep = providers[dep]

                if not oe.packagedata.packaged(dep, d):
                    continue

                dep_pkg_data = oe.packagedata.read_subpkgdata_dict(dep, d)
                dep_pkg = dep_pkg_data["PKG"]
                rdeps.add(dep_pkg)

            dep_dict = {
                'pn': pn,
                'deps': list(rdeps)
                }

            tsmeta_write_dictname(localdata, "runtime_deps", pkg_name, dep_dict)
}

addtask do_collect_runtime_deps after do_collect_build_deps before do_build do_rm_work

do_collect_runtime_deps[rdeptask] = "do_collect_build_deps"
do_rootfs[recrdeptask] += "do_collect_build_deps do_collect_runtime_deps"
do_populate_sdk[recrdeptask] += "do_collect_build_deps do_collect_runtime_deps"


def get_package_checksum(d):
    CHECKSUM_LIST = [ "md5", "sha256", "sha1", "sha384", "sha512" ]

    allowed_checksums = ("SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "MD2", "MD4", "MD5", "MD6")
    checksums = []

    for src_uri in d.getVar('SRC_URI', True).split():
        fetch_data = bb.fetch2.FetchData(src_uri, d)
        if fetch_data.localpath and fetch_data.method.supports_checksum(fetch_data):
            for checksum_id in CHECKSUM_LIST:
                if checksum_id.upper() not in allowed_checksums:
                    continue

                if "name" in fetch_data.parm:
                    checksum_name = "%s.%ssum" % (fetch_data.parm["name"], checksum_id)
                else:
                    checksum_name = "%ssum" % checksum_id

                if checksum_name in fetch_data.parm:
                    checksum_expected = fetch_data.parm[checksum_name]
                elif fetch_data.type not in ["http", "https", "ftp", "ftps", "sftp", "s3", "az", "crate"]:
                    checksum_expected = None
                else:
                    checksum_expected = d.getVarFlag("SRC_URI", checksum_name, True)

                checksum = checksum_expected
                if checksum is None:
                    continue

                checksums.append({
                    "algorithm": checksum_id.upper(),
                    "checksum_value": checksum
                })
    
    return checksums

python do_vigiles_patchmeta() {
    import json
    import oe.recipeutils
    import os

    src_patches_raw = oe.recipeutils.get_recipe_patches(d)
    src_patches = { os.path.basename(p) : p for p in src_patches_raw }

    patched_cves = _get_patched(src_patches)

    patch_meta = {
        "src_patches": src_patches,
        "patched_cves": patched_cves
    }

    workdir = d.getVar("VIGILES_PATCHMETA_DIR", True)

    if not os.path.exists(workdir):
        os.makedirs(workdir)

    outfile = os.path.join(workdir, "vigiles-patches.json")

    with open(outfile, "w") as f:
        bb.debug(2, "Writing patchmeta to: %s" % outfile)
        f.write(json.dumps(patch_meta, indent=2))
}

addtask vigiles_patchmeta after do_patch before do_compile

SSTATETASKS += "do_vigiles_patchmeta"

do_vigiles_patchmeta[dirs] = "${VIGILES_PATCHMETA_DIR} ${VIGILES_PATCHMETA_DEPLOY}"
do_vigiles_patchmeta[vardeps] += "SRC_URI"
do_vigiles_patchmeta[sstate-inputdirs] = "${VIGILES_PATCHMETA_DIR}"
do_vigiles_patchmeta[sstate-outputdirs] = "${VIGILES_PATCHMETA_DEPLOY}"
do_vigiles_patchmeta[cleandirs] = "${VIGILES_PATCHMETA_DEPLOY}"

python do_vigiles_patchmeta_setscene () {
    sstate_setscene(d)
}
addtask do_vigiles_patchmeta_setscene


def vigiles_collect_pkg_info(d):
    import json
    
    pn = d.getVar('PN', True)
    bpn = d.getVar('BPN', True)

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
        'patched_cves',
        'summary',
        'homepage',
        'src_uri',
        'pkg_cpe_id',
        'release_date',
        'end_of_life',
        'level_of_support'
    ]
    pn_dict = tsmeta_read_dictname_vars(d, 'pn', pn, pn_vars)
    manifest = tsmeta_read_dictname_vars(d, 'src', pn, src_vars)
    manifest['name'] = pn_dict['pn']
    manifest['version'] = manifest.get('cve_version', pn_dict['pv'])
    # Add cpe_id for each package in manifest to support spdx format
    manifest['cpe_id'] = manifest.get('pkg_cpe_id') or get_cpe_ids(manifest['cve_product'], manifest['cve_version'])
    manifest.pop('pkg_cpe_id')

    # Clean up cve_version by removing leading '-' or '~' if present
    import re
    cve_version = manifest['cve_version']
    match = re.match(r"^(.*?)[~-]([a-zA-Z].*)$", cve_version)
    if match:
        manifest['cve_version'] = match.group(1) + match.group(2)

    # Add download location in manifest json
    src_uri_list = manifest.pop('src_uri')
    for src_uri in src_uri_list:
        if not src_uri.startswith("file://"):
            manifest['download_location'] = src_uri
            break
    else:
        manifest['download_location'] = "UNKNOWN"

    sources = manifest.pop('sources')
    patch_metafile = os.path.join(d.getVar("VIGILES_PATCHMETA_DIR", True), "vigiles-patches.json")
    patches = []
    patched_dict = {}

    if os.path.exists(patch_metafile):
        with open(patch_metafile, "r") as f:
            patch_meta = json.load(f)
            patches = list(patch_meta.get("src_patches", {}).keys())
            patched_dict = patch_meta.get("patched_cves", {})

    if patches:
        manifest['patches'] = sorted(patches)
    if len(patched_dict):
        manifest['patched_cves'] = patched_dict

    if not len(manifest['srcrev']):
        manifest.pop('srcrev')
    if not len(manifest['patched_cves']):
        manifest.pop('patched_cves')
    if not manifest['release_date']:
        manifest.pop('release_date')
    if not manifest['end_of_life']:
        manifest.pop('end_of_life')
    if not manifest['level_of_support']:
        manifest.pop('level_of_support')

    manifest['checksums'] = get_package_checksum(d)

    tsmeta_write_dict(d, "cve", manifest)


python do_vigiles_pkg() {
    vigiles_collect_pkg_info(d)
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

    v_dir = d.getVar('VIGILES_DIR', True)
    m_max_len = int(d.getVar('VIGILES_MANIFEST_NAME_MAX_LENGTH'))
    v_tstamp = d.getVar('VIGILES_TIMESTAMP', True)

    # truncate manifest name to acceptable configured length
    _name = d.getVar('VIGILES_MANIFEST_NAME', True)[:m_max_len]
    _imgdirname = d.getVar('VIGILES_MANIFEST_NAME', True)[:m_max_len - 1]

    v_imgdir = _get_imgdir(v_dir, _imgdirname)
    bb.note("Creating Vigiles Image Directory at %s" % v_imgdir)
    bb.utils.mkdirhier(v_imgdir)

    f_path = _get_vout_path(v_imgdir, _name, m_max_len, v_tstamp, d.getVar('VIGILES_MANIFEST_SUFFIX', True))
    with open(f_path, "w") as f_out:
        s = json.dumps(dict_out, indent=2, sort_keys=True)
        f_out.write(s)

    l_path = _get_vlink(v_dir, _name, m_max_len, d.getVar('VIGILES_MANIFEST_SUFFIX', True))

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

VIGILES_BACKFILL += "${VIGILES_EXTRA_BACKFILL}"

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

    vgls_extra = d.getVar('VIGILES_EXTRA_PACKAGES', True ) or ''
    extra_files = oe.utils.squashspaces(vgls_extra).split(' ')
    if not extra_files:
        bb.debug(2, "Vigiles: No Extra Packages.")
        return {}

    bb.debug(1, "Importing Extra Packages from %s" % extra_files)

    additional = {
        'additional_licenses': defaultdict(str),
        'additional_packages': defaultdict(dict),
        'additional_packages_info': defaultdict(dict)
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
                    release_date = row[3].strip() if len(row) > 3 else ''
                    end_of_life = row[4].strip() if len(row) > 4 else ''
                    level_of_support = row[5].strip() if len(row) > 5 else ''

                    extra_rows.append([pkg, ver, license, release_date, end_of_life, level_of_support])
        except Exception as e:
            bb.warn("Vigiles Extras File: %s" % e)
            return {}

    if not extra_rows:
        return {}

    # Skip CSV header if present
    header = extra_rows[0]
    if header[0].lower() == "product":
        extra_rows = extra_rows[1:]

    include_closed_license = bb.utils.to_boolean(d.getVar(
        "VIGILES_INCLUDE_CLOSED_LICENSES", True
    ))

    for row in extra_rows:
        pkg = row[0].replace(' ', '-')
        ver = row[1].replace(' ', '.')
        license = row[2]
        release_date = row[3]
        end_of_life = row[4]
        level_of_support = row[5]

        if not include_closed_license and license == "CLOSED":
            continue

        license_key = pkg + ver

        bb.debug(1, "Extra Package: %s, Version: %s, License: %s = %s" %
                 (pkg, ver, license_key, license))

        pkg_vers = set(additional['additional_packages'].get(pkg, []))
        pkg_vers.add(ver)

        additional['additional_packages'][pkg] = sorted(list(pkg_vers))
        additional['additional_licenses'][license_key] = license

        # Update lifecycle info dictionary if any value exists
        lifecycle = {}
        if release_date:
            lifecycle['release_date'] = release_date
        if end_of_life:
            lifecycle['end_of_life'] = end_of_life
        if level_of_support:
            los_value =_get_valid_los(level_of_support)
            if los_value:
                lifecycle["level_of_support"] = los_value
            else:
                bb.warn(
                    "Invalid level_of_support '%s' for additional package '%s'. Refer to the README for valid values."
                    % (level_of_support, pkg)
                )

        if lifecycle:
            key = pkg + ver if ver else pkg
            additional['additional_packages_info'][key] = lifecycle

    if not additional['additional_packages_info']:
        additional.pop('additional_packages_info',None)

    return additional


##
#   Packages can be excluded from the manifest by setting
#    'VIGILES_EXCLUDE' in local.conf, which is expected to be a list of
#    .csv files in the format of
#       <product>
##
def _filter_excluded_packages(d, vgls_pkgs):
    import csv

    vgls_excld_files = d.getVar('VIGILES_EXCLUDE', True ) or ''
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

def _get_packages(d, pn_list):
    indict = tsmeta_read_dictdir(d, "cve")
    include_closed_license = bb.utils.to_boolean(d.getVar('VIGILES_INCLUDE_CLOSED_LICENSES'))
    dict_out = {}
    for pn in pn_list:
        if pn in indict.keys():
            if not include_closed_license and indict.get(pn, {}).get("license", "").lower() == "closed":
                continue
            dict_out[pn] = indict.get(pn, {})
            dict_out[pn]["component_type"] = ["component"]
    return dict_out

def vigiles_image_collect(d):
    from datetime import datetime

    def get_dep_pns(pn, deps, tsmeta_dir):
        dep_pns = set()
        dep_reference = tsmeta_read_dictdir(d, tsmeta_dir)
        for dep in deps:
            dep_pn = dep_reference.get(dep, {}).get("pn", "")
            if dep_pn and dep_pn != pn:
                dep_pns.add(dep_pn)
        return list(dep_pns)

    def add_dependencies(dict_out):
        from collections import deque, defaultdict

        def get_pkgs(src):
            all_pkgs = src.get("deps", [])
            if bb.utils.to_boolean(d.getVar('VIGILES_SBOM_ROOTFS_MANIFEST_ONLY', True)):
                return [p for p in all_pkgs if p in rootfs_pkg_set]
            return all_pkgs

        dependency_only_comment = {
            "build": "Dependency Only; This component was identified as a build dependency by Vigiles",
            "runtime": "Dependency Only; This component was identified as a runtime dependency by Vigiles",
            "build&runtime": "Dependency Only; This component was identified as a build and runtime dependency by Vigiles",
        }

        packages = dict_out['packages']
        deps = defaultdict(lambda : {"build": set(), "runtime": set()})
        rootfs_pkg_set = set(packages.keys())
        queue = deque(rootfs_pkg_set)
        parsed_keys = set()
        build_deps = set()
        runtime_deps = set()

        while queue:
            key = queue.popleft()
            if key in parsed_keys:
                continue

            parsed_keys.add(key)

            bdep_dict = tsmeta_read_dictname(d, "build_deps", key)
            rdep_dict = tsmeta_read_dictname(d, "runtime_deps", key)

            bdeps = get_pkgs(bdep_dict)
            rdeps = get_pkgs(rdep_dict)

            key_pn = bdep_dict.get("pn", rdep_dict.get("pn")) or key

            # Collect PN's of the package to avoid multiple packages with same cve_product
            bdep_pns = get_dep_pns(key_pn, bdeps, "build_deps")
            rdep_pns = get_dep_pns(key_pn, rdeps, "runtime_deps")

            deps[key_pn]["build"].update(bdep_pns)
            deps[key_pn]["runtime"].update(rdep_pns)

            queue.extend(bdeps + rdeps)

            build_deps.update(bdep_pns)
            runtime_deps.update(rdep_pns)

        build_and_runtime = build_deps & runtime_deps
        build_only = build_deps - runtime_deps
        runtime_only = runtime_deps - build_deps
        
        for pkg, dep_info in deps.items():
            if not packages.get(pkg):
                pkg_info = tsmeta_read_dictname(d, 'cve', pkg)
                packages[pkg] = pkg_info
            
            if "dependencies" not in packages[pkg]:
                packages[pkg]["dependencies"] = {"build": [], "runtime": []}
            
            packages[pkg]["dependencies"]["build"] = sorted(list(dep_info["build"]))
            packages[pkg]["dependencies"]["runtime"] = sorted(list(dep_info["runtime"]))
            packages[pkg]["package_supplier"] = d.getVar('SPDX_SUPPLIER', True)
            component_type = packages[pkg].get("component_type", [])
            if not component_type:
                packages[pkg]["component_type"] = []

            if pkg in build_and_runtime:
                packages[pkg]["component_type"].extend(["build", "runtime"])
                if not component_type:
                    packages[pkg]["comment"] = dependency_only_comment["build&runtime"]
            elif pkg in build_only:
                packages[pkg]["component_type"].append("build")
                if not component_type:
                    packages[pkg]["comment"] = dependency_only_comment["build"]
            elif pkg in runtime_only:
                packages[pkg]["component_type"].append("runtime")
                if not component_type:
                    packages[pkg]["comment"] = dependency_only_comment["runtime"]

            packages[pkg]["component_type"].sort()

    def set_package_field_defaults(manifest):
        for pkg, pkg_dict in manifest.get("packages", {}).items():
            if not pkg_dict.get("version", ""):
                pkg_dict["version"] = "unset"
            if not pkg_dict.get("cve_version", ""):
                pkg_dict["cve_version"] = pkg_dict["version"]
            if not pkg_dict.get("name", ""):
                pkg_dict["name"] = pkg
            if not pkg_dict.get("cve_product", ""):
                pkg_dict["cve_product"] = pkg
            if not pkg_dict.get("license", ""):
                pkg_dict["license"] = "unknown"
            if not pkg_dict.get("checksums", ""):
                pkg_dict["checksums"] = []
        return manifest

    sys_dict = vigiles_get_build_dict(d)

    backfill_list = d.getVar('VIGILES_BACKFILL', True).split()

    boot_pn = d.getVar('VIGILES_UBOOT_PN', True ) or \
        d.getVar('PREFERRED_PROVIDER_virtual/bootloader', True ) or ''
    if boot_pn:
        backfill_list.append(boot_pn)

    kernel_pn = d.getVar('VIGILES_KERNEL_PN', True ) or \
        d.getVar('PREFERRED_PROVIDER_virtual/kernel', True ) or ''
    if kernel_pn:
        backfill_list.append(kernel_pn)

    if "tegra" in sys_dict.get('layers', {}).keys():
        secure_os = d.getVar('PREFERRED_PROVIDER_virtual/secure-os', True) or ''
        if secure_os:
            backfill_list.append(secure_os)
            pn_dict = tsmeta_read_dictname(d, "pn", secure_os)
            deps = pn_dict.get("depends", [])

            for dep in deps:
                if dep.startswith("virtual") or "native" in dep or "cross" in dep:
                    continue
                backfill_list.append(dep)

    initramfs_image = d.getVar('INITRAMFS_IMAGE', True)
    if initramfs_image:
        backfill_list.append(initramfs_image)
    rdep_list = tsmeta_pn_list(d)

    # This list() cast will remove duplicates if the backfill packages are
    # already present
    pn_list = list(sorted(backfill_list + rdep_list))

    # truncate manifest_name to acceptable configured length
    _name = d.getVar('VIGILES_MANIFEST_NAME', True)[:int(d.getVar('VIGILES_MANIFEST_NAME_MAX_LENGTH', True))]

    dict_out = dict(
            date             = datetime.utcnow().isoformat(),
            distro           = sys_dict["distro"]["codename"],
            distro_version   = sys_dict["distro"]["version"],
            image            = sys_dict["image"]["basename"],
            layers           = sys_dict["layers"],
            machine          = sys_dict["machine"]["title"],
            manifest_version = d.getVar('VIGILES_MANIFEST_VERSION', True ),
            manifest_name    = _name,
            packages         = _get_packages(d, pn_list),
            whitelist        = (d.getVar('VIGILES_WHITELIST', True ) or "").split(),
        )
    dict_out.update(_get_extra_packages(d))
    _filter_excluded_packages(d, dict_out['packages'])
    
    add_dependencies(dict_out)
    # Add default package fields
    dict_out = set_package_field_defaults(dict_out)

    return dict_out

python () {
    pn = d.getVar("PN", True)
    initramfs_image = d.getVar("INITRAMFS_IMAGE", True)

    if pn == initramfs_image:
        if bb.utils.to_boolean(d.getVar('VIGILES_DISABLE_INITRAMFS_SBOM', True)):
            d.setVar('VIGILES_DISABLE_INITRAMFS_REPORT', d.getVar('VIGILES_DISABLE_INITRAMFS_SBOM', True))
            d.appendVarFlag('do_vigiles_image', 'noexec', "1")
        if bb.utils.to_boolean(d.getVar('VIGILES_DISABLE_INITRAMFS_REPORT', True)):
            d.appendVarFlag('do_vigiles_check', 'noexec', "1")
}

python do_vigiles_image() {
    bb.note("Collecting Vigiles Metadata")
    cve_manifest = vigiles_image_collect(d)

    bb.note("Writing Vigiles Metadata")
    vigiles_write_manifest(d, "cve", cve_manifest)
}

addtask do_vigiles_image after do_rootfs before do_vigiles_check
do_vigiles_image[nostamp] = "1"
do_rootfs[nostamp] = "1"
do_rootfs[recrdeptask] += "do_vigiles_pkg"
do_rootfs[recideptask] += "do_vigiles_pkg"


def vigiles_image_depends(d):
    pn = d.getVar('PN', True )
    deps = list()
    if bb.data.inherits_class('image', d):
        backfill_pns = d.getVar('VIGILES_BACKFILL', True ).split()
        deps = [ ':'.join([_pn, 'do_vigiles_pkg']) for _pn in backfill_pns ]

        boot_pn = d.getVar('VIGILES_UBOOT_PN', True ) or \
            d.getVar('PREFERRED_PROVIDER_virtual/bootloader', True ) or ''
        if boot_pn:
            deps.append('%s:do_vigiles_uboot_config' % boot_pn)

        kernel_pn = d.getVar('VIGILES_KERNEL_PN', True ) or \
            d.getVar('PREFERRED_PROVIDER_virtual/kernel', True ) or ''
        if kernel_pn:
            deps.append('%s:do_vigiles_kconfig' % kernel_pn)

    return ' '.join(deps)


do_vigiles_image[depends] += " ${@vigiles_image_depends(d)} "


def _get_kernel_pf(d):
    bpn = d.getVar('PREFERRED_PROVIDER_virtual/kernel', True )
    kdict = tsmeta_read_dictname_vars(d, 'cve', bpn, ['name', 'cve_version']) or {}
    cve_v = kdict.get('cve_version', 'unset')

    vgls_pf = '-'.join([bpn, cve_v])
    return vgls_pf


def _find_config(d, vgls_pf, config_in):
    import shutil

    vgls_timestamp = d.getVar('VIGILES_TIMESTAMP', True )

    vgls_config_full = '_'.join([vgls_pf, vgls_timestamp])
    config_fname = '.'.join([vgls_config_full, 'config'])
    config_lname = '.'.join([vgls_pf, 'config'])

    bb.debug(1, "Translation: %s -> %s" % (config_fname, config_lname))

    vigiles_config_dir = d.getVar('VIGILES_DIR_KCONFIG', True )
    vigiles_dir = d.getVar('VIGILES_DIR', True )
    config_out = os.path.join(vigiles_config_dir, config_fname)
    config_link = os.path.join(vigiles_dir, config_lname)

    if os.path.lexists(config_link):
        os.remove(config_link)

    if not config_in:
        return

    if config_in == 'auto':
        build_dir = os.path.relpath(d.getVar('B', True ))
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
    vigiles_collect_pkg_info(d)
    vgls_pf = _get_kernel_pf(d)
    config_in = d.getVar('VIGILES_KERNEL_CONFIG', True ) or ''
    _find_config(d, vgls_pf, config_in)
}


python() {

    pn = d.getVar('PN', True )
    kernel_pn = d.getVar('VIGILES_KERNEL_PN', True ) or \
        d.getVar('PREFERRED_PROVIDER_virtual/kernel', True ) or ''

    if pn == kernel_pn:
        bb.build.addtask('do_vigiles_kconfig', 'do_savedefconfig', 'do_configure', d)
        d.appendVarFlag('do_vigiles_kconfig', 'depends', ' %s:do_configure' % pn)
}

do_vigiles_kconfig[nostamp] = "1"


def _get_uboot_pf(d):
    from oe import recipeutils as oe

    pn = d.getVar('PN', True )
    boot_pn = d.getVar('VIGILES_UBOOT_PN', True ) or \
        d.getVar('PREFERRED_PROVIDER_virtual/bootloader', True ) or ''

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

    vigiles_collect_pkg_info(d)
    if not bb.data.inherits_class('uboot-config', d):
        return

    # The following is needed to avoid a configuration conflict
    # when python3.8 is installed on the host system.
    if '_PYTHON_SYSCONFIGDATA_NAME' in os.environ:
        del os.environ['_PYTHON_SYSCONFIGDATA_NAME']

    vgls_pf = _get_uboot_pf(d)
    config_in = d.getVar('VIGILES_UBOOT_CONFIG', True ) or ''

    vgls_timestamp = d.getVar('VIGILES_TIMESTAMP', True )

    vgls_config_full = '_'.join([vgls_pf, vgls_timestamp])
    config_fname = '.'.join([vgls_config_full, 'config'])
    config_lname = '.'.join([vgls_pf, 'config'])

    bb.debug(1, "Translation: %s -> %s" % (config_fname, config_lname))

    vigiles_config_dir = d.getVar('VIGILES_DIR_KCONFIG', True )
    vigiles_dir = d.getVar('VIGILES_DIR', True )
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
        build_dir = os.path.relpath(d.getVar('B', True ))
        uboot_machine = d.getVar('UBOOT_MACHINE', True ) or None
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
            f_out.write('\n'.join(config_preamble))
            f_out.write('\n'.join(sorted(list(config_set))))
    else:
        bb.warn("config does not exist, skipping.")
        bb.warn("config path: %s" % config_in)
        return

    bb.debug(1, "Link: %s -> %s" %
             (os.path.relpath(config_link), os.path.relpath(config_out)))
    os.symlink(os.path.relpath(config_out, vigiles_dir), config_link)
}


python() {
    pn = d.getVar('PN', True )
    boot_pn = d.getVar('VIGILES_UBOOT_PN', True ) or \
        d.getVar('PREFERRED_PROVIDER_virtual/bootloader', True ) or ''

    if pn == boot_pn:
        bb.build.addtask('do_vigiles_uboot_config', 'do_rm_work', 'do_compile', d)
        d.appendVarFlag('do_vigiles_uboot_config', 'depends', ' %s:do_compile' % pn) 
}

do_vigiles_uboot_config[nostamp] = "1"


def log_vigiles_response(d, log_type="INFO", msg="", response=""):
    def log(l_type, log_buffer):
        if l_type == "DEBUG":
            return bb.debug(1, log_buffer)
        if l_type == "ERROR":
            error_level = d.getVar("VIGILES_ERROR_LEVEL", True) or ""
            error_level = error_level.upper()
            if error_level not in ["INFO", "WARNING", "ERROR", "FATAL"]:
                bb.fatal("Invalid value for VIGILES_ERROR_LEVEL. Choose from INFO, WARNING, ERROR or FATAL")
            l_type = error_level

        return error_level_map[l_type](log_buffer)
    
    error_level_map = {
        "DEBUG": bb.debug,
        "WARNING": bb.warn,
        "ERROR": bb.error,
        "FATAL": bb.fatal,
        "INFO": bb.plain
    }
    log_buffer = msg or ""
    for line in response.splitlines():
        log_type_list = [lt for lt in error_level_map if line.startswith(lt)]
        if log_type_list:
            log(log_type, log_buffer)
            log_buffer = line
            log_type = log_type_list[0]
        else:
            log_buffer += "\n" + line

    if log_buffer:
        log(log_type, log_buffer)


def _get_export_details(d, vigiles_out):
    export_format = d.getVar('VIGILES_EXPORT_FORMAT', True)
    export_args = []
    export_path = ""

    if not export_format:
        return export_args, export_path, export_format

    file_format = export_format.strip().lower()
    export_args += ['--export-format', file_format]

    if file_format.startswith("cyclonedx"):
        cyclonedx_format = d.getVar('VIGILES_CYCLONEDX_FORMAT', True)
        if cyclonedx_format:
            file_format = cyclonedx_format.strip().lower()
            export_args += ['--cyclonedx-format', cyclonedx_format.strip().lower()]

        cyclonedx_version = d.getVar('VIGILES_CYCLONEDX_VERSION', True)
        if cyclonedx_version:
            export_args += ['--cyclonedx-version', cyclonedx_version.strip().lower()]
    elif file_format == "pdfsummary":
        file_format = file_format[:3]

    export_path = vigiles_out.replace(".txt", "") + "." + file_format
    export_args += ['--export-path', export_path]

    return export_args, export_path, file_format


python do_vigiles_check() {
    v_dir = d.getVar('VIGILES_DIR',True)
    m_max_len = int(d.getVar('VIGILES_MANIFEST_NAME_MAX_LENGTH',True))
    v_tstamp = d.getVar('VIGILES_TIMESTAMP',True)

    # truncate manifest_name to acceptable configured length
    _name = d.getVar('VIGILES_MANIFEST_NAME',True)[:m_max_len]
    _imgdirname = d.getVar('VIGILES_MANIFEST_NAME',True)[:m_max_len - 1]

    v_imgdir = _get_imgdir(v_dir, _imgdirname)

    vigiles_in = _get_vlink(v_dir, _name, m_max_len, d.getVar('VIGILES_MANIFEST_SUFFIX',True))
    vigiles_out = _get_vout_path(v_imgdir, _name, m_max_len, v_tstamp, d.getVar('VIGILES_REPORT_SUFFIX',True))
    vigiles_link = _get_vlink(v_dir, _name, m_max_len, d.getVar('VIGILES_REPORT_SUFFIX',True))

    # The following is needed to avoid a configuration conflict
    # when python3.8 is installed on the host system.
    if '_PYTHON_SYSCONFIGDATA_NAME' in os.environ:
        del os.environ['_PYTHON_SYSCONFIGDATA_NAME']

    vigiles_kconfig = os.path.join(d.getVar('VIGILES_DIR', True ),
                                   '.'.join([_get_kernel_pf(d), 'config']))
    vigiles_uconfig = os.path.join(d.getVar('VIGILES_DIR', True ),
                                   '.'.join([_get_uboot_pf(d), 'config']))

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

        ecosystems = d.getVar('VIGILES_ECOSYSTEMS', True)
        if ecosystems:
            bb.debug(1, "Using Ecosystems: %s" % ecosystems)
            args = args + ['-e', ecosystems]

        subscribe = d.getVar('VIGILES_NOTIFICATION_FREQUENCY', True)
        if subscribe:
            bb.debug(1, "Setting SBOM report notification frequency to: %s" % subscribe)
            args = args + ['-s', subscribe]

        sbom_token_path = d.getVar('VIGILES_DOWNLOAD_SBOM_TOKEN_PATH', True)
        if sbom_token_path:
            bb.debug(1, "SBOM token will be saved to : %s" % sbom_token_path)
            args = args + ['--sbom-token-path', sbom_token_path]

        vigiles_env = os.environ.copy()

        # This does the same as bb.utils.export_proxies(), but that isn't
        # exposed (cleanly) until krogoth..
        proxy_vars = ['http_proxy', 'HTTP_PROXY', 'https_proxy', 'HTTPS_PROXY',
                    'ftp_proxy', 'FTP_PROXY', 'no_proxy', 'NO_PROXY',
                    'GIT_PROXY_COMMAND']
        for v in proxy_vars:
            if v not in vigiles_env.keys():
                v_proxy = d.getVar(v, True)
                if v_proxy is not None:
                    vigiles_env[v] = v_proxy

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
        vigiles_env['VIGILES_KEY_FILE'] = _orig_env.getVar('VIGILES_KEY_FILE', True ) or ''
        vigiles_env['VIGILES_DASHBOARD_CONFIG'] = _orig_env.getVar('VIGILES_DASHBOARD_CONFIG', True) or ''
        vigiles_env['VIGILES_SUBFOLDER_NAME'] = _orig_env.getVar('VIGILES_SUBFOLDER_NAME') or ''

        conf_key = d.getVar('VIGILES_KEY_FILE', True )
        if conf_key:
            args = args + ['-K', conf_key]
        conf_dashboard = d.getVar('VIGILES_DASHBOARD_CONFIG', True )
        if conf_dashboard:
            args = args + ['-C', conf_dashboard]
        conf_subfolder_name = d.getVar('VIGILES_SUBFOLDER_NAME')
        if conf_subfolder_name:
            args = args + ['-F', conf_subfolder_name]

        vigiles_env['LINUXLINK_SERVER'] = _orig_env.getVar('LINUXLINK_SERVER', True ) or ''

        _upload_only = bb.utils.to_boolean(d.getVar('VIGILES_UPLOAD_ONLY', True ), False)
        if _upload_only:
            args = args + ['-U']

        layerdir = d.getVar('VIGILES_LAYERDIR', True )
        path = os.path.join(layerdir, "scripts", cmd)

        args = [path] + args

        bb.debug(1, "Vigiles Command Line: %s" % (" ").join(args))
        return bb.process.run(args, env=vigiles_env)

    _check_disabled = bb.utils.to_boolean(d.getVar('VIGILES_DISABLE_CHECK', True), False)
    if _check_disabled:
        bb.plain("Vigiles: Skipping Check for %s" % d.getVar('VIGILES_MANIFEST_NAME', True)[:int(d.getVar('VIGILES_MANIFEST_NAME_MAX_LENGTH', True))])
        return

    bb.utils.mkdirhier(os.path.dirname(vigiles_out))

    vigiles_export_args, vigiles_export_report_path, file_format = _get_export_details(d, vigiles_out)
    try:
        check_out, _ = run_checkcves(d, "checkcves.py", 
            [ '-m', vigiles_in, '-o', vigiles_out ] + vigiles_export_args)

        log_vigiles_response(d, response=check_out)

        if os.path.lexists(vigiles_link):
            os.remove(vigiles_link)
        if os.path.exists(vigiles_out):
            os.symlink(os.path.relpath(vigiles_out, os.path.dirname(vigiles_link)), vigiles_link)
        if os.path.exists(vigiles_export_report_path):
            export_vlink = _get_vlink(v_dir, _name, m_max_len, d.getVar('VIGILES_REPORT_SUFFIX', True).replace('.txt', '')) + '.' + file_format
            if os.path.lexists(export_vlink):
                os.remove(export_vlink)
            os.symlink(os.path.relpath(vigiles_export_report_path, os.path.dirname(export_vlink)), export_vlink)

    except bb.process.NotFoundError as err:
        log_vigiles_response(d, "ERROR", "Vigiles: checkcves.py could not be found:\n", str(err))
    except Exception as err:
        log_vigiles_response(d, "ERROR", "Vigiles: run_checkcves failed:\n", str(err))
}


addtask do_vigiles_check after do_vigiles_image
do_vigiles_check[nostamp] = "1"
do_vigiles_check[vardepsexclude] = "BB_ORIGENV"

python() {
    if bb.data.inherits_class('kernel', d):
        # Forward-compatibility with later renditions of kernel.bbclass
        d.setVar('CVE_PRODUCT', 'linux_kernel')
    elif bb.data.inherits_class('image', d):
        pn = d.getVar('PN', True )
        bb.build.addtask('do_vigiles_check', 'do_build', 'do_vigiles_image', d)
        d.appendVarFlag('do_vigiles_check', 'depends', ' %s:do_vigiles_image' % pn)
}


def _validate_sbom_download_args(d):
    sbom_type = (d.getVar("VIGILES_DOWNLOAD_SBOM_SPEC", True) or "").lower()
    sbom_format = (d.getVar("VIGILES_DOWNLOAD_SBOM_FORMAT", True) or "").lower()
    sbom_version = (d.getVar("VIGILES_DOWNLOAD_SBOM_VERSION", True) or "").strip()

    valid_types = (d.getVar("VIGILES_VALID_SBOM_SPEC", True) or "").split()
    valid_spdx_formats = (d.getVar("VIGILES_VALID_SPDX_FORMATS", True) or "").split()
    valid_cyclonedx_formats = (d.getVar("VIGILES_VALID_CYCLONEDX_FORMATS", True) or "").split()
    valid_spdx_versions = (d.getVar("VIGILES_VALID_SPDX_VERSIONS", True) or "").split()
    valid_cyclonedx_versions = (d.getVar("VIGILES_VALID_CYCLONEDX_VERSIONS", True) or "").split()

    if sbom_type not in valid_types:
        raise ValueError(
            "Invalid sbom specification '%s' selected. Choose from %s" % (
                sbom_type,
                valid_types
            ))

    if sbom_type == "cyclonedx":
        if sbom_format not in valid_cyclonedx_formats:
            raise ValueError(
                "Invalid file format '%s' for %s. Choose from %s" % (
                    sbom_format,
                    sbom_type, 
                    valid_cyclonedx_formats
                ))
        if sbom_version not in valid_cyclonedx_versions:
            raise ValueError(
                "Invalid sbom version '%s' for %s. Choose from %s" % (
                    sbom_version,
                    sbom_type, 
                    valid_cyclonedx_versions
                ))
    else:
        if sbom_format not in valid_spdx_formats:
            raise ValueError(
                "sbom_format file format '%s' for %s. Choose from %s" % (
                    sbom_format,
                    sbom_type, 
                    valid_spdx_formats
                ))
        if sbom_version not in valid_spdx_versions:
            raise ValueError(
                "Invalid sbom version '%s' for %s. Choose from %s" % (
                    sbom_version,
                    sbom_type, 
                    valid_spdx_versions
                ))


python do_vigiles_download_sbom() {
    import os
    import datetime

    _orig_env = d.getVar('BB_ORIGENV', False)
    vigiles_env = os.environ.copy()
    vigiles_env['VIGILES_KEY_FILE'] = _orig_env.getVar('VIGILES_KEY_FILE', True ) or ''
    vigiles_env['LINUXLINK_SERVER'] = _orig_env.getVar('LINUXLINK_SERVER', True ) or ''

    token_path = d.getVar("VIGILES_DOWNLOAD_SBOM_TOKEN_PATH", True)
    if not os.path.exists(token_path):
        log_vigiles_response(d, "ERROR", "Vigiles: SBOM token file not found: %s" % token_path)
        return

    try:
        with open(token_path, "r") as f:
            token = f.read().strip()
    except IOError as e:
        log_vigiles_response(d, "ERROR", "Vigiles: Failed to read token file %s: %s" % (token_path, str(e)))
        return

    if not token:
        log_vigiles_response(d, "ERROR", "Vigiles: SBOM token file is empty: %s" % token_path)
        return

    keyfile = d.getVar("VIGILES_KEY_FILE", True)
    if not os.path.exists(keyfile):
        log_vigiles_response(d, "ERROR", "Vigiles: API key not found")
        return

    img_dir = d.getVar("VIGILES_DOWNLOAD_SBOM_DEPLOY_DIR", True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")

    sbom_type = (d.getVar("VIGILES_DOWNLOAD_SBOM_SPEC", True) or "").lower()
    sbom_format = (d.getVar("VIGILES_DOWNLOAD_SBOM_FORMAT", True) or "").lower()
    sbom_version = (d.getVar("VIGILES_DOWNLOAD_SBOM_VERSION", True) or "").strip()

    if sbom_type and not sbom_version:
        if sbom_type == "cyclonedx":
            d.setVar("VIGILES_DOWNLOAD_SBOM_VERSION", d.getVar("VIGILES_DEFAULT_CYCLONEDX_VERSION", True))
        else:
            d.setVar("VIGILES_DOWNLOAD_SBOM_VERSION", d.getVar("VIGILES_DEFAULT_SPDX_VERSION", True))

        sbom_version = (d.getVar("VIGILES_DOWNLOAD_SBOM_VERSION", True) or "").strip()

    try:
        _validate_sbom_download_args(d)
    except ValueError as err:
        log_vigiles_response(d, "ERROR", "Vigiles: %s" % str(err))
        return

    sbom_name = "%s-%s" % (d.getVar("VIGILES_MANIFEST_NAME", True), d.getVar("MACHINE", True))
    sbom_suffix = "-%s-sbom.%s" % (sbom_type, ("spdx" if sbom_format == "tag" else sbom_format))
    sbom_max_len = int(d.getVar("VIGILES_MANIFEST_NAME_MAX_LENGTH", True))

    output_path = _get_vout_path(img_dir, sbom_name, sbom_max_len, timestamp, sbom_suffix)
    link_path = _get_vlink(img_dir, sbom_name, sbom_max_len, sbom_suffix)

    layerdir = d.getVar('VIGILES_LAYERDIR', True)
    path = os.path.join(layerdir, "scripts", "download_sbom.py")

    cmd = [
        "python3",
        path,
        "-K", keyfile,
        "-t", token,
        "-s", sbom_type,
        "-f", sbom_format,
        "-v", sbom_version,
        "-o", output_path
    ]

    bb.plain("Vigiles: Downloading %s-%s SBOM" % (sbom_type, sbom_version))

    try:
        stdout, stderr = bb.process.run(cmd, env=vigiles_env)
        log_vigiles_response(d, response=stdout)
    except bb.process.NotFoundError as err:
        log_vigiles_response(d, "ERROR", "Vigiles: download_sbom.py could not be found:\n", str(err))
        return
    except Exception as err:
        log_vigiles_response(d, "ERROR", "Vigiles: SBOM download failed:\n", str(err))
        return

    if os.path.exists(output_path):
        if os.path.lexists(link_path):
            os.remove(link_path)

        os.symlink(os.path.relpath(output_path, os.path.dirname(link_path)), link_path)
        bb.debug(1, "Vigiles: Created symlink: %s -> %s" % (link_path, output_path))
        bb.plain("Vigiles: Successfully downloaded SBOM to %s" % link_path)
    else:
        log_vigiles_response(d, "ERROR", "Vigiles: Failed to download SBOM")
        return
}

do_vigiles_download_sbom[network] = "1"
do_vigiles_download_sbom[vardepsexclude] = "BB_ORIGENV"

python () {
    if bb.utils.to_boolean(d.getVar("VIGILES_ENABLE_DOWNLOAD_SBOM", True)):
        bb.build.addtask("do_vigiles_download_sbom", "do_image_complete", "do_vigiles_check", d)
}
