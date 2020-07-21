###########################################################
#
# classes/tsmeta.bbclass - Metadata Collection
#
# Copyright (C) 2019 Timesys Corporation
#
#
# This source is released under the MIT License.
#
###########################################################

tsmeta_dirname = "tsmeta"
tsmeta_dir = "${TMPDIR}/${tsmeta_dirname}"

tsmeta_cve_dir = "${tsmeta_dir}/cve"
tsmeta_image_dir = "${tsmeta_dir}/image"
tsmeta_pkg_dir = "${tsmeta_dir}/pkg"
tsmeta_pn_dir = "${tsmeta_dir}/pn"
tsmeta_recipe_dir = "${tsmeta_dir}/recipe"
tsmeta_src_dir = "${tsmeta_dir}/src"

tsmeta_distro_dir = "${tsmeta_dir}/distro"
tsmeta_features_dir = "${tsmeta_dir}/features"
tsmeta_image_dir = "${tsmeta_dir}/image"
tsmeta_layers_dir = "${tsmeta_dir}/layers"
tsmeta_machine_dir = "${tsmeta_dir}/machine"
tsmeta_preferred_dir = "${tsmeta_dir}/preferred"

tsmeta_lvars_pkg = " \
    ALTERNATIVE     \
    RCONFLICTS      \
    RDEPENDS        \
    RPROVIDES       \
    RRECOMMENDS     \
    RREPLACES       \
    RSUGGESTS       \
"

tsmeta_vars_pkg = " \
    SECTION         \
    PACKAGE_ARCH    \
    PKG             \
"

tsmeta_vars_pn = "  \
    BP              \
    BPN             \
    EXTENDPKGV      \
    PF              \
    PKGR            \
    PKGV            \
    PN              \
    PV              \
"

tsmeta_lvars_pn = " \
    DEPENDS \
    IMAGE_INSTALL \
    PACKAGES \
    PACKAGES_DYNAMIC\
    PROVIDES \
"

tsmeta_lvars_src = "\
    FILESEXTRAPATHS         \
    SRC_URI                 \
"

tsmeta_vars_src = "\
    BRANCH                  \
    CVE_PRODUCT             \
    CVE_VERSION             \
    FILE                    \
    LICENSE                 \
    SRCBRANCH               \
    SRCREV                  \
"


def tsmeta_get_type_dir(d, tsm_type):
    key = "tsmeta_" + tsm_type.lower() + "_dir"
    return d.getVar(key)

def tsmeta_get_type_path(d, tsm_type, var_name):
    return os.path.join(
        tsmeta_get_type_dir(d, tsm_type),
        var_name + ".json")

def tsmeta_get_type_glob(d, tsm_type):
    import glob
    ls_dict = dict()
    tsm_dir = tsmeta_get_type_dir(d, tsm_type)

    varfiles = glob.glob(os.path.join(tsm_dir, "*.json"))
    for vf in varfiles:
        basename = os.path.basename(vf)
        dict_name, ext = os.path.splitext(basename)
        ls_dict[dict_name] = vf
    return ls_dict

def tsmeta_read_json(d, trj_path):
    import json
    dict_in = dict()
    if os.path.exists(trj_path):
        with open(trj_path) as f:
            dict_in = json.load(f)
    return dict_in

def tsmeta_write_json(d, dict_out, twj_path):
    import json

    s = json.dumps(dict_out, indent=8, sort_keys=False)
    if twj_path:
        with open(twj_path, "w") as f:
            f.write(s)


def tsmeta_write_dictname(d, tsm_type, twd_name, twd_dict):
    import oe.packagedata
    import json

    tsm_dir = tsmeta_get_type_dir(d, tsm_type)
    bb.utils.mkdirhier(tsm_dir)

    outfile = tsmeta_get_type_path(d, tsm_type, twd_name)
    tsmeta_write_json(d, twd_dict, outfile)

def tsmeta_write_dict(d, tsm_type, twd_dict):
    twd_name = d.getVar('PN')
    tsmeta_write_dictname(d, tsm_type, twd_name, twd_dict)

def tsmeta_write_dictdir(d, tsm_type, twd_dict):
    for twd_name in twd_dict.keys():
        tsmeta_write_dictname(d, tsm_type, twd_name, twd_dict[twd_name])


TSMETA_DEBUG ?= "0"
tsmeta_debug_dir = "${tsmeta_dir}/debug"

def tsmeta_debug(d, dict_tag, dict_out):
    if bb.utils.to_boolean(d.getVar('TSMETA_DEBUG'), True):
        dict_name = ("%s-%s" % (d.getVar('PN'), dict_tag))
        tsmeta_write_dictname(d, 'debug', dict_name, dict_out)


def tsmeta_read_dictname(d, tsm_type, trd_name):
    infile = tsmeta_get_type_path(d, tsm_type, trd_name)
    return tsmeta_read_json(d, infile)

def tsmeta_read_dict(d, trd_type):
    trd_name = d.getVar('PN')
    return tsmeta_read_dictname(d, trd_type, trd_name)

def tsmeta_read_dictdir(d, tsm_type):
    trd_dict = dict()

    if not os.path.exists(tsmeta_get_type_dir(d,tsm_type)):
        bb.debug(2,"dict dir %s not found, generating.." % tsm_type)
        bb.build.exec_func("tsmeta_get_" + tsm_type, d)

    for dict_name, dict_path in sorted(tsmeta_get_type_glob(d, tsm_type).items()):
        trd_dict[dict_name] = tsmeta_read_json(d, dict_path)
    return trd_dict

def tsmeta_read_dictdir_files(d, trdf_type, trdf_list):
    indict = tsmeta_read_dictdir(d, trdf_type)
    dict_out = { key: indict.get(key, "") for key in trdf_list if key in indict.keys() }
    return dict_out


def tsmeta_read_dictname_single(d, trdv_type, trdv_name, trdv_var):
    indict = tsmeta_read_dictname(d, trdv_type, trdv_name)
    value = indict.get(trdv_var, "")
    return value

def tsmeta_read_dictname_vars(d, trdv_type, trdv_name, trdv_list):
    indict = tsmeta_read_dictname(d, trdv_type, trdv_name)
    dict_out = { key: indict.get(key, "") for key in trdv_list }
    return dict_out 


def tsmeta_read_dict_vars(d, trdv_type, trdv_list):
    pn = d.getVar('PN')
    return tsmeta_read_dictname_vars(d, trdv_type, pn, trdv_list)


def tsmeta_get_dict(d, tsm_type, dict_in):
    dict_out = dict()

    key =  tsm_type.upper()
    name = dict_in.get("name", d.getVar(key))
    varlist = dict_in.get("vars", [])

    if name:
        if len(varlist):
            dict_out = tsmeta_read_dictname_vars(d, tsm_type, name, varlist)
        else:
            dict_out = tsmeta_read_dictdir(d, tsm_type)
    return dict_out


def tsmeta_get_yocto_vars(d, varlist):
    dict_out = dict()
    for key in (d.getVar(varlist) or "").split():
        value = (d.getVar(key) or "")
        if value:
            dict_out[key.lower()] = oe.utils.squashspaces(value)
    return dict_out

def read_var_list(d, tsm_type, dest_dict):
    varlist = "tsmeta_vars_" + tsm_type
    dest_dict.update(tsmeta_get_yocto_vars(d, varlist))

def read_lvar_list(d, tsm_type, dest_dict):
    varlist = "tsmeta_lvars_" + tsm_type

    dest_dict.update( 
            { 
                key.lower(): list((d.getVar(key) or "").split()) 
                    for key in (d.getVar(varlist) or "").split() 
            }
        )


def tsmeta_get_vars(d, tgv_type):
    dest_dict = dict()
    read_var_list(d, tgv_type, dest_dict)
    read_lvar_list(d, tgv_type, dest_dict)
    tsmeta_write_dict(d, tgv_type, dest_dict)


def tsmeta_get_pn(d):
    tsmeta_get_vars(d, "pn")


def _get_cve_product(d):
    cve_p = d.getVar('CVE_PRODUCT')
    if bb.data.inherits_class('uboot-config', d):
        cve_p = 'u-boot'
    if not cve_p:
        cve_p = d.getVar('PN')
    return cve_p


def _detect_kernel_version(d):
    import os
    import sys

    _version = None
    _major = _minor = _revision = _extra = None
    source_dir = os.path.relpath(d.getVar('S'))
    makefile_path = os.path.join(source_dir, 'Makefile')
    if not os.path.exists(makefile_path):
        return None

    try:
        with open(makefile_path) as f_in:
            for line in f_in:
                _split = line.split('=')
                if len(_split) != 2:
                    continue
                key, val = [x.strip() for x in _split]
                if key == 'VERSION':
                    _major = val
                elif key == 'PATCHLEVEL':
                    _minor = val
                elif key == 'SUBLEVEL':
                    _revision = val
                elif key == 'EXTRAVERSION':
                    _extra = val
            f_in.close()
    except Exception as e:
        bb.warn("Could not read/parse kernel Makefile (%s): %s." %
                   (makefile_path, e))
    finally:
        if _major and _minor and _revision:
            _version = '.'.join([_major, _minor, _revision])
            if _extra:
                _version = _version + _extra
    return _version


def _get_cve_version(d):
    import oe.recipeutils as oe

    cve_v = d.getVar('CVE_VERSION')
    if bb.data.inherits_class('kernel', d):
        cve_v = _detect_kernel_version(d)

    if not cve_v:
        pv = d.getVar('PV')
        uri_type = 'git' if ('git' in pv or 'AUTOINC' in pv) else ''
        (bpv, pfx, sfx) = oe.get_recipe_pv_without_srcpv(pv, uri_type)
        cve_v = bpv
    return cve_v


def tsmeta_get_src(d):
    import oe.recipeutils as oe

    tsm_type = "src"
    src_dict = dict()

    read_var_list(d, tsm_type, src_dict)
    read_lvar_list(d, tsm_type, src_dict)

    src_dict["cve_product"] = _get_cve_product(d)
    src_dict["cve_version"] = _get_cve_version(d)

    uri_dict = dict()

    def uri_add(u_type, u_path):
        if not u_type in uri_dict.keys():
            uri_dict[u_type] = list()
        uri_dict[u_type].append(u_path)

    src_patches_raw = oe.get_recipe_patches(d)
    src_patches = { os.path.basename(p) : p for p in src_patches_raw }

    uri_dict["patches"] = src_patches

    for uri_desc in src_dict["src_uri"]:
        proto, remote, path, three, four, perms = bb.fetch.decodeurl(uri_desc)

        base = os.path.basename(path)
        if base in src_patches.keys():
            continue

        if remote:
            uri_type = proto
            uri_path = uri_desc
        else:
            uri_type = "file"
            uri_path = path

        uri_add(uri_type, uri_path)

    src_dict["sources"] = uri_dict

    if src_dict["srcrev"] == "INVALID":
        src_dict.pop("srcrev")

    recipe_path = src_dict.pop('file')
    recipe_layer = bb.utils.get_file_layer(recipe_path, d) or '.'
    layer_path = os.path.join(
        d.getVar('BSPDIR') or '.',
        tsmeta_read_dictname_single(d, 'layers', recipe_layer, 'path')
    )
    src_dict['layer'] = recipe_layer
    src_dict['recipe'] = os.path.relpath(recipe_path, layer_path)
    tsmeta_write_dict(d, tsm_type, src_dict)

def tsmeta_get_pkg(d):
    import oe.packagedata


    def get_var_list(varlist, pkg, d_sub):
        vdict = dict()
        for base_key in d.getVar(varlist).split():
            pkg_key = base_key + "_" + pkg
            dest_key = base_key.lower()

            if pkg_key in d_sub.keys():
                actual_key = pkg_key 
            elif base_key in d_sub.keys():
                actual_key = base_key
            else:
                continue

            value = d_sub[actual_key]
            if value != "" :
                vdict[dest_key] = value
        return vdict

    def read_extlvar_list(tsm_type, pkg, d_sub, dest_dict):
        varlist = "tsmeta_lvars_" + tsm_type
        vdict = get_var_list(varlist, pkg, d_sub)

        for key, value in vdict.items():
            dest_list = []
            for item in value.split():
                if item.startswith('(') or item.endswith(')') and len(dest_list):
                    dest_list[-1] += (" " + item)
                else:
                    dest_list.append(item)
            dest_dict[key] = list(dest_list)

    def read_extvar_list(tsm_type, pkg, d_sub, dest_dict):
        varlist = "tsmeta_vars_" + tsm_type
        dest_dict.update(get_var_list(varlist, pkg, d_sub))

    pd_dir = d.getVar('PKGDATA_DIR')

    pn_dict = dict()
    pn_name = d.getVar('PN')
    f_pn = os.path.join(pd_dir, pn_name)

    if not os.path.exists(f_pn):
        return

    with open(f_pn, 'r') as infile:
        for line in infile:
            pn_dict = { sp: dict() for sp in line.split()[1:] }
    for sp in pn_dict.keys():

        sp_file = os.path.join(pd_dir, "runtime", sp)
        if not os.path.exists(sp_file):
            continue

        with open (sp_file, 'r') as infile:
            for line in infile:
                key, value = line.split(":", 1)
                pn_dict[sp][key] = oe.utils.squashspaces(value)

    dict_out = dict()
    for pkg in pn_dict.keys():
        dict_out[pkg] = dict()
        read_extvar_list("pkg", pkg, pn_dict[pkg], dict_out[pkg])
        read_extlvar_list("pkg", pkg, pn_dict[pkg], dict_out[pkg])

    tsmeta_write_dict(d, "pkg", dict_out)


python do_tsmeta_pkgvars() {
    # The following is needed to avoid a configuration conflict
    # when python3.8 is installed on the host system.
    if '_PYTHON_SYSCONFIGDATA_NAME' in os.environ:
        del os.environ['_PYTHON_SYSCONFIGDATA_NAME']
    tsmeta_get_pn(d)
    tsmeta_get_src(d)
    tsmeta_get_pkg(d)
}


def tsmeta_collect_preferred(d):
    import json
    pref_filter = dict(
        provider = "PREFERRED_PROVIDER_",
        version = "PREFERRED_VERSION_",
        runtime = "VIRTUAL-RUNTIME_",
    )

    d_keys = sorted(d.keys())
    p_dict = {
        p_name: { 
                key.replace(p_type, "") : d.getVar(key)
                    for key in d_keys if key.startswith(p_type) 
                }
                for p_name, p_type in pref_filter.items() 
            }

    # bb.plain("%s" % json.dumps(p_dict, indent = 4, sort_keys = True))
    return p_dict

python tsmeta_get_preferred() {
    tsmeta_write_dictdir(d, "preferred", 
        tsmeta_collect_preferred(d))
}


python tsmeta_get_machine() {
    tempdict = { key.replace("MACHINE_", "").lower(): \
        oe.utils.squashspaces(str(d.getVar(key))) \
        for key in d.keys() if key.startswith("MACHINE_") and \
            not key.startswith("MACHINE_FEATURES") }

    mdict = dict()
    for key in tempdict.keys():
        if key.startswith("features")   or \
            key.startswith("essential") or \
            key.startswith("extra")     or \
            key.endswith("filter")      or \
            key.endswith("codecs")      or \
            key.endswith("firmware"):
            mdict[key] = (tempdict[key] or "").split()
        else:
            mdict[key] = tempdict[key]

    mdict['title'] = d.getVar('MACHINE')
    tsmeta_write_dictname(d, "machine", mdict["title"], mdict)
}

python tsmeta_get_distro() {
    tempdict = { key.replace("DISTRO_", "").lower(): \
        oe.utils.squashspaces(str(d.getVar(key))) \
        for key in d.keys() if key.startswith("DISTRO_") and \
            not key.startswith("DISTRO_FEATURES") }

    ddict = dict()
    for key in tempdict.keys():
        if key.startswith("features")   or \
            key.startswith("essential") or \
            key.startswith("extra")     or \
            key.endswith("filter")      or \
            key.endswith("codecs")      or \
            key.endswith("firmware"):
            ddict[key] = (tempdict[key] or "").split()
        else:
            ddict[key] = tempdict[key]

    ddict['title'] = d.getVar('DISTRO')
    tsmeta_write_dictname(d, "distro", ddict["title"], ddict)
}

python tsmeta_get_image() {

    tempdict = { key.replace("IMAGE_", "").lower(): d.getVar(key) \
        for key in d.keys() if key.startswith("IMAGE_") and \
        not (key.startswith("IMAGE_CMD_") or key.startswith("IMAGE_FEATURES")) }

    extra_keys = [
        'EXTRA_IMAGE_INSTALL',
        'PACKAGE_INSTALL',
        'RDEPENDS',
        'RRECOMMENDS'
    ]
    extra_dict = { key.lower(): (d.getVar(key) or "") for key in extra_keys }

    tempdict.update( { key: oe.utils.squashspaces(value).split() for key, value in extra_dict.items()
            if len(value) and isinstance(value, str) } )

    imgdict = dict()

    for key in tempdict.keys():
        if  key.startswith("features")  or \
            key.startswith("fstypes")   or \
            key.startswith("install")   or \
            key.startswith("linguas")   or \
            key.endswith("files")       or \
            key.endswith("command")     or \
            key.endswith("classes")     or \
            key.endswith("types"):
            imgdict[key] = (tempdict[key] or "").split()
        else:
            imgdict[key] = tempdict[key]

    tsmeta_write_dictname(d, "image", imgdict["basename"], imgdict)
}

python tsmeta_get_features() {
    fdict = dict(
        distro = { key.replace("DISTRO_FEATURES_", "").lower(): \
                    oe.utils.squashspaces(str(d.getVar(key))).split()  \
                    for key in d.keys() if key.startswith("DISTRO_FEATURES_")  },
        machine = { key.replace("MACHINE_FEATURES_", "").lower(): \
                    oe.utils.squashspaces(str(d.getVar(key))).split()  \
                    for key in d.keys() if key.startswith("MACHINE_FEATURES_")  },
        image = { key.replace("IMAGE_FEATURES_", "").lower(): \
                    oe.utils.squashspaces(str(d.getVar(key))).split()  \
                    for key in d.keys() if key.startswith("IMAGE_FEATURES_")  },
        packages = { key.replace("FEATURE_PACKAGES_", "").lower(): \
                    oe.utils.squashspaces(str(d.getVar(key))).split()  \
                    for key in d.keys() if key.startswith("FEATURE_PACKAGES_")  },
    )

    fdict['distro']['base']     = d.getVar('DISTRO_FEATURES').split()
    fdict['machine']['base']    = d.getVar('MACHINE_FEATURES').split()
    fdict['image']['base']      = d.getVar('IMAGE_FEATURES').split()

    tsmeta_write_dictdir(d, "features", fdict)
}



def tsmeta_git_branch_info(d, path):
    import bb.process

    def _run_git(_git_cmd, _arg_list = []):
        _args = ' '.join(_arg_list)
        _cmd = ' '.join([_git_cmd, _args])
        # bb.plain('Command: %s' % _cmd)
        try:
            git_out, _ = bb.process.run(_cmd, cwd=path)
            # bb.plain('git output: %s' % git_out)
        except Exception as ex:
            bb.debug(1, 'git Failed: %s -- %s' % (_cmd, ex))
            git_out = ""
            raise
        return oe.utils.squashspaces(git_out)

    def _repo_config():
        _git_config_cmd = ' '.join([
            'git',
            'config'
        ])
        _local_list_args = [
            '-l',
            '--local'
        ]
        _local_config = _run_git(_git_config_cmd, _local_list_args)
        # cfg_dict = {}
        # for _entry in _local_config.split():
        #     _name, _value = _entry.split('=', 2)
        #     cfg_dict[_name] = _value
        # bb.plain("git Config for %s: %s" % (path, cfg_dict))
        return _local_config

    def _head_revision():
        _git_log_cmd = ' '.join([
            'git',
            'log',
        ])

        _log_args = [
            '--max-count=1',
            '--format=\'%H\''
        ]
        _rev = _run_git(_git_log_cmd, _log_args)
        # bb.plain('Path: %s, Revision: %s' %(path, _rev))
        return _rev

    def _branch_name(_rev):
        _git_branch_cmd = ' '.join([
            'git',
            'branch'
        ])

        _points_at = '='.join([
            '--points-at',
            'HEAD'
        ])
        _color = '='.join([
            '--color',
            'never',
        ])
        _pipeline = ' '.join([
            '|',
            'cut',
            '-s',
            '-d',
            '\'*\'',
            '-f',
            '2'
        ])
        _name = _run_git(_git_branch_cmd, [_points_at, _color, _pipeline])
        if any([
            _str in _name for _str in [ '(no branch)', '(HEAD detached' ]
        ]):
            _name = "detached"
        # bb.plain("Path: %s, Branch Name: %s" %(path, _name))
        return _name

    def _get_remote_list():
        _git_remote_cmd = ' '.join([
            'git',
            'remote'
        ])
        _remotes = _run_git(_git_remote_cmd)
        return _remotes.split()

    def _upstream_branch(_rev):
        _git_for_each_ref_cmd = ' '.join([
            'git',
            'for-each-ref',
            '--sort=-committerdate',
            '--count=1'
        ])
        _points_at = '='.join([ '--points-at', _rev ])
        _contains = '='.join([ '--contains', _rev ])
        _refname_format = '='.join([ '--format', '\'%(refname:short)\'' ])
        _upstream_format = '='.join([ '--format', '\'%(upstream:short)\'' ])

        _remotes = _get_remote_list()
        _remotes_list = [ '/'.join(['refs/remotes', _r]) for _r in _remotes ]
        _remotes_arg = ' '.join(_remotes_list)

        def _upstream_simple():
            return _run_git(_git_for_each_ref_cmd, [_points_at, _upstream_format])

        def _upstream_tracking():
            return _run_git(_git_for_each_ref_cmd, [_points_at, _refname_format, _remotes_arg])

        def _upstream_fallback():
            return _run_git(_git_for_each_ref_cmd, [_contains, _refname_format, _remotes_arg])

        _simple = _upstream_simple()
        _tracking = _upstream_tracking()
        _fallback = _upstream_fallback()

        if _simple:
            _ret = _simple
        elif _tracking:
            _ret = _tracking
        elif _fallback:
            _ret = _fallback
        else:
            _ret = "unknown/unknown"
        return _ret.split('/', 1)

    def _upstream_url(_remote):
        _git_cmd_ls_remote = ' '.join([
            'git',
            'ls-remote'
        ])
        _remote_args = [
            '--get-url',
            _remote
        ]
        _remote_url = _run_git(_git_cmd_ls_remote, _remote_args)
        return _remote_url

    r_config = _repo_config()
    if not r_config:
        return {}

    b_rev = _head_revision()
    b_name = _branch_name(b_rev)
    b_info = _upstream_branch(b_rev)
    b_remote = b_info[0]
    b_upstream = b_info[-1]
    b_url = _upstream_url(b_remote)

    branch_dict = dict(
        branch = b_name,
        head = b_rev,
        upstream = b_upstream,
        remote = b_remote,
        url = b_url
    )

    return branch_dict


def tsmeta_collect_layers(d):
    layer_dict = dict()
    bspdir = d.getVar('BSPDIR')

    def _layer_info(lpath):
        ldict = tsmeta_git_branch_info(d, lpath)
        ldict['path'] = os.path.relpath(lpath, bspdir)
        return ldict

    for lname in d.getVar('BBFILE_COLLECTIONS').split():
        pattern = d.getVar('_'.join(['BBFILE_PATTERN', lname]))
        full_path = os.path.normpath(pattern.split('^')[-1])
        try:
            layer_dict[lname] = _layer_info(full_path)
        except Exception as e:
            bb.warn("Vigiles: Could not get repo info for %s: %s" % (lname, e))

    if 'timesys' not in layer_dict:
        meta_timesys_dir = d.getVar('VIGILES_LAYERDIR')
        layer_dict['timesys'] = _layer_info(meta_timesys_dir)

    return layer_dict

python tsmeta_get_layers() {
    tsmeta_write_dictdir(d, "layers",
        tsmeta_collect_layers(d))
}


python do_tsmeta_build() {
    dict_names = [ 'features', 'image', 'preferred' ]

    for d_name in dict_names:
        bb.build.exec_func("tsmeta_get_" + d_name, d)
}

addtask do_tsmeta_build
do_tsmeta_build[nostamp] = "1"


def tsmeta_pn_list(d):
    image_dict = {
        "machine" : {
            "name" : d.getVar('MACHINE'),
        },
        "distro" : {
            "name" : d.getVar('DISTRO'),
        },
        "image" : {
            "name" : d.getVar('IMAGE_BASENAME'),
        }
    }
    tsmeta_debug(d, 'image_dict', image_dict)

    def get_pkg_lookup():
        pkg_dict_base = tsmeta_read_dictdir(d, "pkg")
        pkg_lookup = dict(
            virtual = tsmeta_read_dictdir(d, "preferred"),
            rproviders = dict(),
            aliases = dict(),
        )

        for (pn, pn_dict) in pkg_dict_base.items():
            for (pkg, pkg_dict) in pn_dict.items():
                pkg_name = pkg_dict.get("pkg")

                pkg_lookup[pkg] = dict(
                        pn = pn,
                        rdepends = [ val.split(" ")[0] for val in pkg_dict.get("rdepends", []) ],
                        rrecommends = [ val.split(" ")[0] for val in pkg_dict.get("rrecommends", []) ],
                        rprovides = [ val.split(" ")[0] for val in pkg_dict.get("rprovides", []) ],
                    )

                if pkg_name != pkg and not pkg_name in pkg_lookup.keys():
                    # pkg_lookup[pkg_name] = dict( pkg_lookup[pkg] )
                    # pkg_lookup[pkg_name]["alias"] = pkg
                    pkg_lookup['aliases'][pkg_name] = pkg

                for feature in pkg_lookup[pkg]["rprovides"]:
                    if not feature in pkg_lookup['virtual'].keys():
                        pkg_lookup['rproviders'][feature] = pkg

        tsmeta_debug(d, 'pkg_map', pkg_lookup)
        return pkg_lookup

    def distill_image_pns(pkg_list, pkg_lookup):
        image_pns = set()
        for ppp in sorted(pkg_list):
            pn_name = str()
            if ppp in pkg_lookup.keys():
                pn_name = ppp
                bb.debug(2, "Checking %s (pn found)" % ppp)
            elif ppp in pkg_lookup['aliases'].keys():
                pn_name = pkg_lookup['aliases'].get(ppp)
                bb.debug(2, "Checking %s (alias %s found)" % (ppp, pn_name))
            elif ppp in pkg_lookup['virtual']["provider"].keys():
                pn_name = pkg_lookup['virtual']["provider"].get(ppp)
                bb.debug(2, "Checking %s (provider %s found)" % (ppp, pn_name))
            elif ppp in pkg_lookup['virtual']["runtime"].keys():
                pn_name = pkg_lookup['virtual']["runtime"].get(ppp)
                bb.debug(2, "Checking %s (runtime %s found)" % (ppp, pn_name))
            elif ppp in pkg_lookup['rproviders'].keys():
                pn_name = pkg_lookup['rproviders'].get(ppp)
                bb.debug(2, "Checking %s (rprovider %s found)" % (ppp, pn_name))
            else:
                bb.warn("%s: No pkg entry found" % ppp)
                continue

            p_dict = pkg_lookup.get(pn_name, {})
            pkg_pn = p_dict.get("pn", "None")
            image_pns.add(pkg_pn)

        pn_out = sorted(list(image_pns))
        tsmeta_debug(d, 'image_pns', pn_out)
        return pn_out

    def get_manifest_pkgs(sys_dict):
        image_dir = d.getVar("DEPLOY_DIR_IMAGE")
        image_spec = d.getVar("IMAGE_LINK_NAME")
        manifest_link = '.'.join([image_spec, 'manifest'])
        manifest_path = os.path.join(image_dir, manifest_link)

        rootfs_pkgs = list()
        if os.path.exists(manifest_path):
            bb.plain("Using RootFS Manifest %s" % manifest_path)
            with open(manifest_path) as f_desc:
                rootfs_pkgs = [ line.split()[0] for line in f_desc ]
        else:
            bb.error("RootFS Manifest Not Found: %s" % manifest_path)
        return rootfs_pkgs

    pkg_pn_map = get_pkg_lookup()
    rootfs_pkgs = get_manifest_pkgs(image_dict)
    image_pn_list = distill_image_pns(rootfs_pkgs, pkg_pn_map)
    return image_pn_list


python() {
    pn = d.getVar('PN')
    context = (d.getVar('BB_WORKERCONTEXT') or "")
    if context and bb.data.inherits_class('image', d):
        bb.build.exec_func("do_tsmeta_build", d)
}

addhandler tsmeta_eventhandler
tsmeta_eventhandler[eventmask] = "bb.event.BuildStarted"
python tsmeta_eventhandler() {
    import bb.runqueue
    import oe.path

    oe.path.remove(d.getVar('tsmeta_dir'), recurse = True)

    dict_names = [ 'distro', 'layers', 'machine' ]

    for d_name in dict_names:
        bb.build.exec_func("tsmeta_get_" + d_name, d)
}
