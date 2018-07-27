#!/usr/bin/env python
import fnmatch
import os
import sys
import re
import subprocess
import bisect
import logging

import bb.msg
import bb.providers
import bb.cache

__logger_name = 'BitBake'
logger = logging.getLogger(__logger_name)


def create_logger():
    logger = logging.getLogger(__logger_name)
    console = logging.StreamHandler(sys.stdout)
    errconsole = logging.StreamHandler(sys.stderr)
    format_str = "%(levelname)s: %(message)s"
    format = bb.msg.BBLogFormatter(format_str)
    bb.msg.addDefaultlogFilter(console, bb.msg.BBLogFilterStdOut)
    bb.msg.addDefaultlogFilter(errconsole, bb.msg.BBLogFilterStdErr)
    bb.providers.logger.setLevel(logging.DEBUG)
    console.setFormatter(format)
    errconsole.setFormatter(format)
    logger.addHandler(console)
    logger.addHandler(errconsole)
    return logger


def get_eof_pos(fn):
    with open(fn, 'a') as f:
        return f.tell()
    return -1


def is_useful_dep(cooker, pkg, dep):
    return dep in cooker.recipecache.pkg_pn and \
        dep != pkg and not is_native(dep) and not is_kernel(cooker, dep) and \
        not is_nopackages(cooker, dep)



def git_subprocess(args):
    try:
        with open(os.devnull, 'w') as devnull:
            output = subprocess.check_output(['git'] + args, stderr=devnull)[:-1]
    except subprocess.CalledProcessError:
        output = b'UNKNOWN'
    return output.decode('utf-8', 'replace')


def get_layer_info(cooker):
    all_info = []
    for lyr in cooker.data.getVar("BBLAYERS", True).split():
        # change working dir to layer for git commands
        curdir = os.getcwd()
        os.chdir(lyr)
        # gather info about the layer dir we are in
        name = os.path.basename(lyr)
        # remote can be tricky: can't assume git new enough for
        # 'remote get-url', or that remote name will be 'origin', or that
        # reflog hasn't been purged, so we're doing this in 2 commands
        remotes = git_subprocess(['remote']).split('\n')
        remote_name = 'origin' if 'origin' in remotes else remotes[0]
        remote = git_subprocess(['config', '--get',
                                 'remote.%s.url' % remote_name])
        prefix = git_subprocess(['rev-parse', '--show-prefix'])
        revision = git_subprocess(['rev-parse', 'HEAD'])
        branch = git_subprocess(['rev-parse', '--abbrev-ref', 'HEAD'])
        info = {'name': name,
                'path': lyr,
                'remote': remote,
                'revision': revision,
                'branch': branch}
        if len(prefix) > 0:
            info['prefix'] = prefix
        machines = []
        try:
            for f in os.listdir('conf/machine'):
                result = re.match('^(.*).conf$', f)
                if result is not None:
                    machines.append(result.group(1))
        except Exception:
            pass
        info['machines'] = sorted(machines)
        os.chdir(curdir)
        all_info.append(info)
    return all_info


# the BBFILES variable contains a unix file pattern like recipes-*/*/*.bb, this
# function is used to check if a file would be parsed
def is_whitelisted(whitelist_patterns, filename):
    for p in whitelist_patterns:
        if fnmatch.fnmatch(filename, p):
            return True
    return False


# these functions are taken from bitbake-layers
def get_layer_name(layerdir):
    return os.path.basename(layerdir.rstrip(os.sep))


def get_file_layerdir(cooker, filename):
    layer = bb.utils.get_file_layer(filename, cooker.data)
    return cooker.bbfile_collections.get(layer, None)


def get_file_layer(cooker, filename):
    layerdir = get_file_layerdir(cooker, filename)
    if layerdir:
        return get_layer_name(layerdir)
    else:
        return None


def is_native(pkg):
    return pkg.startswith('nativesdk-') or pkg.endswith('-native')


def get_fn(cooker, p):
    return cooker.recipecache.pkg_pn[p][0]


def __has_class(cls, cooker, p):
    fn = get_fn(cooker, p)
    return "%s.bbclass" % cls in [os.path.basename(b) for b in cooker.recipecache.inherits[fn]]


def is_kernel(cooker, p):
    return __has_class('kernel', cooker, p)


def is_image(cooker, p):
    return __has_class('image', cooker, p)


def is_nopackages(cooker, p):
    return __has_class('nopackages', cooker, p)


def dict_insort(d, k, v):
    try:
        if v not in d[k]:
            bisect.insort_left(d[k], v)
    except KeyError:
        d[k] = [v]


def get_images_from_cache(cooker):
    images = []
    for img in cooker.recipecache.pkg_pn:
        if not is_image(cooker, img): continue
        images.append(img)
    return images


def is_valid_image(cooker, image):
    images = get_images_from_cache(cooker)
    return image in images


def get_patch_list(recipedata):
    files = recipedata.getVar('SRC_URI', True).split()
    if not files:
        return []

    patches = []
    for f in files:
        fields = f.split('://')[-1].split(';')
        patch = fields[0]
        if ((patch.split('.')[-1] in ('diff', 'patch')) or 'apply=yes' in fields):
            patches.append(patch)
    return patches


def get_cve_whitelist(cooker):
    whitelist = cooker.data.getVar('CHECKCVES_WHITELIST', True) or ''
    return [w.strip() for w in whitelist.split()]
