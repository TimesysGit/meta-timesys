import fnmatch
import os
import re
import subprocess
import bisect
import bb  # needs bitbake/lib in python path


def git_subprocess(args):
    try:
        output = subprocess.check_output(['git'] + args, stderr=subprocess.DEVNULL)[:-1]
    except subprocess.CalledProcessError:
        output = b'UNKNOWN'
    return output.decode('utf-8', 'replace')


def get_layer_info(config_data):
    all_info = []
    for lyr in config_data.getVar("BBLAYERS").split():
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


def get_file_layer(tinfoil, filename):
    layerdir = get_file_layerdir(tinfoil, filename)
    if layerdir:
        return get_layer_name(layerdir)
    else:
        return '?'


def get_file_layerdir(tinfoil, filename):
    layer = bb.utils.get_file_layer(filename, tinfoil.config_data)
    return tinfoil.config_data.bbfile_collections.get(layer, None)


def is_native(pkg):
    return pkg.startswith('nativesdk-') or pkg.endswith('-native')


def is_kernel(recipe):
    return 'kernel' in recipe.inherits()


def is_image(recipe):
    return 'image' in recipe.inherits()


def dict_insort(d, k, v):
    try:
        if v not in d[k]:
            bisect.insort_left(d[k], v)
    except KeyError:
        d[k] = [v]


def get_images_from_cache(tinfoil):
    images = [r.pn for r in tinfoil.all_recipes(sort=False) if is_image(r)]
    images.sort()
    return images


def is_valid_image(tinfoil, image, images=None):
    if not images:
        images = get_images_from_cache(tinfoil)
    return image in images


def get_patch_list(recipedata):
    files = recipedata.getVar('SRC_URI').split()
    if not files:
        return []

    patches = []
    for f in files:
        fields = f.split('://')[-1].split(';')
        patch = fields[0]
        if ((patch.split('.')[-1] in ('diff', 'patch')) or 'apply=yes' in fields):
            patches.append(patch)
    return patches


def get_cve_whitelist(tinfoil):
    whitelist = tinfoil.config_data.get('CHECKCVES_WHITELIST') or ''
    return [w.strip() for w in whitelist.split()]
