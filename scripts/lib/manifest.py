#!/usr/bin/env python3
# Copyright (C) 2017 Timesys Corporation

from datetime import datetime
import logging
import json
import os
import re
import sys

# expects bitbake dir, target image, output filename
broot = sys.argv[1]
target = sys.argv[2]
ofile = sys.argv[3]

sys.path.insert(0, os.path.join(broot, 'lib'))

import bb
import bb.tinfoil
from utils import get_file_layer, get_layer_info, get_images_from_cache, \
                  is_valid_image, is_native, get_patch_list

logger = logging.getLogger('BitBake')

manifest_version = "1.1"


def setup_tinfoil(tracking=False):
    tinfoil = bb.tinfoil.Tinfoil(tracking=tracking)
    tinfoil.logger.setLevel(logger.getEffectiveLevel())

    options = bb.tinfoil.TinfoilConfigParameters(False,
                                                 parse_only=True,
                                                 dry_run=True)
    tinfoil.prepare(config_params=options)
    tinfoil.run_command('setFeatures', ['bb.cooker.CookerFeatures.HOB_EXTRA_CACHES'])

    # this part is from bitbake/lib/bblayers:
    tinfoil.bblayers = (tinfoil.config_data.getVar('BBLAYERS', True) or "").split()
    layerconfs = tinfoil.config_data.varhistory.get_variable_items_files(
        'BBFILE_COLLECTIONS', tinfoil.config_data)
    tinfoil.config_data.bbfile_collections = {
        layer: os.path.dirname(os.path.dirname(path))
        for layer, path in layerconfs.items()}

    return tinfoil


def find_patched_cves(tf, realfn, recipedata):
    cve_pattern = re.compile("(CVE\-\d{4}\-\d+)+")
    patched_cves = dict()

    for patch in get_patch_list(recipedata):
        # do quick check for CVE ID in file name first, else check patch body
        cves = cve_pattern.findall(patch)
        if not cves:
            try:
                with open(patch, 'rb') as f:
                    content = f.read().decode('utf-8', 'replace')
            except (OSError, IOError, UnicodeDecodeError) as e:
                logger.warning("Failed to read patch: %s: %s" % (patch, e))
                continue
            cves = cve_pattern.findall(content)

        for cve in cves:
            try:
                if patch not in patched_cves[cve]:
                    patched_cves[cve].append(patch)
            except KeyError:
                patched_cves[cve] = [patch]
    return patched_cves


def layer_dict(lyr):
    # Keep a subset of all the layer info
    return dict(remote=lyr['remote'], rev=lyr['revision'], branch=lyr['branch'])


if __name__ == '__main__':
    tf = setup_tinfoil(tracking=True)
    images = get_images_from_cache(tf)
    if not is_valid_image(tf, target, images=images):
        print("Unable to find image: %s\n" % target)
        print("Please select an image from the following list:")
        for img in images:
            print(img)
        tf.shutdown()
        sys.exit(1)

    distro = tf.config_data.get('DISTRO_CODENAME') or tf.config_data.get('DISTRO_NAME')

    layer_info = {lyr['name']: layer_dict(lyr) for lyr in get_layer_info(tf.config_data)}

    manifest = dict(date=datetime.utcnow().isoformat(),
                    distro=distro,
                    distro_version=tf.config_data.get('DISTRO_VERSION'),
                    image=target,
                    layers=layer_info,
                    machine=tf.config_data.get('MACHINE'),
                    packages=dict(),
                    manifest_version=manifest_version)

    tf.set_event_mask(['bb.event.DepTreeGenerated',
                       'bb.command.CommandFailed',
                       'bb.command.CommandCompleted'])

    ret = tf.run_command('generateDepTreeEvent', [target], 'build')

    depgraph = None
    if ret:
        while True:
            event = tf.wait_event(1)
            if event:
                if isinstance(event, bb.event.DepTreeGenerated):
                    depgraph = event._depgraph
                elif isinstance(event, bb.command.CommandFailed):
                    logger.error(str(event.error))
                    tf.shutdown()
                    sys.exit(2)
                elif isinstance(event, bb.command.CommandCompleted):
                    break
                elif isinstance(event, logging.LogRecord):
                    logger.handle(event)

    if not depgraph:
        logger.error('Failed to generate a depgraph for this image!')
        tf.shutdown()
        sys.exit(2)

    for p in depgraph['pn']:
        recipeinfo = tf.parse_recipe(p)
        if is_native(p):
            continue

        fn = tf.get_recipe_file(p)
        (pe, pv, pr) = tf.cooker_data.pkg_pepvpr[fn]
        realfn = bb.cache.virtualfn2realfn(fn)[0]

        lyr = get_file_layer(tf, realfn)
        info = layer_info.get(lyr)
        branch = info.get('branch', 'UNKNOWN')
        cves = find_patched_cves(tf, realfn, recipeinfo)

        manifest['packages'][p] = dict(version=pv,
                                       layer=lyr,
                                       branch=branch,
                                       patched_cves=cves)

    s = json.dumps(manifest, indent=2, sort_keys=True)
    with open(ofile, "w") as f:
        f.write(s)

    tf.shutdown()
    print('Done. Wrote manifest to "%s"' % ofile)
