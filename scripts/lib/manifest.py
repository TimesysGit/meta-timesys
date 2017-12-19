#!/usr/bin/env python
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
from backport import generatePkgDepTreeData
from utils import get_file_layer, get_layer_info, get_images_from_cache, \
is_valid_image

logger = logging.getLogger('BitBake')

manifest_version = "1.2"

def setup_tinfoil(tracking=False):
    tinfoil = bb.tinfoil.Tinfoil(tracking=tracking)
    tinfoil.logger.setLevel(logger.getEffectiveLevel())

    options = bb.tinfoil.TinfoilConfigParameters(parse_only=True, dry_run=True)
    tinfoil.config.setConfigParameters(options)
    tinfoil.cooker.featureset.setFeature(bb.cooker.CookerFeatures.HOB_EXTRA_CACHES)

    tinfoil.bblayers = (tinfoil.config_data.getVar('BBLAYERS', True) or "").split()
    layerconfs = tinfoil.config_data.varhistory.get_variable_items_files(
        'BBFILE_COLLECTIONS', tinfoil.config_data)
    tinfoil.cooker.bbfile_collections = {
        layer: os.path.dirname(os.path.dirname(path))
        for layer, path in layerconfs.items()}

    # on this instance, use backported generatePkgDepTreeData()
    tinfoil.cooker.generatePkgDepTreeData = \
        generatePkgDepTreeData.__get__(tinfoil.cooker, tinfoil.cooker.__class__)

    tinfoil.prepare()
    return tinfoil


def find_patched_cves(cooker_data, realfn):
    # iterate over the recipes which would be built (pn-buildlist)
    cve_match = re.compile("CVE:( CVE\-\d{4}\-\d+)+")
    cve_patch_name_match = re.compile("(CVE\-\d{4}\-\d+)+")
    patched_cves = dict()
    for key, value in cooker_data.file_checksums[realfn[0]].items():
        patches = value.split()
        for patch in patches:
            patch_file, _, patch_data = patch.partition(':')
            if patch_file.endswith('.patch') and patch_data == 'True':
                with open(patch_file, "rb") as f:
                    try:
                        patch_text = f.read().decode('utf-8', 'replace')
                    except UnicodeDecodeError:
                        logger.info("Failed to read patch %s" % patch_file)
                        f.close()
                match = cve_match.search(patch_text)
                if match:
                    cves = patch_text[match.start()+5:match.end()]
                    for cve in cves.split():
                        try:
                            if patch_file not in patched_cves[cve]:
                                patched_cves[cve].append(patch_file)
                        except KeyError:
                            patched_cves[cve] = [patch_file]
                else:
                    match = cve_patch_name_match.search(patch_file)
                    if match:
                        cve = match.group(1)
                        try:
                            if patch_file not in patched_cves[cve]:
                                patched_cves[cve].append(patch_file)
                        except KeyError:
                            patched_cves[cve] = [patch_file]
    return patched_cves


def layer_dict(lyr):
    # Keep a subset of all the layer info
    return dict(remote=lyr['remote'], rev=lyr['revision'], branch=lyr['branch'])


if __name__ == '__main__':
    tf = setup_tinfoil(tracking=True)
    if not is_valid_image(tf.cooker, target):
        images = get_images_from_cache(tf.cooker)
        print("Unable to find image: %s\n" % target)
        print("Please select an image from the following list:")
        for img in images:
            print(img)
        tf.shutdown()
        sys.exit(1)

    distro = tf.config_data.get('DISTRO_CODENAME') or tf.config_data.get('DISTRO_NAME')
    layer_info = {lyr['name']: layer_dict(lyr) for lyr in get_layer_info(tf.cooker)}

    manifest = dict(date=datetime.utcnow().isoformat(),
                    distro=distro,
                    distro_version=tf.config_data.get('DISTRO_VERSION'),
                    image=target,
                    layers=layer_info,
                    machine=tf.config_data.get('MACHINE'),
                    packages=dict(),
                    manifest_version=manifest_version)

    latest_versions, preferred_versions = bb.providers.findProviders(
                                              tf.config_data,
                                              tf.cooker_data,
                                              tf.cooker_data.pkg_pn)

    depgraph = tf.cooker.generatePkgDepTreeData([target], 'build')
    for p in depgraph['pn']:
        if p.endswith('-native'):
            continue

        pref = preferred_versions[p]
        realfn = bb.cache.Cache.virtualfn2realfn(pref[1])
        preffile = realfn[0]
        # We only display once per recipe, we should prefer non extended
        # versions of the recipe if present (so e.g. in OpenEmbedded, openssl
        # rather than nativesdk-openssl which would otherwise sort first).
        if realfn[1] and realfn[0] in tf.cooker_data.pkg_fn:
            continue

        lyr = get_file_layer(tf.cooker, preffile)
        p_version = str("%s" % (pref[0][1]))
        info = layer_info.get(lyr)
        branch = info.get('branch', 'UNKNOWN')
        cves = find_patched_cves(tf.cooker_data, realfn)

        manifest['packages'][p] = dict(version=p_version,
                                       layer=lyr,
                                       branch=branch,
                                       patched_cves=cves)

        appendfiles = tf.cooker.collection.get_file_appends(preffile)
        recipe_info = bb.cache.Cache.loadDataFull(pref[1], appendfiles,
                                                  tf.config_data)
        cve_product = recipe_info.get('CVE_PRODUCT')
        if cve_product:
            cve_version = p_version.split("+git")[0]
            manifest['packages'][p]['cve_product'] = cve_product
            manifest['packages'][p]['cve_version'] = cve_version


    s = json.dumps(manifest, indent=2, sort_keys=True)
    with open(ofile, "w") as f:
        f.write(s)

    tf.shutdown()
    print('Done. Wrote manifest to "%s"' % ofile)
