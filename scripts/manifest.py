#!/usr/bin/env python

import json
import os
import re
import sys
import subprocess
import logging

if len(sys.argv) != 4:
    usage()

def usage():
    print("This script generates a json manifest file of the recipes built for an image.")
    print("manifest.py <bitbake-root> <bitbake-target> <output-file>")
    sys.exit(1)

broot = sys.argv[1]
target = sys.argv[2]
ofile = sys.argv[3]

# need to add our lib folder, so first figure out where manifest.py lives
bindir = os.path.dirname(__file__)
# get parent dir
topdir = os.path.dirname(bindir)
# add libs to path for imports
sys.path[0:0] = [os.path.join(broot, 'lib'), os.path.join(topdir, 'lib')]

from cooker import TimesysCooker
from utils import get_file_layer, get_layer_info

logger = logging.getLogger('BitBake')
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.INFO)

cooker = TimesysCooker()
manifest = dict()
logger.critical ("trying to start cooker")
if cooker.start():
    logger.info ("started cooker")

    # get a list of all the recipes and providing files (layers)
    (latest_versions, preferred_versions) = bb.providers.findProviders(cooker.data, cooker.recipecache, cooker.recipecache.pkg_pn)
    allproviders = bb.providers.allProviders(cooker.recipecache)

    logger.info ("running for %s" % target)
    # generate dependencies for the image target passed, image_complete is last image task
    depgraph = cooker.generatePkgDepTreeData([target], 'build')

    # get all the layers currently used
    layer_info = { lyr['name'] : dict(collection=lyr.get('collection', 'UNKNOWN'), remote=lyr['remote'].decode('utf-8'), rev=lyr['revision'].decode('utf-8'), branch=lyr['branch'].decode('utf-8')) for lyr in get_layer_info(cooker) }
    manifest = dict(layers=layer_info, packages=dict(), image=target, distro=cooker.data.get('DISTRO_CODENAME'), distro_version=cooker.data.get('DISTRO_VERSION'), machine=cooker.data.get('MACHINE'))
    preffiles = []
    items = dict() # pkg -> { version, layers : [{ info }] }

    cve_match = re.compile("CVE:( CVE\-\d{4}\-\d+)+")
    cve_patch_name_match = re.compile("(CVE\-\d{4}\-\d+)+")
    patched_cves = dict()

    # iterate over the recipes which would be built (pn-buildlist)
    for p in depgraph['pn']:
        pref = preferred_versions[p]
        realfn = bb.cache.Cache.virtualfn2realfn(pref[1])
        preffile = realfn[0]
        # We only display once per recipe, we should prefer non extended versions of the
        # recipe if present (so e.g. in OpenEmbedded, openssl rather than nativesdk-openssl
        # which would otherwise sort first).
        if realfn[1] and realfn[0] in cooker.recipecache.pkg_fn:
            continue

        lyr = get_file_layer(cooker, preffile)
        p_version = str("%s" % (pref[0][1]))
        info = layer_info.get(lyr)
        branch = info['branch']

        manifest['packages'][p] = dict(version=p_version, layer=lyr, branch=branch)

        for key,value in cooker.recipecache.file_checksums[realfn[0]].iteritems():
            patches = value.split()
            for patch in patches:
                patch_file,_,patch_data = patch.partition(':')
                if patch_file.endswith('.patch') and patch_data == 'True':
                    with open(patch_file, "r") as f:
                        try:
                            patch_text = f.read()
                        except UnicodeDecodeError:
                            logger.info ("Failed to read patch %s" %  patch_file)
                            f.close()
                    match = cve_match.search(patch_text)
                    if match:
                        cves = patch_text[match.start()+5:match.end()]
                        for cve in cves.split():
                            try:
                                patched_cves[cve].append(patch_file)
                            except KeyError:
                                patched_cves[cve] = [patch_file]
                    else:
                        match = cve_patch_name_match.search(patch_file)
                        if match:
                            cve = match.group(1)
                            try:
                                patched_cves[cve].append(patch_file)
                            except KeyError:
                                patched_cves[cve] = [patch_file]
    manifest["patched_cves"] = patched_cves

    import pprint
    pp = pprint.PrettyPrinter(indent=2)
    pp.pprint(manifest)
    # dump the manifest.
    s = json.dumps(manifest, indent=2)
    with open(ofile, "w") as f:
        f.write(s)

    cooker.shutdown()
else:
    logger.error("Failed to start cooker. Exiting...")
