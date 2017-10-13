#!/usr/bin/env python

import fnmatch
import re

# pulled from poky/bitbake/lib/bb/utils.py - not available before fido(ish)
def get_file_layer(filename, d):
    """Determine the collection (as defined by a layer's layer.conf file) containing the specified file"""
    collections = (d.getVar('BBFILE_COLLECTIONS', True) or '').split()
    collection_res = {}
    for collection in collections:
        collection_res[collection] = d.getVar('BBFILE_PATTERN_%s' % collection, True) or ''

    def path_to_layer(path):
        # Use longest path so we handle nested layers
        matchlen = 0
        match = None
        for collection, regex in collection_res.iteritems():
            if len(regex) > matchlen and re.match(regex, path):
                matchlen = len(regex)
                match = collection
        return match

    result = None
    bbfiles = (d.getVar('BBFILES', True) or '').split()
    bbfilesmatch = False
    for bbfilesentry in bbfiles:
        if fnmatch.fnmatch(filename, bbfilesentry):
            bbfilesmatch = True
            result = path_to_layer(bbfilesentry)

    if not bbfilesmatch:
        # Probably a bbclass
        result = path_to_layer(filename)

    return result


# We need a BBCooker fix from poky@44b3eb65d9d6b2b91af08a5d50ec28f5df50f8f9
# which was not merged in for Morty or Pyro.
def generatePkgDepTreeData(self, pkgs_to_build, task):
    """
    Create a dependency tree of pkgs_to_build, returning the data.
    """
    if not task.startswith("do_"):
        task = "do_%s" % task

    _, taskdata = self.prepareTreeData(pkgs_to_build, task)

    seen_fns = []
    depend_tree = {}
    depend_tree["depends"] = {}
    depend_tree["pn"] = {}
    depend_tree["rdepends-pn"] = {}
    depend_tree["rdepends-pkg"] = {}
    depend_tree["rrecs-pkg"] = {}

    # if we have extra caches, list all attributes they bring in
    extra_info = []
    for cache_class in self.caches_array:
        if type(cache_class) is type and issubclass(cache_class, bb.cache.RecipeInfoCommon) and hasattr(cache_class, 'cachefields'):
            cachefields = getattr(cache_class, 'cachefields', [])
            extra_info = extra_info + cachefields

    tids = []
    for mc in taskdata:
        for tid in taskdata[mc].taskentries:
            tids.append(tid)

    for tid in tids:
        (mc, fn, taskname, taskfn) = bb.runqueue.split_tid_mcfn(tid)

        pn = self.recipecaches[mc].pkg_fn[taskfn]
        pn = self.add_mc_prefix(mc, pn)

        if pn not in depend_tree["pn"]:
            depend_tree["pn"][pn] = {}
            depend_tree["pn"][pn]["filename"] = taskfn
            version  = "%s:%s-%s" % self.recipecaches[mc].pkg_pepvpr[taskfn]
            depend_tree["pn"][pn]["version"] = version
            rdepends = self.recipecaches[mc].rundeps[taskfn]
            rrecs = self.recipecaches[mc].runrecs[taskfn]
            depend_tree["pn"][pn]["inherits"] = self.recipecaches[mc].inherits.get(taskfn, None)

            # for all extra attributes stored, add them to the dependency tree
            for ei in extra_info:
                depend_tree["pn"][pn][ei] = vars(self.recipecaches[mc])[ei][taskfn]

        if taskfn not in seen_fns:
            seen_fns.append(taskfn)

            depend_tree["depends"][pn] = []
            for dep in taskdata[mc].depids[taskfn]:
                pn_provider = ""
                if dep in taskdata[mc].build_targets and taskdata[mc].build_targets[dep]:
                    fn_provider = taskdata[mc].build_targets[dep][0]
                    pn_provider = self.recipecaches[mc].pkg_fn[fn_provider]
                else:
                    pn_provider = dep
                pn_provider = self.add_mc_prefix(mc, pn_provider)
                depend_tree["depends"][pn].append(pn_provider)

            depend_tree["rdepends-pn"][pn] = []
            for rdep in taskdata[mc].rdepids[taskfn]:
                pn_rprovider = ""
                if rdep in taskdata[mc].run_targets and taskdata[mc].run_targets[rdep]:
                    fn_rprovider = taskdata[mc].run_targets[rdep][0]
                    pn_rprovider = self.recipecaches[mc].pkg_fn[fn_rprovider]
                else:
                    pn_rprovider = rdep
                pn_rprovider = self.add_mc_prefix(mc, pn_rprovider)
                depend_tree["rdepends-pn"][pn].append(pn_rprovider)

            depend_tree["rdepends-pkg"].update(rdepends)
            depend_tree["rrecs-pkg"].update(rrecs)

    return depend_tree
