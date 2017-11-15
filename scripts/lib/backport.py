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
    _, taskdata = self.prepareTreeData(pkgs_to_build, task)
    tasks_fnid = []
    if len(taskdata.tasks_name) != 0:
        for task in xrange(len(taskdata.tasks_name)):
            tasks_fnid.append(taskdata.tasks_fnid[task])

    seen_fnids = []
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

    for task in xrange(len(tasks_fnid)):
        fnid = tasks_fnid[task]
        fn = taskdata.fn_index[fnid]
        pn = self.recipecache.pkg_fn[fn]

        if pn not in depend_tree["pn"]:
            depend_tree["pn"][pn] = {}
            depend_tree["pn"][pn]["filename"] = fn
            version  = "%s:%s-%s" % self.recipecache.pkg_pepvpr[fn]
            depend_tree["pn"][pn]["version"] = version
            rdepends = self.recipecache.rundeps[fn]
            rrecs = self.recipecache.runrecs[fn]
            depend_tree["pn"][pn]["inherits"] = self.recipecache.inherits.get(fn, None)

            # for all extra attributes stored, add them to the dependency tree
            for ei in extra_info:
                depend_tree["pn"][pn][ei] = vars(self.recipecache)[ei][fn]

        if fnid not in seen_fnids:
            seen_fnids.append(fnid)

            depend_tree["depends"][pn] = []
            for dep in taskdata.depids[fnid]:
                item = taskdata.build_names_index[dep]
                pn_provider = ""
                targetid = taskdata.getbuild_id(item)
                if targetid in taskdata.build_targets and taskdata.build_targets[targetid]:
                    id = taskdata.build_targets[targetid][0]
                    fn_provider = taskdata.fn_index[id]
                    pn_provider = self.recipecache.pkg_fn[fn_provider]
                else:
                    pn_provider = item
                depend_tree["depends"][pn].append(pn_provider)

            depend_tree["rdepends-pn"][pn] = []
            for rdep in taskdata.rdepids[fnid]:
                item = taskdata.run_names_index[rdep]
                pn_rprovider = ""
                targetid = taskdata.getrun_id(item)
                if targetid in taskdata.run_targets and taskdata.run_targets[targetid]:
                    id = taskdata.run_targets[targetid][0]
                    fn_rprovider = taskdata.fn_index[id]
                    pn_rprovider = self.recipecache.pkg_fn[fn_rprovider]
                else:
                    pn_rprovider = item
                depend_tree["rdepends-pn"][pn].append(pn_rprovider)

            depend_tree["rdepends-pkg"].update(rdepends)
            depend_tree["rrecs-pkg"].update(rrecs)

    return depend_tree
