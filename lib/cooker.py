#!/usr/bin/python

import logging
import os
import sys

from bb.cooker import state, BBCooker, CookerFeatures
from bb.cookerdata import CookerConfiguration
from bb import BBHandledException

logger = logging.getLogger('BitBake.TimesysCooker')

class TimesysCooker(BBCooker):
    def __init__(self, extra_caches=None):
        def idle_cb(a, b):
            pass

        cfg = CookerConfiguration()
        cfg.setServerRegIdleCallback(idle_cb)
        cfg.dry_run = True
        # need tracking to get the collections
        features = [CookerFeatures.HOB_EXTRA_CACHES, CookerFeatures.BASEDATASTORE_TRACKING]

        # init our base class
        BBCooker.__init__(self, cfg, features)

        # this is a hacky way to throw in more caches if we make custom cache classes
        if isinstance(extra_caches, list):
            self.caches_array += extra_caches

        self.parseConfiguration()

        # timesys-cooker specific members
        self.is_started = False
        self.bblayers = (self.data.getVar('BBLAYERS', '') or "").split()
        layerconfs = self.data.varhistory.get_variable_items_files('BBFILE_COLLECTIONS', self.data)
        self.bbfile_collections = {layer: os.path.dirname(os.path.dirname(path)) for layer, path in layerconfs.items()}


    # return true if the cooker is started, false otherwise
    # this function can take an array of caches...
    def start(self):
        logger.debug(1, "starting cooker")
        # parse all the recipes
        try:
            while self.state in (state.initial, state.parsing):
                self.updateCache()
        except KeyboardInterrupt:
            logger.error("User keyboard interrupt. Cannot start cooker.")
            self.shutdown()
            self.updateCache()
        except Exception as e:
            # bitbake should log it, we're using BBLogger
            pass
        else:
            self.is_started = True
            logger.debug(1, "cooker started")
        return self.is_started

    def stop(self):
        logger.debug(1, "shutting down cooker")
        self.shutdown()
        while self.state != state.shutdown:
            self.updateCache()
        self.configwatcher.close()
        self.watcher.close()
        self.unlockBitbake()
        logger.debug(1, "cooker shutdown complete")

    # We need a bitbake fix from poky@44b3eb65d9d6b2b91af08a5d50ec28f5df50f8f9
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
