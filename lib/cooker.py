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
