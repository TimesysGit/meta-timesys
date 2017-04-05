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
