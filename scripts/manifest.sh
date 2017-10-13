#!/bin/bash

if [ $# -ne 2 ]; then
	echo "$0 must be run with 2 arguments:"
	echo "$0 <image-recipe> <output-file>"
	exit 1
fi

# check for our required utilities...
for UTIL in dirname git readlink which; do
	U=$(which ${UTIL} 2>/dev/null)
	if [ -z "${U}" ]; then
		echo "${U} is required. Cannot continue."
		exit 1
	fi
done

BITBAKE=$(which bitbake 2>/dev/null)

if [ -z "${BITBAKE}" ]; then
	echo "bitbake not found in PATH. Did you 'source oe-init-build-env'?"
	exit 1
fi

BBLIBDIR=$(readlink -f "$(dirname "${BITBAKE}")/..")
MANIFEST_PY=$(dirname "$(readlink -f "$0")")/lib/manifest.py

echo "Running manifest script. This takes some time using bitbake: ${BBLIBDIR}"
${MANIFEST_PY} ${BBLIBDIR} $@
