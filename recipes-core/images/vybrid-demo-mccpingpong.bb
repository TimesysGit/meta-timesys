SUMMARY = "This demo image will boot mcc-pingpong demo on Vybrid platfroms"

IMAGE_FEATURES += "ssh-server-dropbear"

IMAGE_INSTALL = "\
	packagegroup-core-boot \
	mcc-pingpong \
	${CORE_IMAGE_EXTRA_INSTALL} \
	"

LICENSE = "MIT"

inherit core-image

COMPATIBLE_MACHINE = "(vf60)"
