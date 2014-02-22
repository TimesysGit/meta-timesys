# Copyright (C) 2014 Timesys Corporation
SUMMARY = "MCC Ping Pong Demo"
DESCRIPTION = "This demo for Freescale Vybrid platforms pings the M4 running an MXQ image."
LICENSE = "GPL-2.0"
LIC_FILES_CHKSUM = "file://LICENSE;md5=c49712341497d0b5f2e40c30dff2af9d"

DEPENDS = "libmcc"
RDEPENDS_${PN} = "libmcc mqxboot"

inherit autotools

SRC_URI = "${TIMESYS_MIRROR}/m/mcc-pingpong/mcc-pingpong-${PV}/mcc-pingpong-${PV}.tar.bz2 \
           file://update-mcc_free_buffer-call.patch"

SRC_URI[md5sum] = "a03417c37f97849baa794e37d88e0cd2"
SRC_URI[sha256sum] = "ad25a15f34eb758b7896d327a28ef884e2ab04851cff42f059b32dc63e42704b"

S = "${WORKDIR}/mcc-pingpong-${PV}"

CFLAGS += " -I${STAGING_KERNEL_DIR}/include"

COMPATIBLE_MACHINE = "(vf60)"
