cmake_minimum_required(VERSION 3.5)

project(ipo C)

add_executable("ipo" ipo.c)

add_definitions(-D__KERNEL__ -DDEBUG -D__LITTLE_ENDIAN_BITFIELD -DCONFIG_SLAB)

set(KERNEL_ROOT "/home/ramichen/project/c/centos/linux-3.10.0-957.12.2.el7")
IF(NOT EXISTS ${KERNEL_ROOT})
        set(KERNEL_ROOT "/Volumes/devel/linux")
endif(NOT EXISTS ${KERNEL_ROOT})

include_directories(
        # kernel headers
        "${KERNEL_ROOT}/include"
        "${KERNEL_ROOT}/include/uapi"
        "${KERNEL_ROOT}/arch/x86/include/"
        "${KERNEL_ROOT}/arch/x86/include/uapi"
        # kernel source
        "${KERNEL_ROOT}/mm"
)
