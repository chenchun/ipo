cmake_minimum_required(VERSION 3.5)

project(ipo C)

add_executable("ipo" ipo.c)

set(dirs /home/ramichen/project/c/centos/linux-3.10.0-957.12.2.el7 /Volumes/devel/linux /Users/ramichen/project/c/centos7 /home/ramichen/project/c/linux)
foreach(dir IN LISTS dirs)
        if(EXISTS ${dir})
                set(KERNEL_ROOT ${dir})
                break()
        endif()
endforeach()
message("KERNEL_ROOT=" ${KERNEL_ROOT})

execute_process(COMMAND grep pcpu_sw_netstats ${KERNEL_ROOT}/include/linux/netdevice.h
        OUTPUT_VARIABLE OUT)
if("${OUT}" STREQUAL "")
        set(PCPU_SW_NETSTATS "NPCPU_SW_NETSTATS")
else()
        set(PCPU_SW_NETSTATS "PCPU_SW_NETSTATS")
endif()

add_definitions(-D__KERNEL__ -DDEBUG -D__LITTLE_ENDIAN_BITFIELD -DCONFIG_SLAB -D${PCPU_SW_NETSTATS})

include_directories(
        # kernel headers
        "${KERNEL_ROOT}/include"
        "${KERNEL_ROOT}/include/uapi"
        "${KERNEL_ROOT}/arch/x86/include/"
        "${KERNEL_ROOT}/arch/x86/include/uapi"
        # kernel source
        "${KERNEL_ROOT}/mm"
)
