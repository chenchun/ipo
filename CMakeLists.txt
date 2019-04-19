cmake_minimum_required(VERSION 3.5)

project(ipo)

add_executable("ipo" ipo.c)

set(KERNEL_ROOT "/home/ramichen/project/c/linux")

include_directories(
        # kernel headers
        "${KERNEL_ROOT}/include"
        "${KERNEL_ROOT}/arch/amd/include"
        "${KERNEL_ROOT}/arch/amd64/include"
        # kernel source
        "${KERNEL_ROOT}/mm"
)