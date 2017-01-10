cmake_minimum_required(VERSION 3.5)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

project (fib_perf)
set(CMAKE_BUILD_TYPE Release)
set(CMAKE_C_FLAGS "-std=c99")

link_directories($ENV{CCNX_DEPENDENCIES}/lib)
include_directories($ENV{CCNX_DEPENDENCIES}/include)
link_directories($ENV{CCNX_HOME}/lib)
include_directories($ENV{CCNX_HOME}/include)

set(OPENSSL_ROOT_DIR $ENV{CCNX_DEPENDENCIES})

find_package( LongBow REQUIRED )
include_directories(${LONGBOW_INCLUDE_DIRS})

find_package( LibEvent REQUIRED )
include_directories(${LIBEVENT_INCLUDE_DIRS})

find_package( Libparc REQUIRED )
include_directories(${LIBPARC_INCLUDE_DIRS})

find_package( CCNX_Common REQUIRED )
include_directories(${CCNX_COMMON_INCLUDE_DIRS})

find_package( CCNX_Transport_Rta REQUIRED )
include_directories(${CCNX_TRANSPORT_RTA_INCLUDE_DIRS})

find_package( CCNX_Portal REQUIRED )
include_directories(${CCNX_PORTAL_INCLUDE_DIRS})

#find_library(ARGON argon2)

# add the automatically determined parts of the RPATH
# which point to directories outside the build tree to the install RPATH
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH true)

# the RPATH to be used when installing, but only if it's not a system directory
list(FIND CMAKE_PLATFORM_IMPLICIT_LINK_DIRECTORIES "${CMAKE_INSTALL_PREFIX}/lib" isSystemDir)
if("${isSystemDir}" STREQUAL "-1")
    set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")
endif("${isSystemDir}" STREQUAL "-1")

include_directories(
        $ENV{CCNX_HOME}/include
    )

link_directories(
        $ENV{CCNX_HOME}/lib
    )

set(tsec_SOURCES
    src/tsec.c
    )

set(obfuscate_SOURCES
    src/obfuscate.c
    )

set(single_SOURCES
    src/single.c
    )

set(PERF_LIBRARIES
        argon2
        scrypt
        ssl
        crypto
        sodium
        parc
        longbow
        longbow-ansiterm
        ccnx_common
        ccnx_transport_rta
        ccnx_api_portal
        ccnx_api_notify
        ccnx_api_control
       )

set(targets
    tsec
    obfuscate
    single
    )

foreach(program ${targets})
    MESSAGE("Building " ${program})
    add_executable(${program} ${${program}_SOURCES})
    set_target_properties(${program} PROPERTIES COMPILE_FLAGS "-Wall -pg")
    target_link_libraries(${program} ${PERF_LIBRARIES})
    install(TARGETS ${program} DESTINATION bin)
endforeach()
