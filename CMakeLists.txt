cmake_minimum_required(VERSION 2.8)

project (fib_perf)
set(CMAKE_BUILD_TYPE Release)

include_directories(
        $ENV{CCNX_DEPENDENCIES}/include
        $ENV{CCNX_HOME}/include
        ${CMAKE_SOURCE_DIR}/include
        #/Users/cwood/Projects/balloon/include
    )

link_directories(
        $ENV{CCNX_HOME}/lib
        ${CMAKE_SOURCE_DIR}/lib
        #/Users/cwood/Projects/balloon/build/libballoon/
        #/Users/cwood/Projects/balloon/build/echo
        #/Users/cwood/Projects/balloon/build/keccak
        #/Users/cwood/Projects/balloon/build/libballoon/
        #/Users/cwood/Projects/balloon/build/blake2b
        #/Users/cwood/Projects/balloon/build/simpira
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
       longbow
       longbow-ansiterm
       parc
       ccnx_common
       ccnx_api_portal
       ccnx_api_notify
       ccnx_transport_rta
       ccnx_api_control
       sodium
       argon2
       scrypt

       # All balloon libraries
       #balloon
       #blake2b
       #keccak
       #simpira
       #crypto
       #echo
       )

set (targets 
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

