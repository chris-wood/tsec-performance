cmake_minimum_required(VERSION 2.8)

project (fib_perf)
set(CMAKE_BUILD_TYPE Release)

include_directories(
        $ENV{CCNX_DEPENDENCIES}/include
        $ENV{CCNX_HOME}/include
        ${CMAKE_SOURCE_DIR}/include
    )

link_directories(
        $ENV{CCNX_HOME}/lib
        ${CMAKE_SOURCE_DIR}/lib
    )

set(tsec_SOURCES
    src/tsec_perf.c
    )

set(obfuscate_SOURCES
    src/obfuscate_perf.c
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
       )

set (targets 
    tsec_perf
    obfsucate_perf
    )

foreach(program ${targets})
    add_executable(${program} ${tsec_SOURCES})
    set_target_properties(${program} PROPERTIES COMPILE_FLAGS "-Wall -pg")
    target_link_libraries(${program} ${PERF_LIBRARIES})
    install(TARGETS ${program} DESTINATION bin)
endforeach()

