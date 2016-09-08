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

add_executable(tsec_perf ${tsec_SOURCES})
set_target_properties(tsec_perf PROPERTIES COMPILE_FLAGS "-Werror -pg")
target_link_libraries(tsec_perf ${PERF_LIBRARIES})
install(TARGETS tsec_perf DESTINATION bin)

add_executable(obfuscate_perf ${obfuscate_SOURCES})
set_target_properties(obfuscate_perf PROPERTIES COMPILE_FLAGS "-Werror -pg")
target_link_libraries(obfuscate_perf ${PERF_LIBRARIES})
install(TARGETS obfuscate_perf DESTINATION bin)
