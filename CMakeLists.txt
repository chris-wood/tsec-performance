cmake_minimum_required(VERSION 2.8)

project (fib_perf)
set(CMAKE_BUILD_TYPE Release)

include_directories(
        /usr/local/ccnx/dependencies/build/include
        /Users/cwood/PARC/side/Bindings/usr/include
    )

link_directories(
        /Users/cwood/PARC/side/Bindings/usr/lib
    )

set(tsec_SOURCES
    src/tsec_perf.c
    )

set(TSEC_PERF_LIBRARIES
       longbow
       longbow-ansiterm
       parc
       ccnx_common
       ccnx_api_portal
       ccnx_api_notify
       ccnx_transport_rta
       ccnx_api_control
       check
       sodium
       )

add_executable(tsec_perf ${tsec_SOURCES})
set_target_properties(tsec_perf PROPERTIES COMPILE_FLAGS "-Werror -pg")
target_link_libraries(tsec_perf ${TSEC_PERF_LIBRARIES})
install(TARGETS tsec_perf DESTINATION bin)
