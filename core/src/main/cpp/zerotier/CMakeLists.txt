cmake_minimum_required(VERSION 3.22)
project(meowz_zerotier LANGUAGES CXX)

include(FetchContent)
set(zt_commit fc5c3ec22090b5b2a0f274e863651fe9ca489bf4)
set(MEOW_ZT_ARCHIVE "" CACHE FILEPATH "Optional local copy of the pinned upstream source archive")
if(MEOW_ZT_ARCHIVE)
    set(zt_archive "${MEOW_ZT_ARCHIVE}")
else()
    set(zt_archive "https://codeload.github.com/zerotier/ZeroTierOne/tar.gz/${zt_commit}")
endif()
if(POLICY CMP0135)
    cmake_policy(SET CMP0135 NEW)
endif()
FetchContent_Declare(zt_upstream
    URL "${zt_archive}"
    URL_HASH SHA256=5f48e6a9492cc2a31f28f9f15e7fad5e1b4a82e95fe451464ff2b32d6bed9fa4
    SOURCE_SUBDIR meowz-do-not-build-upstream-targets)
FetchContent_MakeAvailable(zt_upstream)

# Build the MPL client, not the daemon, controller, or nonfree targets. The
# upstream CMake recipe targets an older core and omits the current headers.
set(zt "${zt_upstream_SOURCE_DIR}")
set(prom "${zt}/ext/prometheus-cpp-lite-1.0")
file(GLOB zt_node_sources CONFIGURE_DEPENDS "${zt}/node/*.cpp")
add_library(meowz_zerotier_core STATIC ${zt_node_sources} "${zt}/osdep/OSUtils.cpp")
target_compile_features(meowz_zerotier_core PUBLIC cxx_std_17)
set_target_properties(meowz_zerotier_core PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(meowz_zerotier_core SYSTEM
    PUBLIC "${zt}/include"
    PRIVATE "${zt}/ext" "${prom}/core/include" "${prom}/simpleapi/include"
            "${prom}/3rdparty/http-client-lite/include")

if(NOT ANDROID)
    include(CTest)
    if(BUILD_TESTING)
        add_executable(zerotier_node_test node_test.cpp)
        target_link_libraries(zerotier_node_test PRIVATE meowz_zerotier_core)
        add_test(NAME zerotier_node_lifecycle COMMAND zerotier_node_test)
    endif()
endif()
