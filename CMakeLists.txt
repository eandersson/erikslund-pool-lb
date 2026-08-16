cmake_minimum_required(VERSION 3.22)
project(erikslund_pool_lb VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "" FORCE)
endif()

add_compile_options(-Wall -Wextra -Wshadow)

option(NATIVE_ARCH "Tune for the build machine CPU" ON)
option(PROFILE_BUILD "Retain symbols and frame pointers for production-path profiling" OFF)
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_options(-O3 -flto -fno-plt -fno-semantic-interposition
                        -ffunction-sections -fdata-sections -pipe -fPIE
                        -fstack-protector-strong -fstack-clash-protection
                        -fcf-protection=full)
    add_compile_definitions(_FORTIFY_SOURCE=3 _GLIBCXX_ASSERTIONS)
    add_link_options(-flto=auto -Wl,-O3 -Wl,--as-needed -Wl,--gc-sections
                     -pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack)
    if(NATIVE_ARCH)
        add_compile_options(-march=native -mtune=native)
    endif()
endif()

if(PROFILE_BUILD)
    add_compile_options(-g -fno-omit-frame-pointer)
    add_link_options(-g)
endif()

find_package(Threads REQUIRED)
find_package(OpenSSL 3.0 REQUIRED COMPONENTS SSL Crypto)
# erikslund-http-embedded retains the erikslund-http package and erikslund::http target names.
find_package(erikslund-http 0.1.2 EXACT CONFIG REQUIRED)
find_library(MIMALLOC_LIBRARY mimalloc REQUIRED)

file(GLOB_RECURSE CORE_SOURCES CONFIGURE_DEPENDS ${CMAKE_SOURCE_DIR}/src/*.cpp)
list(FILTER CORE_SOURCES EXCLUDE REGEX ".*/main\\.cpp$")

add_library(erikslund_pool_lb_core STATIC ${CORE_SOURCES})
target_include_directories(erikslund_pool_lb_core PUBLIC ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(erikslund_pool_lb_core PUBLIC Threads::Threads OpenSSL::SSL OpenSSL::Crypto
                                                       erikslund::http)

add_executable(erikslund-pool-lb ${CMAKE_SOURCE_DIR}/src/main.cpp)
target_link_libraries(erikslund-pool-lb PRIVATE erikslund_pool_lb_core
    -Wl,--no-as-needed ${MIMALLOC_LIBRARY} -Wl,--as-needed)
target_compile_definitions(erikslund-pool-lb PRIVATE HAVE_MIMALLOC)
target_link_options(erikslund-pool-lb PRIVATE -rdynamic)

include(CTest)
if(BUILD_TESTING)
    file(GLOB_RECURSE TEST_SOURCES CONFIGURE_DEPENDS ${CMAKE_SOURCE_DIR}/tests/*.cpp)
    list(FILTER TEST_SOURCES EXCLUDE REGEX ".*/e2e/.*")
    add_executable(erikslund_pool_lb_tests ${TEST_SOURCES})
    target_link_libraries(erikslund_pool_lb_tests PRIVATE erikslund_pool_lb_core)
    target_compile_options(erikslund_pool_lb_tests PRIVATE -Wno-shadow)
    add_test(NAME unit COMMAND erikslund_pool_lb_tests)
endif()
