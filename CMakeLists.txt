cmake_minimum_required(VERSION 3.16)
project(cno_quicly C)

option(CNO_QUIC_SHARED "Build as shared library" OFF)

find_package(PkgConfig REQUIRED)
pkg_check_modules(QUICLY  REQUIRED libquicly)
pkg_check_modules(PICOTLS REQUIRED libpicotls-core libpicotls-openssl)
pkg_check_modules(OPENSSL REQUIRED openssl)
pkg_check_modules(LIBUV   REQUIRED libuv)

if(NOT DEFINED QUICKJS_INCLUDE_DIR)
    pkg_check_modules(QUICKJS quickjs)
    if(QUICKJS_FOUND)
        set(QUICKJS_INCLUDE_DIR ${QUICKJS_INCLUDE_DIRS})
        set(QUICKJS_LIB         ${QUICKJS_LIBRARIES})
    else()
        message(FATAL_ERROR "QuickJS not found. Pass -DQUICKJS_INCLUDE_DIR=... -DQUICKJS_LIB=...")
    endif()
endif()

if(CNO_QUIC_SHARED)
    add_library(CNO_QUIC SHARED native.c)
else()
    add_library(CNO_QUIC STATIC native.c)
endif()

target_include_directories(CNO_QUIC PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    ${QUICKJS_INCLUDE_DIR}
    ${QUICLY_INCLUDE_DIRS}
    ${PICOTLS_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIRS}
    ${LIBUV_INCLUDE_DIRS}
)

target_link_libraries(CNO_QUIC PUBLIC
    ${QUICLY_LIBRARIES}
    ${PICOTLS_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${LIBUV_LIBRARIES}
    ${QUICKJS_LIB}
)

target_compile_options(CNO_QUIC PRIVATE
    -Wall -Wextra -Wno-unused-parameter
    $<$<CONFIG:MinSizeRel>:-Os>
)

include(GNUInstallDirs)
install(TARGETS CNO_QUIC
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
install(FILES native.h        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/circu)
install(FILES native.d.ts     DESTINATION ${CMAKE_INSTALL_DATADIR}/circu)