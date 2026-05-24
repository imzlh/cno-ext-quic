cmake_minimum_required(VERSION 3.16)
project(cno_quicly C)

# ─── Options ────────────────────────────────────────────────────────────────
option(CNO_QUIC_SHARED "Build as shared library" OFF)

# ─── Dependency strategy ────────────────────────────────────────────────────
# We support two layouts:
#   1. Submodule mode (preferred, required on Windows since vcpkg has no
#      libquicly port): deps/quicly + deps/quicly/deps/picotls are checked
#      out via `git submodule update --init --recursive`. We `add_subdirectory`
#      to build them in-tree.
#   2. System mode (Linux/macOS dev convenience): pkg-config finds quicly +
#      picotls installed by the user. Used as fallback only.
#
# When ext-quic is built as part of cno-cli's top-level CMake, sibling
# targets (`uv_a` from circu.js, `qjs` from circu.js/deps/quickjs,
# `OpenSSL::SSL` from find_package) are reused instead of pkg-config.

set(_QUICLY_SRC "${CMAKE_CURRENT_SOURCE_DIR}/deps/quicly")
set(_PICOTLS_SRC "${_QUICLY_SRC}/deps/picotls")

if(EXISTS "${_QUICLY_SRC}/CMakeLists.txt")
    set(CNO_QUIC_USE_SUBMODULE ON)
    if(NOT EXISTS "${_PICOTLS_SRC}/CMakeLists.txt")
        message(FATAL_ERROR
            "ext-quic: deps/quicly was found but deps/quicly/deps/picotls is missing.\n"
            "Run: cd ext-quic && git submodule update --init --recursive")
    endif()
else()
    set(CNO_QUIC_USE_SUBMODULE OFF)
    message(STATUS "ext-quic: deps/quicly not present — falling back to pkg-config")
endif()

# ─── OpenSSL ────────────────────────────────────────────────────────────────
# find_package handles vcpkg + system installs uniformly.
if(NOT TARGET OpenSSL::SSL)
    find_package(OpenSSL REQUIRED)
endif()

# ─── libuv ──────────────────────────────────────────────────────────────────
# Prefer circu.js's bundled libuv when available (top-level build).
if(TARGET uv_a)
    set(_UV_TARGET uv_a)
elseif(TARGET uv)
    set(_UV_TARGET uv)
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(LIBUV REQUIRED libuv)
    set(_UV_TARGET ${LIBUV_LIBRARIES})
endif()

# ─── quicly + picotls ───────────────────────────────────────────────────────
if(CNO_QUIC_USE_SUBMODULE)
    # Tame quicly's noisy build a bit.
    set(WITH_DTRACE OFF CACHE BOOL "" FORCE)
    set(BUILD_FUZZER OFF CACHE BOOL "" FORCE)

    # picotls comes in via quicly's add_subdirectory(deps/picotls).
    # quicly's CMakeLists creates targets: quicly, picotls-core, picotls-openssl.
    add_subdirectory("${_QUICLY_SRC}" "${CMAKE_CURRENT_BINARY_DIR}/quicly" EXCLUDE_FROM_ALL)

    set(_QUICLY_TARGETS quicly picotls-core picotls-openssl)
    set(_QUICLY_INCLUDES
        "${_QUICLY_SRC}/include"
        "${_PICOTLS_SRC}/include")
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(QUICLY  REQUIRED libquicly)
    pkg_check_modules(PICOTLS REQUIRED libpicotls-core libpicotls-openssl)
    set(_QUICLY_TARGETS  ${QUICLY_LIBRARIES} ${PICOTLS_LIBRARIES})
    set(_QUICLY_INCLUDES ${QUICLY_INCLUDE_DIRS} ${PICOTLS_INCLUDE_DIRS})
endif()

# ─── QuickJS ────────────────────────────────────────────────────────────────
if(NOT DEFINED QUICKJS_INCLUDE_DIR)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(QUICKJS quickjs)
    if(QUICKJS_FOUND)
        set(QUICKJS_INCLUDE_DIR ${QUICKJS_INCLUDE_DIRS})
        set(QUICKJS_LIB         ${QUICKJS_LIBRARIES})
    else()
        message(FATAL_ERROR "QuickJS not found. Pass -DQUICKJS_INCLUDE_DIR=... -DQUICKJS_LIB=...")
    endif()
endif()

# ─── circu.js src for tjs.h ─────────────────────────────────────────────────
if(NOT DEFINED CIRCU_SRC_DIR)
    get_filename_component(_guess "${CMAKE_CURRENT_SOURCE_DIR}/../circu.js/src" ABSOLUTE)
    if(EXISTS "${_guess}/tjs.h")
        set(CIRCU_SRC_DIR "${_guess}")
    else()
        message(WARNING "CIRCU_SRC_DIR not set and tjs.h not found at ${_guess}. "
                        "Pass -DCIRCU_SRC_DIR=<circu.js/src path> to fix.")
    endif()
endif()

# ─── Target ─────────────────────────────────────────────────────────────────
if(CNO_QUIC_SHARED)
    add_library(CNO_QUIC SHARED native.c)
else()
    add_library(CNO_QUIC STATIC native.c)
endif()

target_include_directories(CNO_QUIC
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        ${QUICKJS_INCLUDE_DIR}
        ${_QUICLY_INCLUDES}
    PRIVATE
        ${CIRCU_SRC_DIR}
)

target_link_libraries(CNO_QUIC PUBLIC
    ${_QUICLY_TARGETS}
    OpenSSL::SSL
    OpenSSL::Crypto
    ${_UV_TARGET}
    ${QUICKJS_LIB}
)

target_compile_options(CNO_QUIC PRIVATE
    $<$<NOT:$<C_COMPILER_ID:MSVC>>:-Wall -Wextra -Wno-unused-parameter>
    $<$<CONFIG:MinSizeRel>:$<IF:$<C_COMPILER_ID:MSVC>,/Os,-Os>>
)

include(GNUInstallDirs)
install(TARGETS CNO_QUIC
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(FILES native.h        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/circu)
install(FILES native.d.ts     DESTINATION ${CMAKE_INSTALL_DATADIR}/circu)
