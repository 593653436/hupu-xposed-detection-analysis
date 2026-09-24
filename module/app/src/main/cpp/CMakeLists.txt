cmake_minimum_required(VERSION 3.22.1)

project(hupushield C)

set(CMAKE_C_STANDARD 11)

add_library(hupushield SHARED
        hupushield.c
        xhook/xhook.c
        xhook/xh_core.c
        xhook/xh_elf.c
        xhook/xh_log.c
        xhook/xh_util.c
        xhook/xh_version.c)

target_include_directories(hupushield PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/xhook
        ${CMAKE_CURRENT_SOURCE_DIR}/shadowhook_inc)

find_library(log-lib log)

target_link_libraries(hupushield
        ${log-lib}
        dl)

# ---------------------------------------------------------------------------
# ShadowHook (MIT, bytedance/android-inline-hook) — runtime dlopen, NOT linked.
#
# Inline hooking is what this project was missing: Yidun reaches its syscalls
# through raw `svc #0` thunks, so PLT/GOT patching (xHook) can never see them, and
# its tripwires are armed from within libnesec's own constructors — i.e. before
# dlopen returns. ShadowHook replaces the target function body itself, so when the
# hook is installed stops mattering.
#
# Deliberately absent from target_link_libraries: putting it in DT_NEEDED broke the
# module outright. ART probes the entry point with dlsym(handle, "JNI_OnLoad"), and
# that lookup walks the dependency chain — so it found the JNI_OnLoad exported by
# libshadowhook.so (which returns JNI_ERR) and rejected libhupushield.so with
#   "JNI_ERR returned from JNI_OnLoad in .../libhupushield.so"
# before a single line of our own code had run. hupushield.c dlopen()s it instead.
#
# Only arm64-v8a ships, matching the device and the module's abiFilters.
# ---------------------------------------------------------------------------
if(ANDROID_ABI STREQUAL "arm64-v8a" AND
        EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../jniLibs/${ANDROID_ABI}/libshadowhook.so")
    target_compile_definitions(hupushield PRIVATE HS_HAVE_SHADOWHOOK=1)
endif()
