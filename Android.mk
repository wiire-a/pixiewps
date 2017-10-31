LOCAL_PATH:=$(call my-dir)/src
include $(CLEAR_VARS)

LOCAL_CFLAGS:=-std=c99 -O3

LOCAL_MODULE:=pixiewps
LOCAL_SRC_FILES:=pixiewps.c mbedtls/sha256.c mbedtls/md.c mbedtls/md_wrap.c

include $(BUILD_EXECUTABLE)
