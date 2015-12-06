LOCAL_PATH:=$(call my-dir)/src
include $(CLEAR_VARS)

LOCAL_CFLAGS:=-std=c99 -O3

LOCAL_MODULE:=pixiewps
LOCAL_SRC_FILES:=pixiewps.c random_r.c crypto/sha256.c crypto/md.c crypto/md_wrap.c

include $(BUILD_EXECUTABLE)
