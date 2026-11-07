LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := dobby
LOCAL_SRC_FILES := libraries/$(TARGET_ARCH_ABI)/libdobby.a
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE    := standcore
LOCAL_CFLAGS    := -w -fvisibility=hidden -fexceptions -O2
LOCAL_CPPFLAGS  := -w -fvisibility=hidden -std=c++17 -fexceptions -O2
LOCAL_LDLIBS    := -llog
LOCAL_STATIC_LIBRARIES := dobby
LOCAL_SRC_FILES := standcore.cpp
include $(BUILD_SHARED_LIBRARY)
