LOCAL_PATH := $(my-dir)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := \
	ELF.cpp \
	Config.cpp \
	SharedObject.cpp \
	Process.cpp \
	Logger.cpp \
	Decoder.cpp \
	Hook.cpp \
	main.cpp

LOCAL_C_INCLUDES += \
	$(LOCAL_PATH)/include \
	$(ARMHOOK_ROOT_PATH)/deps/libjansson/src \
	$(ARMHOOK_ROOT_PATH)/deps/libjansson/android \
	bionic \
	bionic/libstdc++/include \
	external/stlport/stlport

LOCAL_MODULE_TAGS := optional
LOCAL_SHARED_LIBRARIES := libstlport libjansson
LOCAL_CFLAGS += -std=c++11 -Wall -Wextra

LOCAL_MODULE:= armhook
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_ARM_MODE := arm

LOCAL_SRC_FILES := \
	helper/main.c \
	helper/trampoline.S

LOCAL_C_INCLUDES += \
	$(LOCAL_PATH)/helper

LOCAL_MODULE_TAGS := optional
LOCAL_SHARED_LIBRARIES :=
LOCAL_CFLAGS += -Wall -Wextra
LOCAL_LDFLAGS := -Wl,--no-warn-shared-textrel

LOCAL_MODULE := libarmhook
include $(BUILD_SHARED_LIBRARY)
