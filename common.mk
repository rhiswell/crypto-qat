
#Set Upstream code based flags
WITH_UPSTREAM?=1
WITH_CMDRV?=1

#QA API and SAL PATHS
ifndef ICP_ROOT
$(error ICP_ROOT is undefined. Please set the path to the ICP_ROOT)
endif

ICP_API_DIR?=$(ICP_ROOT)/quickassist/include/
ICP_LAC_DIR?=$(ICP_ROOT)/quickassist/lookaside/access_layer/
SAMPLE_PATH?=$(ICP_ROOT)/quickassist/lookaside/access_layer/src/sample_code/functional/
ICP_BUILD_OUTPUT?=$(ICP_ROOT)/build

#ifdef WITH_CMDRV
ifeq ($(WITH_CMDRV),1)
    ifeq ($(WITH_ICP_TARGET),1)
        CMN_ROOT?=$(ICP_ROOT)/quickassist/utilities/libqae_mem/
        CMN_MODULE_NAME?=libqae_mem
    else
        CMN_ROOT?=$(ICP_ROOT)/quickassist/utilities/libusdm_drv/
        CMN_MODULE_NAME?=libusdm_drv
    endif
endif
#endif
CMN_ROOT?=$(ICP_ROOT)/quickassist/lookaside/access_layer/src/sample_code/performance/qae/
CMN_MODULE_NAME?=qaeMemDrv

export CMN_ROOT
export CMN_MODULE_NAME

DO_CRYPTO?=1
ifeq ($(DO_CRYPTO),1)
        EXTRA_CFLAGS+=-DDO_CRYPTO
endif

#include files
INCLUDES += -I$(ICP_API_DIR) \
	-I$(ICP_API_DIR)lac \
	-I$(ICP_API_DIR)dc \
	-I$(ICP_LAC_DIR)include \
	-I$(SAMPLE_PATH)include

#default builds user
ICP_OS_LEVEL?=user_space
OS?=linux
ICP_OS?=linux_2.6
RM=rm -vf
RM-DIR=rm -rfv

ifeq ($(ICP_OS_LEVEL),user_space)
#############################################################
#
# Build user space executible
#
############################################################
ADDITIONAL_OBJECTS += -L/usr/Lib -L$(ICP_BUILD_OUTPUT) 

ifeq ($(WITH_UPSTREAM),1)
    ifeq ($(WITH_ICP_TARGET),1)
        ADDITIONAL_OBJECTS += $(ICP_BUILD_OUTPUT)/libicp_qa_al_s.so
    else
        ADDITIONAL_OBJECTS += $(ICP_BUILD_OUTPUT)/libqat_s.so
    endif
else
        ADDITIONAL_OBJECTS += $(ICP_BUILD_OUTPUT)/libicp_qa_al_s.so
endif

ifeq ($(WITH_CMDRV),1)
	ADDITIONAL_OBJECTS += $(CMN_ROOT)/$(OS)/build/$(ICP_OS)/user_space/$(CMN_MODULE_NAME).a
endif

ADDITIONAL_OBJECTS += -lpthread -lcrypto

ifeq ($(WITH_UPSTREAM),1)
        EXTRA_CFLAGS+=-DWITH_UPSTREAM
        ADDITIONAL_OBJECTS += -ludev
endif

USER_INCLUDES= $(INCLUDES)
USER_INCLUDES+= -I$(CMN_ROOT)/
ifeq ($(WITH_CMDRV),1)
	EXTRA_CFLAGS+=-DWITH_CMDRV
else
USER_SOURCE_FILES += $(CMN_ROOT)/$(OS)/user_space/qae_mem_utils.c
endif

ifdef SYSROOT
EXTRA_CFLAGS += --sysroot=$(SYSROOT)
endif

default: clean
	$(CC) -Wall -O1 $(USER_INCLUDES)  -DUSER_SPACE $(EXTRA_CFLAGS) \
	$(USER_SOURCE_FILES) $(ADDITIONAL_OBJECTS) -o $(OUTPUT_NAME)

clean:
	$(RM) *.o $(OUTPUT_NAME)
else
#############################################################
#
# Build kernel space module
#
############################################################
EXTRA_CFLAGS+=$(INCLUDES)
KBUILD_EXTRA_SYMBOLS += $(SAMPLE_PATH)/../../Module.symvers
export $(KBUILD_EXTRA_SYMBOLS)

default: clean
	$(MAKE) -C $(KERNEL_SOURCE_ROOT) M=$(PWD) modules

clean:
	$(RM) *.mod.* *.ko *.o *.a
	$(RM) modules.order Module.symvers .*.*.*
	$(RM-DIR) .tmp_versions
endif
