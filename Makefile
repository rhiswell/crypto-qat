
include $(PWD)/common.mk

OUTPUT_NAME=file_encryptor
USER_SOURCE_FILES += common/cpa_sample_utils.c file_encryptor.c

build_test: rt_utils_test

rt_utils_test: rt_utils_test.c
	$(CC) $(USER_INCLUDES) -DUSER_SPACE $(EXTRA_CFLAGS) $^ $(ADDITIONAL_OBJECTS) -o $@	

