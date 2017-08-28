MODULE_NAME = devilish

obj-m += $(MODULE_NAME).o

$(MODULE_NAME)-objs := devilishcalls.o

EXTRA_CFLAGS += -Werror
