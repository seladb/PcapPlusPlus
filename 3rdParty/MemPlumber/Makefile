ifeq ($(wildcard ../../mk/platform.mk),)
  $(error platform.mk not found! Please run configure script first)
endif

include ../../mk/platform.mk

include Makefile.defs

ifdef ANDROID_TOOLCHAIN
FLAGS := --gcc-toolchain=$(ANDROID_TOOLCHAIN) --sysroot=$(ANDROID_TOOLCHAIN)/sysroot -DANDROID
endif
ifdef ANDROID_TARGET
FLAGS += --target=$(ANDROID_TARGET)
endif

%.o: %.cpp
	@echo Building MemPlumber file: $<
	@$(CC) $(FLAGS) -Wall -O2 -g -c -o "$@" "$<"

CUR_TARGET := $(notdir $(shell pwd))

.SILENT:

all: start memplumber_sources
	@echo Finished successfully building: $(CUR_TARGET)
	@echo ' '

start:
	@echo ==== Building target: $(CUR_TARGET) ====

memplumber_sources: $(MEMPLUMBER_OBJS_FILENAMES)

clean:
	@$(RM) -rf $(MEMPLUMBER_HOME)/MemPlumber/*.o
	@echo Clean finished: $(CUR_TARGET)