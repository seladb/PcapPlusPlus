ifeq ($(wildcard ../../mk/platform.mk),)
  $(error platform.mk not found! Please run configure script first)
endif

include ../../mk/platform.mk

SOURCES := $(wildcard *.cpp)
OBJS_FILENAMES := $(patsubst %.cpp,%.o,$(SOURCES))

%.o: %.cpp
	@echo 'Building debug-new file: $<'
	@$(GCC) -Wall -O2 -g -c -o "$@" "$<"

CUR_TARGET := $(notdir $(shell pwd))

.SILENT:

all: start debug_new_sources
	@echo 'Finished successfully building: $(CUR_TARGET)'
	@echo ' '

start:
	@echo '==> Building target: $(CUR_TARGET)'

debug_new_sources: $(OBJS_FILENAMES)

clean:
	@$(RM) -rf *.o
	@echo 'Clean finished: $(CUR_TARGET)'
