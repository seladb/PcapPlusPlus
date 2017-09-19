ifeq ($(wildcard ../../mk/platform.mk),)
  $(error platform.mk not found! Please run configure script first)
endif

include ../../mk/platform.mk

SOURCES := $(wildcard *.cpp)
OBJS_FILENAMES := $(patsubst %.cpp,%.o,$(SOURCES))

%.o: %.cpp
	@echo 'Building debug-new file: $<'
	@$(GCC) -Wall -O2 -g -c -o "$@" "$<"

debug_new_sources: $(OBJS_FILENAMES)

all: debug_new_sources

clean:
	@$(RM) -rf *.o
	@echo 'Clean finished'
