ifeq ($(wildcard ../../mk/platform.mk),)
  $(error platform.mk not found! Please run configure script first)
endif

include ../../mk/platform.mk

SOURCES := $(wildcard *.cpp)
OBJS_FILENAMES := $(patsubst %.cpp,%.o,$(SOURCES))

%.o: %.cpp
	@echo 'Building debug-new file: $<'
	@echo 'Invoking: GCC Compiler'
	$(GCC) -Wall -O2 -fPIC -g -c -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

debug_new_sources: $(OBJS_FILENAMES)

all: debug_new_sources

clean:
	$(RM) -rf *.o
	@echo 'Clean finished'
