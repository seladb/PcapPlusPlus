ifeq ($(wildcard ../../mk/platform.mk),)
  $(error platform.mk not found! Please run configure script first)
endif

include ../../mk/platform.mk

SOURCES := $(wildcard LightPcapNg/src/*.c)
OBJS_FILENAMES := $(patsubst LightPcapNg/src/%.c,Obj/%.o,$(SOURCES))

INCLUDES := -I"LightPcapNg/include"
			
Obj/%.o: LightPcapNg/src/%.c
	@echo 'Building file: $<'
	@$(GCC) $(INCLUDES) -Wall -O2 -DUNIVERSAL -g -c -o "$@" "$<"

CUR_TARGET := $(notdir $(shell pwd))

.SILENT:

create_light_pcapng_directories:
	@$(MKDIR) -p Obj
	@$(MKDIR) -p Lib

start:
	@echo '==> Building target: $(CUR_TARGET)'

# Sources only
light_pcapng_sources: create_light_pcapng_directories $(OBJS_FILENAMES)

# Sources and static lib
light_pcapng_all: start light_pcapng_sources
	@$(AR) -r  "Lib/light_pcapng.a" $(OBJS_FILENAMES)
	@echo 'Finished successfully building: $(CUR_TARGET)'
	@echo ' '

light_pcapng_clean:
	@$(RM) -rf ./Obj/*
	@$(RM) -rf ./Lib/*
	@echo 'Clean finished: $(CUR_TARGET)'

# Clean target
clean: light_pcapng_clean
