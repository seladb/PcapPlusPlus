ifeq ($(wildcard ../../mk/platform.mk),)
  $(error platform.mk not found! Please run configure script first)
endif

include ../../mk/platform.mk

SOURCES := $(wildcard LightPcapNg/src/*.c)
OBJS_FILENAMES := $(patsubst LightPcapNg/src/%.c,Obj/%.o,$(SOURCES))

INCLUDES := -I"LightPcapNg/include"
			
Obj/%.o: LightPcapNg/src/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC Compiler'
	$(GCC) $(INCLUDES) -Wall -O2 -fPIC -DUNIVERSAL -g -c -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

create_light_pcapng_directories:
	$(MKDIR) -p Obj
	$(MKDIR) -p Lib

# Sources only
light_pcapng_sources: create_light_pcapng_directories $(OBJS_FILENAMES)

# Sources and static lib
light_pcapng_all: light_pcapng_sources
	@echo 'Building target: $@'
	@echo 'Invoking: GCC Archiver'
	$(AR) -r  "Lib/light_pcapng.a" $(OBJS_FILENAMES)
	@echo 'Finished successfully building target: $@'
	@echo ' '

light_pcapng_clean:
	$(RM) -rf ./Obj/*
	$(RM) -rf ./Lib/*
	@echo 'Clean finished'

# Clean target
clean: light_pcapng_clean
