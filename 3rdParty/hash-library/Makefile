ifeq ($(wildcard ../../mk/platform.mk),)
  $(error platform.mk not found! Please run configure script first)
endif

include ../../mk/platform.mk

SOURCES := $(wildcard *.cpp)
OBJS_FILENAMES := $(patsubst %.cpp,Obj/%.o,$(SOURCES))

INCLUDES := -I"../EndianPortable/include"

DEFS := -DUNIVERSAL -fPIC

Obj/%.o: %.cpp
	@echo Building file: $<
	@$(CXX) $(INCLUDES) -Wall -O2 $(GLOBAL_FLAGS) $(DEFS) -g -c -o "$@" "$<"

CUR_TARGET := $(notdir $(shell pwd))

.SILENT:

create_directories:
	@$(MKDIR) -p Obj
	@$(MKDIR) -p Lib

start:
	@echo ==== Building target: $(CUR_TARGET) ====

# Sources only
hash_library_sources: create_directories $(OBJS_FILENAMES)

# Sources and static lib
hash_library_all: start hash_library_sources
	@$(AR) -r  "Lib/hash_library.a" $(OBJS_FILENAMES)
	@echo Finished successfully building: $(CUR_TARGET)
	@echo ' '

hash_library_clean:
	@$(RM) -rf ./Obj/*
	@$(RM) -rf ./Lib/*
	@echo Clean finished: $(CUR_TARGET)

# Clean target
clean: hash_library_clean
