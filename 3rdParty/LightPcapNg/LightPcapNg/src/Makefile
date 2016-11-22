ROOT_DIR = ..
INCLUDE = $(ROOT_DIR)/include
HEADERS = $(INCLUDE)/light_pcapng.h $(INCLUDE)/light_special.h $(INCLUDE)/light_debug.h \
	$(INCLUDE)/light_platform.h $(INCLUDE)/light_internal.h $(INCLUDE)/light_util.h $(INCLUDE)/light_types.h
SOURCES = light_io.c light_pcapng.c light_pcapng_cont.c light_platform.c light_manipulate.c light_internal.c light_alloc.c \
	light_advanced.c light_option.c
OBJECTS = $(SOURCES:.c=.o)
PRECOMPILED = $(HEADERS:.h=.gch)

TESTS = tests/test_read.c tests/test_read_write.c tests/test_mem.c tests/test_histogram.c tests/test_subcapture.c \
	tests/test_feature.c tests/test_flow.c tests/test_feature_advanced.c
TESTE = $(TESTS:.c=.test)

LDFLAGS = -ldl
INCLUDES = -I$(ROOT_DIR)/include
DEBUG = -g -p -ggdb -D_DEBUG
CFLAGS = -Wall -O2 -fPIC -DUNIVERSAL -g
# CFLAGS += $(DEBUG)
# LDFLAGS += $(DEBUG)

all: liblight_pcapng.so liblight_pcapng.a $(TESTE)

%.o: %.c $(HEADERS)
	$(CC) $^ -c $(CFLAGS) $(INCLUDES)

tests/%.test: tests/%.c liblight_pcapng.a
	$(CC) $^ -o $@ $(CFLAGS) $(INCLUDES) $(LDFLAGS)

liblight_pcapng.so: $(OBJECTS)
	$(CC) $^ -shared -o $@ $(LDFLAGS)

liblight_pcapng.a: $(OBJECTS)
	$(AR) rc $@ $^
	
clean:
	rm -rf $(TESTE) $(OBJECTS) $(PRECOMPILED) liblight_pcapng.a liblight_pcapng.so
