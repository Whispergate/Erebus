CC = x86_64-w64-mingw32-gcc
CFLAGS = -shared -DDLL -fPIC -fno-asynchronous-unwind-tables
INCLUDES = $(PWD) -I/usr/x86_64-w64-mingw32/include
LIBDIRS = -L/usr/x86_64-w64-mingw32/lib
ENTRY_POINT = -e DllMain
LIBS = -lkernel32 -lntdll

OUTPUT_DLL = $(OUTPUT_PATH)/$(DLL_NAME)

SOURCES = main.cpp loader.cpp
OBJECTS = $(SOURCES:.cpp=.o)

DLL_EXPORTS = $(TEMPLATE_PATH)/proxy.def

all: $(OUTPUT_DLL)

%.o: %.cpp
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(OUTPUT_DLL): $(DLL_EXPORTS)
	$(CC) $(CFLAGS) $(INCLUDES) $(LIBDIRS) $(ENTRY_POINT) \
		-o $@ \
		$(DLL_TEMPLATE) \
		$(DLL_EXPORTS) \
		$(LIBS)

clean:
	rm -f $(OBJECTS)

distclean: clean
	rm -f $(OUTPUT_DLL)

.PHONY: all clean distclean

