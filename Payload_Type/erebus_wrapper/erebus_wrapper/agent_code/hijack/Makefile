# Makefile for DLL Hijacking Payload Compilation
# Compiles all source files in the hijack directory into a DLL with proxying support

# Compiler and flags
CC = x86_64-w64-mingw32-gcc
CFLAGS = -shared -DDLL -fPIC -fno-asynchronous-unwind-tables
INCLUDES = -I/usr/x86_64-w64-mingw32/include
LIBDIRS = -L/usr/x86_64-w64-mingw32/lib
ENTRY_POINT = -e DllMain
LIBS = -lkernel32 -lntdll

# Output
OUTPUT_DLL = $(OUTPUT_PATH)/$(DLL_NAME)

# Source files - all C++ files in hijack directory
SOURCES = dll_hijack.cpp loader.cpp
OBJECTS = $(SOURCES:.cpp=.o)

# Template files for DLL proxying
DLL_TEMPLATE = $(TEMPLATE_PATH)/dll_template.cpp
DLL_EXPORTS = $(TEMPLATE_PATH)/proxy.def

# Default target
all: $(OUTPUT_DLL)

# Compile object files with mingw flags
%.o: %.cpp
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Link DLL from template, exports, and object files
$(OUTPUT_DLL): $(DLL_TEMPLATE) $(DLL_EXPORTS)
	$(CC) $(CFLAGS) $(INCLUDES) $(LIBDIRS) $(ENTRY_POINT) \
		-o $@ \
		$(DLL_TEMPLATE) \
		$(DLL_EXPORTS) \
		$(LIBS)

# Clean up object files
clean:
	rm -f $(OBJECTS)

# Clean all (including output)
distclean: clean
	rm -f $(OUTPUT_DLL)

.PHONY: all clean distclean

