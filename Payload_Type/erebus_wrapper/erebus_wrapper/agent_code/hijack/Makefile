CXX = x86_64-w64-mingw32-g++
CXXFLAGS = -shared -DDLL -fPIC -fno-asynchronous-unwind-tables -static-libgcc -static-libstdc++
INCLUDES = -I. -I/usr/x86_64-w64-mingw32/include
LIBDIRS = -L/usr/x86_64-w64-mingw32/lib
ENTRY_POINT = -e DllMain
LIBS = -lkernel32 -lntdll

OUTPUT_DLL = $(OUTPUT_PATH)/$(DLL_NAME)

SOURCES = main.cpp loader.cpp
OBJECTS = $(SOURCES:.cpp=.o)

DLL_EXPORTS = $(TEMPLATE_PATH)/proxy.def

all: $(OUTPUT_DLL)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

$(OUTPUT_DLL): $(OBJECTS) $(DLL_EXPORTS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(LIBDIRS) $(ENTRY_POINT) \
		-o $@ \
		$(OBJECTS) \
		$(DLL_EXPORTS) \
		$(LIBS)

clean:
	rm -f $(OBJECTS)

distclean: clean
	rm -f $(OUTPUT_DLL)

.PHONY: all clean distclean