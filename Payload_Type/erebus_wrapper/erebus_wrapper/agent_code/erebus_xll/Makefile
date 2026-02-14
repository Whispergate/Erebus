# Erebus XLL Payload Cross-Compilation Makefile
# Compiles Windows XLL DLLs from Linux using MinGW-w64
# Usage: make XLL_SOURCE=payload.cpp ARCH=x64
# 
# This Makefile provides cross-platform compilation support for XLL DLLs on Linux
# using MinGW-w64 toolchain.

# Configuration
ARCH ?= x64
OPTIMIZATION ?= Ox
VERBOSE ?= 0
RELEASE ?= 1
UNAME_S := $(shell uname -s)
IS_LINUX := $(filter Linux,$(UNAME_S))
IS_MACOS := $(filter Darwin,$(UNAME_S))

# Default source and output if not specified
XLL_SOURCE ?= xll_payload.cpp
XLL_OUTPUT ?= xll_payload.xll
SRCDIR ?= $(dir $(XLL_SOURCE))
OBJDIR ?= $(if $(SRCDIR),$(SRCDIR),.)

# Compiler configuration with explicit path resolution
ifeq ($(ARCH),x64)
    CC = x86_64-w64-mingw32-gcc
    CXX = x86_64-w64-mingw32-g++
    WINDRES = x86_64-w64-mingw32-windres
    ARCH_FLAGS = -m64
else ifeq ($(ARCH),x86)
    CC = i686-w64-mingw32-gcc
    CXX = i686-w64-mingw32-g++
    WINDRES = i686-w64-mingw32-windres
    ARCH_FLAGS = -m32
else
    $(error Unsupported architecture: $(ARCH). Use x64 or x86)
endif

# Verify compiler availability
check_compiler:
	@command -v $(CXX) >/dev/null 2>&1 || { echo "[-] MinGW-w64 compiler not found: $(CXX)"; exit 1; }

# Optimization levels
ifeq ($(OPTIMIZATION),Ox)
    OPT_FLAGS = -O3 -march=native
else ifeq ($(OPTIMIZATION),O2)
    OPT_FLAGS = -O2
else ifeq ($(OPTIMIZATION),O1)
    OPT_FLAGS = -O1
else ifeq ($(OPTIMIZATION),Od)
    OPT_FLAGS = -O0 -g
else
    OPT_FLAGS = -O2
endif

COMMON_FLAGS = $(ARCH_FLAGS) $(OPT_FLAGS) -fPIC -Wall -Wextra -Wno-unknown-pragmas
CFLAGS = $(COMMON_FLAGS) -std=c11
CXXFLAGS = $(COMMON_FLAGS) -std=c++17

# Include directories with proper ordering
SRCDIR_FULL := $(abspath $(SRCDIR))
CFLAGS += -I$(SRCDIR_FULL)
CXXFLAGS += -I$(SRCDIR_FULL)

EXTRA_LIBS ?=

# DLL linking flags - ensure proper Windows DLL export handling
DLL_FLAGS = -shared -Wall,--out-implib,libxll.a -Wl,--enable-auto-import
LDFLAGS = $(ARCH_FLAGS) -shared -lkernel32 -luser32 -ladvapi32 -lole32 -loleaut32 -lstdc++ $(EXTRA_LIBS)

ifeq ($(RELEASE),1)
	LDFLAGS += -static-libgcc -static-libstdc++ -s
endif

ifeq ($(VERBOSE),1)
    V =
    QUIET =
else
    V = @
    QUIET = > /dev/null 2>&1
endif

OBJECT_FILE = $(OBJDIR)$(patsubst %.cpp,%.o,$(patsubst %.c,%.o,$(notdir $(XLL_SOURCE))))
OUTPUT_DIR = $(dir $(abspath $(XLL_OUTPUT)))

all: check_compiler $(XLL_OUTPUT)

check-deps:
	@echo "[*] Checking XLL compilation dependencies..."
	@command -v x86_64-w64-mingw32-g++ >/dev/null 2>&1 || { echo "[-] MinGW-w64 (x86_64) not found"; exit 1; }
	@command -v i686-w64-mingw32-g++ >/dev/null 2>&1 || { echo "[!] MinGW-w64 (i686) not found - 32-bit compilation may fail"; }
	@echo "[+] MinGW-w64 cross-compiler: FOUND"
	@echo "[+] All critical dependencies available"

install-deps:
	@echo "[*] Installing MinGW-w64 cross-compiler..."
	apt-get update && apt-get install -y mingw-w64 mingw-w64-tools unzip
	@echo "[+] MinGW-w64 and unzip installed"

$(OUTPUT_DIR):
	@mkdir -p "$@"

# Compile C/C++ source to object file with proper header dependencies
$(OBJECT_FILE): $(XLL_SOURCE) | $(OUTPUT_DIR)
	@echo "[*] Compiling $(notdir $(XLL_SOURCE)) -> $(notdir $@) ($(ARCH))..."
	$(V)$(CXX) $(CXXFLAGS) -c "$<" -o "$@" $(QUIET)
	@echo "[+] Compilation successful: $@"

# Link object file to DLL with proper Windows export handling
$(XLL_OUTPUT): $(OBJECT_FILE) | $(OUTPUT_DIR)
	@echo "[+] Linking XLL DLL: $(notdir $(XLL_OUTPUT))..."
	$(V)$(CXX) $(DLL_FLAGS) $(LDFLAGS) -o "$@" "$<" $(QUIET)
	@echo "[+] XLL DLL created successfully: $@"
	@ls -lh "$@"

clean:
	@echo "[*] Cleaning build artifacts..."
	$(V)rm -f "$(OBJECT_FILE)" libxll.a "$(XLL_OUTPUT)"
	@echo "[+] Build artifacts removed"

distclean: clean
	@echo "[*] Complete cleanup done"

help:
	@echo "Erebus XLL Payload Cross-Compilation Makefile"
	@echo "=============================================="
	@echo ""
	@echo "QUICK START (Linux with MinGW-w64):"
	@echo "  2. make check-deps                  - Verify MinGW-w64 is installed"
	@echo "  3. make                             - Compile XLL"
	@echo ""
	@echo "Available Targets:"
	@echo "  make [options]                      - Compile XLL payload (default target)"
	@echo "  make check-deps                     - Verify compilation dependencies"
	@echo "  make install-deps                   - Install MinGW-w64 (Linux/Debian)"
	@echo "  make clean                          - Remove build artifacts"
	@echo "  make distclean                      - Full cleanup"
	@echo "  make help                           - Show this help message"
	@echo ""
	@echo "Build Parameters (via make variable assignment):"
	@echo "  XLL_SOURCE=file.cpp                 - Source C++ file (default: xll_payload.cpp)"
	@echo "  XLL_OUTPUT=file.xll                 - Output XLL file (default: xll_payload.xll)"
	@echo "  SRCDIR=/path/to/src                 - Source directory (auto-detected from XLL_SOURCE)"
	@echo "  ARCH=x64|x86                        - Target architecture (default: x64)"
	@echo "  OPTIMIZATION=Ox|O2|O1|Od            - Optimization level (default: Ox)"
	@echo "  EXTRA_LIBS='-lflag -lflag2'         - Extra linker flags (optional)"
	@echo "  VERBOSE=1                           - Enable verbose output"
	@echo ""
	@echo "Build Examples:"
	@echo "  # Default build with automatic SDK detection"
	@echo "  make"
	@echo ""
	@echo "  # Custom source file"
	@echo "  make XLL_SOURCE=custom.cpp XLL_OUTPUT=custom.xll"
	@echo ""
	@echo "  # 32-bit compilation"
	@echo "  make ARCH=x86 OPTIMIZATION=O2"
	@echo ""
	@echo "  # Verbose compilation with custom libraries"
	@echo "  make VERBOSE=1 EXTRA_LIBS='-lws2_32 -lwsock32'"
	@echo ""
	@echo "Environment:"
	@echo "  - Platform: $(UNAME_S)"
	@echo "  - Compiler: $(CXX)"
	@echo "  - Architecture: $(ARCH)"
	@echo ""
	@echo "Troubleshooting:"
	@echo "  - MinGW-w64 not found: Run 'make install-deps' on Linux/Debian"
	@echo "  - Link errors: Add missing libs with EXTRA_LIBS parameter"
	@echo ""

.PHONY: all clean distclean check-deps install-deps help

.DEFAULT_GOAL := all
