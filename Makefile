# --- Configuration ---
NPROCS      := 1
OS          := $(shell uname -s)

# Set NPROCS based on the operating system
ifeq ($(OS),Linux)
    NPROCS := $(shell grep -c ^processor /proc/cpuinfo)
endif
ifeq ($(OS),Darwin) # Added for macOS support
    NPROCS := $(shell sysctl -n hw.ncpu)
endif

# Compiler selection (defaults to clang++)
CXX ?= clang++

# --- Flags ---
# CXXFLAGS: Flags for the C++ compiler (optimization, language standard)
ifeq ($(DEBUG),1)
CXXFLAGS   = -std=c++17 -O0 -g
BOCHS_CXXFLAGS = -O0 -g
else
CXXFLAGS   = -std=c++17 -O3 -g
BOCHS_CXXFLAGS = -O3 -g
endif

# CPPFLAGS: Preprocessor flags (include paths)
CPPFLAGS   = -I vendor/bochs \
             -I vendor/bochs/gui \
             -I vendor/include \
             -I vendor/robin-map/include

# LDFLAGS: Flags for the linker (e.g., PIE for executables)
LDFLAGS    = -fPIE

# LDLIBS: The libraries to link against.
LDLIBS     = -lrt -ldl -lpthread -lsqlite3 -lstdc++fs -lcrypto

# SANITIZE_FLAGS: Flags needed for BOTH compilation and linking for sanitizers.
SANITIZE_FLAGS = 

# --- Source Files and Libraries ---
# List of object files to be created
OBJS       = main.o \
             regs.o \
             breakpoints.o \
             db.o \
             manual_ranges.o \
             instrument.o \
             feedback.o \
             fuzz.o \
             conveyor.o \
             symbolize.o \
             sym2addr_linux.o \
             link_map.o \
             ept.o \
             cov.o \
             vmcs.o \
             enum.o \
             sourcecov.o \
             gdbstub.o \
             task.o \
             virtio.o \
			 mutate.o \
             gcov.o \
             gcov_base.o \
             bochsapi/logfunctions.o \
             devices.o \
             bochsapi/system.o \
             bochsapi/mem.o \
             bochsapi/siminterface.o \
             bochsapi/paramtree.o \
             bochsapi/gui.o \
             bochsapi/apic.o \
             bochsapi/dbg.o

VENDOR_LIBS = vendor/lib/libdebug.a vendor/lib/libcpu.a vendor/lib/libcpudb.a \
              vendor/lib/libavx.a vendor/lib/libfpu.a vendor/libfuzzer-ng/libFuzzer.a \
              vendor/lib/pc_system.o
VENDOR_OBJS =

# --- Targets ---

.PHONY: all clean rebuild_bochs tests

# Default target
all: fuzz

# The main executable linking rule
fuzz: rebuild_bochs $(OBJS) $(VENDOR_LIBS) vendor/libfuzzer-ng/libFuzzer.a
	@echo "===> Linking executable: fuzz"
	$(CXX) $(LDFLAGS) $(SANITIZE_FLAGS) -o $@ $(OBJS) $(VENDOR_OBJS) $(VENDOR_LIBS) $(LDLIBS)

# Generic rule for compiling .cc files into .o files
%.o: %.cc
	@echo "===> Compiling $<"
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(SANITIZE_FLAGS) -c -o $@ $<

vendor/libfuzzer-ng/libFuzzer.a:
	@echo "===> Building libFuzzer-ng"
	cd vendor/libfuzzer-ng/; DEBUG=$(DEBUG) ./build.sh

rebuild_bochs:
	@echo "===> Building Bochs"
	mkdir -p vendor/bochs-build vendor/lib vendor/include
	cd vendor/bochs-build; test -f config.h || CXXFLAGS="$(BOCHS_CXXFLAGS)" ../bochs/configure \
		--enable-vmx=2 --with-vncsrv --enable-x86-64 --enable-e1000 \
		--without-x --without-x11 --without-win32 --without-macos \
		--enable-cpu-level=6 --enable-pci --without-gui --enable-pnic \
		--enable-fast-function-calls --enable-fpu --enable-cdrom \
		--enable-avx --enable-evex --disable-docbook --enable-instrumentation --with-nogui \
		--enable-gdb-stub
	cd vendor/bochs-build; make -j $(NPROCS)
	cp ./vendor/bochs-build/cpu/cpudb/libcpudb.a vendor/lib/
	cp ./vendor/bochs-build/cpu/libcpu.a vendor/lib/
	cp ./vendor/bochs-build/cpu/fpu/libfpu.a vendor/lib/
	cp ./vendor/bochs-build/cpu/avx/libavx.a vendor/lib/
	cp ./vendor/bochs-build/config.h vendor/include/
	cp ./vendor/bochs-build/pc_system.o vendor/lib/pc_system.o
	cp ./vendor/bochs/instrument/stubs/instrument.h vendor/include/
	cd vendor/bochs-build; make -j bx_debug/libdebug.a
	cp ./vendor/bochs-build/bx_debug/libdebug.a vendor/lib/

# This target rebuilds each test from scratch with sanitizers enabled
tests: rebuild_bochs $(OBJS) $(VENDOR_LIBS) vendor/libfuzzer-ng/libFuzzer.a
	@echo "===> Building tests"
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(SANITIZE_FLAGS) -I. tests/cve-2021-3947.cc $(OBJS) $(VENDOR_OBJS) $(VENDOR_LIBS) $(LDFLAGS) $(LDLIBS) -o tests/cve-2021-3947
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(SANITIZE_FLAGS) -I. tests/cve-2022-0216.cc $(OBJS) $(VENDOR_OBJS) $(VENDOR_LIBS) $(LDFLAGS) $(LDLIBS) -o tests/cve-2022-0216

clean:
	@echo "===> Cleaning up"
	rm -rf vendor/bochs-build vendor/lib vendor/include vendor/libfuzzer-ng/libFuzzer.a
	rm -f bochsapi/*.o
	rm -f ./*.o