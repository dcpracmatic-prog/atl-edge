# Makefile for Smart Token Prod native friction core
# Builds libfriction.so (shared library for ctypes) and optional demo.

CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -fPIC -fno-strict-aliasing
LDFLAGS  ?=
PREFIX   ?= /usr/local

# Sanitizer flags (used by dedicated targets / CI)
ASAN_FLAGS = -fsanitize=address,undefined -fno-omit-frame-pointer -g
UBSAN_FLAGS = -fsanitize=undefined -fno-omit-frame-pointer -g

.PHONY: all clean demo install asan ubsan help

all: libfriction.so

libfriction.so: friction_core.cpp friction_core.hpp
	$(CXX) $(CXXFLAGS) -shared -o $@ friction_core.cpp $(LDFLAGS)

demo: main_demo.cpp friction_core.cpp friction_core.hpp
	$(CXX) $(CXXFLAGS) -o friction_demo main_demo.cpp friction_core.cpp $(LDFLAGS)

# Instrumented builds for CI / debugging
asan: CXXFLAGS += $(ASAN_FLAGS)
asan: LDFLAGS  += $(ASAN_FLAGS)
asan: clean libfriction.so

ubsan: CXXFLAGS += $(UBSAN_FLAGS)
ubsan: LDFLAGS  += $(UBSAN_FLAGS)
ubsan: clean libfriction.so

install: libfriction.so
	install -d $(DESTDIR)$(PREFIX)/lib
	install -m 755 libfriction.so $(DESTDIR)$(PREFIX)/lib/

clean:
	rm -f libfriction.so friction_demo

help:
	@echo "Targets:"
	@echo "  all     - build libfriction.so (default)"
	@echo "  demo    - build friction_demo executable"
	@echo "  asan    - rebuild with AddressSanitizer + UBSan"
	@echo "  ubsan   - rebuild with UndefinedBehaviorSanitizer"
	@echo "  install - install libfriction.so to PREFIX (default /usr/local)"
	@echo "  clean   - remove built artifacts"
	@echo ""
	@echo "Variables: CXX, CXXFLAGS, LDFLAGS, PREFIX"
