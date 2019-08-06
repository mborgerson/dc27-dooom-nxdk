ifeq ($(NXDK_DIR),)
NXDK_DIR = $(shell pwd)
endif

ifeq ($(XBE_TITLE),)
XBE_TITLE = nxdk_app
endif

ifeq ($(OUTPUT_DIR),)
OUTPUT_DIR = bin
endif

ifeq ($(NXDK_STACKSIZE),)
NXDK_STACKSIZE = 65536
endif

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
LD           = lld -flavor link
AS           = clang
CC           = clang
CXX          = clang++
CGC          = $(NXDK_DIR)/tools/cg/linux/cgc
endif
ifeq ($(UNAME_S),Darwin)
LD           = /usr/local/opt/llvm/bin/lld -flavor link
AS           = /usr/local/opt/llvm/bin/clang
CC           = /usr/local/opt/llvm/bin/clang
CXX          = /usr/local/opt/llvm/bin/clang++
CGC          = $(NXDK_DIR)/tools/cg/mac/cgc
endif
ifneq (,$(findstring MSYS_NT,$(UNAME_S)))
$(error Please use a MinGW64 shell)
endif
ifneq (,$(findstring MINGW,$(UNAME_S)))
LD           = lld-link
AS           = clang
CC           = clang
CXX          = clang++
CGC          = $(NXDK_DIR)/tools/cg/win/cgc
endif

TARGET       = $(OUTPUT_DIR)/default.xbe
CXBE         = $(NXDK_DIR)/tools/cxbe/cxbe
VP20COMPILER = $(NXDK_DIR)/tools/vp20compiler/vp20compiler
FP20COMPILER = $(NXDK_DIR)/tools/fp20compiler/fp20compiler
EXTRACT_XISO = $(NXDK_DIR)/tools/extract-xiso/extract-xiso
XBE = $(NXDK_DIR)/tools/xbedump/xbe
TOOLS        = cxbe vp20compiler fp20compiler extract-xiso xbe
NXDK_CFLAGS  = -target i386-pc-win32 -march=pentium3 \
               -ffreestanding -nostdlib -fno-builtin -fno-exceptions \
               -I$(NXDK_DIR)/lib -I$(NXDK_DIR)/lib/xboxrt \
               -isystem $(NXDK_DIR)/lib/pdclib/include \
               -I$(NXDK_DIR)/lib/pdclib/platform/xbox/include \
               -I$(NXDK_DIR)/lib/winapi \
               -Wno-ignored-attributes -DNXDK -D__STDC__=1
NXDK_ASFLAGS = -target i386-pc-win32 -march=pentium3 \
               -nostdlib -I$(NXDK_DIR)/lib -I$(NXDK_DIR)/lib/xboxrt
NXDK_CXXFLAGS = $(NXDK_CFLAGS)

ifeq ($(DEBUG),y)
NXDK_CFLAGS += -g -gdwarf-4
NXDK_CXXFLAGS += -g -gdwarf-4
LDFLAGS += -debug
endif

NXDK_CFLAGS += $(CFLAGS)
NXDK_CXXFLAGS += $(CXXFLAGS)

include $(NXDK_DIR)/lib/Makefile
OBJS = $(addsuffix .obj, $(basename $(SRCS)))

ifneq ($(GEN_XISO),)
TARGET += $(GEN_XISO)
endif

ifneq ($(NXDK_NET),)
include $(NXDK_DIR)/lib/net/Makefile
endif

ifneq ($(NXDK_SDL),)
include $(NXDK_DIR)/lib/sdl/SDL2/Makefile.xbox
include $(NXDK_DIR)/lib/sdl/Makefile
endif

V = 0
VE_0 := @
VE_1 :=
VE = $(VE_$(V))

ifeq ($(V),1)
QUIET=
else
QUIET=>/dev/null
endif

DEPS := $(filter %.c.d, $(SRCS:.c=.c.d))
DEPS += $(filter %.cpp.d, $(SRCS:.cpp=.cpp.d))

all: $(TARGET)

$(OUTPUT_DIR)/default.xbe: main.exe $(OUTPUT_DIR) $(CXBE)
	@echo "[ CXBE     ] $@"
	$(VE)$(CXBE) -OUT:$@ -TITLE:$(XBE_TITLE) $< $(QUIET)

$(OUTPUT_DIR):
	@mkdir -p $(OUTPUT_DIR);

ifneq ($(GEN_XISO),)
$(GEN_XISO): $(OUTPUT_DIR)/default.xbe $(EXTRACT_XISO)
	@echo "[ XISO     ] $@"
	$(VE) $(EXTRACT_XISO) -c $(OUTPUT_DIR) $(XISO_FLAGS) $@ $(QUIET)
endif

$(SRCS): $(SHADER_OBJS)

main.exe: $(OBJS) $(NXDK_DIR)/lib/xboxkrnl/libxboxkrnl.lib
	@echo "[ LD       ] $@"
	$(VE) $(LD) $(LDFLAGS) -subsystem:windows -dll -out:'$@' -entry:XboxCRTEntry -stack:$(NXDK_STACKSIZE) $^

%.obj: %.cpp
	@echo "[ CXX      ] $@"
	$(VE) $(CXX) $(NXDK_CXXFLAGS) -MD -MT '$@' -MF '$(patsubst %.cpp,%.cpp.d,$<)' -c -o '$@' '$<'

%.obj: %.c
	@echo "[ CC       ] $@"
	$(VE) $(CC) $(NXDK_CFLAGS) -MD -MT '$@' -MF '$(patsubst %.c,%.c.d,$<)' -c -o '$@' '$<'

%.obj: %.s
	@echo "[ AS       ] $@"
	$(VE) $(AS) $(NXDK_ASFLAGS) -c -o '$@' '$<'

%.inl: %.vs.cg $(VP20COMPILER)
	@echo "[ CG       ] $@"
	$(VE) $(CGC) -profile vp20 -o $@.$$$$ $< $(QUIET) && \
	$(VP20COMPILER) $@.$$$$ > $@ && \
	rm -rf $@.$$$$

%.inl: %.ps.cg $(FP20COMPILER)
	@echo "[ CG       ] $@"
	$(VE) $(CGC) -profile fp20 -o $@.$$$$ $< $(QUIET) && \
	$(FP20COMPILER) $@.$$$$ > $@ && \
	rm -rf $@.$$$$

tools: $(TOOLS)
.PHONY: tools $(TOOLS)

cxbe: $(CXBE)
$(CXBE):
	@echo "[ BUILD    ] $@"
	$(VE)$(MAKE) -C $(NXDK_DIR)/tools/cxbe $(QUIET)

vp20compiler: $(VP20COMPILER)
$(VP20COMPILER):
	@echo "[ BUILD    ] $@"
	$(VE)$(MAKE) -C $(NXDK_DIR)/tools/vp20compiler $(QUIET)

fp20compiler: $(FP20COMPILER)
$(FP20COMPILER):
	@echo "[ BUILD    ] $@"
	$(VE)$(MAKE) -C $(NXDK_DIR)/tools/fp20compiler $(QUIET)

xbe: $(XBE)
$(XBE):
	@echo "[ BUILD    ] $@"
	$(VE)$(MAKE) -C $(NXDK_DIR)/tools/xbedump $(QUIET)

extract-xiso: $(EXTRACT_XISO)
$(EXTRACT_XISO):
	@echo "[ BUILD    ] $@"
	$(VE)$(MAKE) -C $(NXDK_DIR)/tools/extract-xiso $(QUIET)

.PHONY: clean 
clean:
	$(VE)rm -f $(TARGET) \
	           main.exe main.exe.manifest main.lib \
	           $(OBJS) $(SHADER_OBJS) $(DEPS) \
	           $(GEN_XISO)

.PHONY: distclean 
distclean: clean
	$(VE)$(MAKE) -C $(NXDK_DIR)/tools/extract-xiso clean $(QUIET)
	$(VE)$(MAKE) -C $(NXDK_DIR)/tools/fp20compiler distclean $(QUIET)
	$(VE)$(MAKE) -C $(NXDK_DIR)/tools/vp20compiler distclean $(QUIET)
	$(VE)$(MAKE) -C $(NXDK_DIR)/tools/cxbe clean $(QUIET)
	$(VE)bash -c "if [ -d $(OUTPUT_DIR) ]; then rmdir $(OUTPUT_DIR); fi"

-include $(DEPS)
