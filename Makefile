#
# Makefile for BFD protocol application
#

AVL_TARFILE = avl-1.4.0.tar.gz
AVL_DIR = avl-1.4.0

CC = cc

GEN_CFLAGS = -g -Wall -Wconversion -Werror
GEN_CFLAGS += $(shell pkg-config --cflags json-c)

INCDIRS = -I. -I$(AVL_DIR)
override CFLAGS := $(GEN_CFLAGS) $(INCDIRS) $(CFLAGS)
CC_LINK = $(CC)

LIBS = -Lavl-1.4.0 -lavl
LIBS += $(shell pkg-config --libs json-c)

EXE_FILES = bfd bfdd

SRCS := bfd.c
SRCS += bfd-monitor.c
SRCS += tp-timers.c

OBJS := $(SRCS:%.c=%.o)
INCS := $(SRCS:%.c=%.h)

TARFILE = bfd.tar.gz

GEN_DEPS = -Wp,-M,-MP,-MT,$@,-MF,.deps/$(*F).d

# Use 'make V=1' to see compile command.
ifeq ("$(V)", "1")
    Q =
else
    Q = @
endif

%.o: %.c
	@echo CC $@
	@$(CC) $(CFLAGS) -E $(GEN_DEPS) -o /dev/null $< || exit 0
	$(Q)$(CC) $(CFLAGS) -c -o $@ $<

all: $(AVL_DIR)/libavl.a $(EXE_FILES)

$(AVL_DIR)/README:
	tar xvfz $(AVL_TARFILE)

$(AVL_DIR)/libavl.a: $(AVL_DIR)/README
	(cd $(AVL_DIR); ./configure; make)

bfd: $(OBJS) bfd-main.o
	@echo "LINK $@"
	$(Q)$(CC_LINK) -o $@ $(OBJS) bfd-main.o $(LIBS)

bfdd: $(OBJS) bfdd-main.o
	@echo "LINK $@"
	$(Q)$(CC_LINK) -o $@ $(OBJS) bfdd-main.o $(LIBS) -lconfig

clean:
	rm -f *.o $(EXE_FILES)

realclean:
	rm -rf *.o $(EXE_FILES) $(AVL_DIR) *~ *.bak $(TARFILE)

tarfile:
	tar cvfz $(TARFILE) $(SRCS) bfd-main.c bfdd-main.c$(INCS) Makefile $(AVL_TARFILE)

-include $(shell mkdir .deps 2>/dev/null) $(wildcard .deps/*)
