#
# Makefile for BFD protocol application
#

AVL_TARFILE = avl-1.4.0.tar.gz
AVL_DIR = avl-1.4.0

CC = cc
GEN_CFLAGS = -g -Wall -Wconversion -Werror
INCDIRS = -I. -I$(AVL_DIR)
override CFLAGS := $(GEN_CFLAGS) $(INCDIRS) $(CFLAGS)
CC_LINK = $(CC)
LIBS = -Lavl-1.4.0 -lavl

EXE_FILES = bfd

SRCS := bfd.c
SRCS += tp-timers.c
SRCS += bfd-main.c

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

bfd: $(OBJS)
	@echo "LINK $@"
	$(Q)$(CC_LINK) -o $@ $(OBJS) $(LIBS)

clean:
	rm -f *.o $(EXE_FILES)

realclean:
	rm -rf *.o $(EXE_FILES) $(AVL_DIR) *~ *.bak $(TARFILE)

tarfile:
	tar cvfz $(TARFILE) $(SRCS) $(INCS) Makefile $(AVL_TARFILE)

-include $(shell mkdir .deps 2>/dev/null) $(wildcard .deps/*)
