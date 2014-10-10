#
# Makefile for BFD protocol application
#

OUTDIR = build
AVL_TARFILE = src/core/avl-1.4.0.tar.gz
AVL_DIR = $(OUTDIR)/avl-1.4.0

CC = cc
RANLIB = ranlib

GEN_CFLAGS = -g -Wall -Wconversion -Werror
GEN_CFLAGS += $(shell pkg-config --cflags json-c)

INC = -Isrc/inc -I$(AVL_DIR)
override CFLAGS := $(GEN_CFLAGS) $(INC) $(CFLAGS)
CC_LINK = $(CC) -L$(OUTDIR) -L$(AVL_DIR)

LIBS = -lavl
LIBS += $(shell pkg-config --libs json-c)

EXE_FILES  = $(OUTDIR)/bfd
EXE_FILES += $(OUTDIR)/bfdd
EXE_FILES += $(OUTDIR)/bfdmontest

LIB_FILES  = $(OUTDIR)/libbfdmon.a

TARFILE = bfd.tar.gz

DEPDIR := $(OUTDIR)/.deps
GEN_DEPS = -Wp,-M,-MP,-MT,$@,-MF,$(DEPDIR)/$(*F).d

# Use 'make V=1' to see compile command.
ifeq ("$(V)", "1")
    Q =
else
    Q = @
endif

SRCDIRS := core
SRCDIRS += monitor
SRCDIRS += bfd
SRCDIRS += bfdd
SRCDIRS += libbfdmon
SRCDIRS += bfdmontest

define do_include
  SRCS :=
  include src/$(1)/make.mk
  $(1)_SRCS := $$(SRCS)
  $(1)_OBJS := $$($(1)_SRCS:%.c=$(OUTDIR)/%.o)
endef

$(foreach srcdir,$(SRCDIRS),$(eval $(call do_include,$(srcdir))))

EMPTY :=
SPACE := $(EMPTY) $(EMPTY)

VPATH = $(subst $(SPACE),:,$(addprefix src/,$(SRCDIRS)))

$(OUTDIR)/%.o: %.c
	@echo CC $@
	@$(CC) $(CFLAGS) -E $(GEN_DEPS) -o /dev/null $< || exit 0
	$(Q)$(CC) $(CFLAGS) -c -o $@ $<

.DEFAULT_GOAL:=all
.PHONY: all
all: $(AVL_DIR)/libavl.a $(EXE_FILES)

$(AVL_DIR)/README:
	mkdir -p $(OUTDIR)
	tar -C $(OUTDIR) -xvzf $(AVL_TARFILE)

$(AVL_DIR)/libavl.a: $(AVL_DIR)/README
	cd $(AVL_DIR) && ./configure && make

$(OUTDIR)/bfd: $(core_OBJS) $(bfd_OBJS)
	@echo "LINK $@"
	$(Q)$(CC_LINK) -o $@ $^ $(LIBS)

$(OUTDIR)/bfdd: $(core_OBJS) $(monitor_OBJS) $(bfdd_OBJS)
	@echo "LINK $@"
	$(Q)$(CC_LINK) -o $@ $^ $(LIBS) -lconfig

$(OUTDIR)/libbfdmon.a: $(libbfdmon_OBJS)
	@rm -rf $@
	@echo AR $@
	$(Q)$(AR) cru $@ $(libbfdmon_OBJS)
	$(Q)$(RANLIB) $@

$(OUTDIR)/bfdmontest: $(bfdmontest_OBJS) $(core_OBJS) $(OUTDIR)/libbfdmon.a
	@echo "LINK $@"
	$(Q)$(CC_LINK) -o $@ $(bfdmontest_OBJS) $(core_OBJS) -lbfdmon $(LIBS)

clean:
	rm -f $(OUTDIR)/*.o $(EXE_FILES)

realclean:
	rm -rf $(OUTDIR) *~ *.bak

showvar:
	@echo $(var)=$($(var))

-include $(shell mkdir -p $(DEPDIR) 2>/dev/null) $(wildcard $(DEPDIR)/*)
