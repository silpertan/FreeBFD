#
# Makefile for BFD protocol application
#

AVL_TARFILE = avl-1.4.0.tar.gz
AVL_DIR = avl-1.4.0

CC = cc
GEN_CFLAGS = -g -Wall
INCDIRS = -I. -I$(AVL_DIR)
CFLAGS = $(GEN_CFLAGS) $(INCDIRS)
CC_LINK = $(CC)
LIBS = -Lavl-1.4.0 -lavl

OBJS = bfd.o tp-timers.o
EXE_FILES = bfdd
SRCS = bfd.c tp-timers.c
INCS = bfd.h tp-timers.h
TARFILE = bfd.tar.gz

.c.o:
	$(CC) $(CFLAGS) -c $<

all:	avl $(EXE_FILES)

avl:
	@(test -d $(AVL_DIR) || ( \
		echo "Making AVL library ..."; \
		tar xvfz $(AVL_TARFILE); \
		(cd $(AVL_DIR); \
			./configure; \
			make; \
		); \
		echo "make depend ..."; \
		make depend; \
	))

bfdd:	$(OBJS)
	$(CC_LINK) -o bfdd $(OBJS) $(LIBS)

clean:
	rm -f *.o $(EXE_FILES)

realclean:
	rm -rf *.o $(EXE_FILES) $(AVL_DIR) *~ *.bak $(TARFILE)

tarfile:
	tar cvfz $(TARFILE) $(SRCS) $(INCS) Makefile $(AVL_TARFILE)

depend:
	makedepend -- $(CFLAGS) -- $(SRCS)
# DO NOT DELETE

bfd.o: /usr/include/stdio.h /usr/include/features.h /usr/include/sys/cdefs.h
bfd.o: /usr/include/gnu/stubs.h
bfd.o: /usr/lib/gcc-lib/i486-suse-linux/2.95.3/include/stddef.h
bfd.o: /usr/include/bits/types.h /usr/include/libio.h
bfd.o: /usr/include/_G_config.h /usr/include/wchar.h
bfd.o: /usr/include/bits/wchar.h /usr/include/gconv.h
bfd.o: /usr/lib/gcc-lib/i486-suse-linux/2.95.3/include/stdarg.h
bfd.o: /usr/include/bits/stdio_lim.h /usr/include/stdlib.h
bfd.o: /usr/include/unistd.h /usr/include/bits/posix_opt.h
bfd.o: /usr/include/bits/confname.h /usr/include/netdb.h
bfd.o: /usr/include/netinet/in.h /usr/include/stdint.h
bfd.o: /usr/include/bits/wordsize.h /usr/include/bits/socket.h
bfd.o: /usr/include/limits.h
bfd.o: /usr/lib/gcc-lib/i486-suse-linux/2.95.3/include/limits.h
bfd.o: /usr/include/sys/types.h /usr/include/time.h
bfd.o: /usr/include/bits/sockaddr.h /usr/include/asm/socket.h
bfd.o: /usr/include/asm/sockios.h /usr/include/bits/in.h
bfd.o: /usr/include/endian.h /usr/include/bits/endian.h
bfd.o: /usr/include/bits/byteswap.h /usr/include/bits/netdb.h
bfd.o: /usr/include/signal.h /usr/include/bits/sigset.h
bfd.o: /usr/include/bits/signum.h /usr/include/sys/socket.h
bfd.o: /usr/include/sys/uio.h /usr/include/bits/uio.h
bfd.o: /usr/include/arpa/inet.h bfd.h /usr/include/syslog.h
bfd.o: /usr/include/sys/syslog.h tp-timers.h
tp-timers.o: /usr/include/unistd.h /usr/include/features.h
tp-timers.o: /usr/include/sys/cdefs.h /usr/include/gnu/stubs.h
tp-timers.o: /usr/include/bits/posix_opt.h /usr/include/bits/types.h
tp-timers.o: /usr/lib/gcc-lib/i486-suse-linux/2.95.3/include/stddef.h
tp-timers.o: /usr/include/bits/confname.h /usr/include/errno.h
tp-timers.o: /usr/include/bits/errno.h /usr/include/linux/errno.h
tp-timers.o: /usr/include/asm/errno.h /usr/include/string.h
tp-timers.o: /usr/include/signal.h /usr/include/bits/sigset.h
tp-timers.o: /usr/include/bits/signum.h /usr/include/sys/types.h
tp-timers.o: /usr/include/time.h /usr/include/sys/time.h
tp-timers.o: /usr/include/bits/time.h /usr/include/sys/select.h
tp-timers.o: /usr/include/bits/select.h avl-1.4.0/avl.h tp-timers.h
tp-timers.o: /usr/include/stdint.h /usr/include/bits/wchar.h
tp-timers.o: /usr/include/bits/wordsize.h
