# Example makefile for CPE 464
#

CC = gcc
CFLAGS = -g -Wall -Werror
OS = $(shell uname -s)
PROC = $(shell uname -p)
EXEC_SUFFIX=$(OS)-$(PROC)

ifeq ("$(OS)", "SunOS")
	OSLIB=-L/opt/csw/lib -R/opt/csw/lib -lsocket -lnsl
	OSINC=-I/opt/csw/include
	OSDEF=-DSOLARIS
else
ifeq ("$(OS)", "Darwin")
	OSLIB=
	OSINC=
	OSDEF=-DDARWIN
else
	OSLIB=
	OSINC=
	OSDEF=-DLINUX
endif
endif

all: fishnode-$(EXEC_SUFFIX)

fishnode-$(EXEC_SUFFIX): fishnode.c
	$(CC) $(CFLAGS) $(OSINC) $(OSLIB) $(OSDEF) -o $@ fishnode.c smartalloc.c libfish-$(EXEC_SUFFIX).a -lpcap

handin: README
	handin bellardo 464_p3 README libfish-Darwin-i386.a libfish-Linux-x86_64.a smartalloc.c fish.h smartalloc.h fishnode.c fishnode.h Makefile

clean:
	-rm -rf fishnode-* fishnode-*.dSYM
