# makedumpfile

VERSION=1.6.5
DATE=5 Dec 2018

# Honour the environment variable CC
ifeq ($(strip $CC),)
CC	= gcc
endif

CFLAGS = -g -O2 -Wall -D_FILE_OFFSET_BITS=64 \
	  -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE \
	  -DVERSION='"$(VERSION)"' -DRELEASE_DATE='"$(DATE)"'
CFLAGS_ARCH	= -g -O2 -Wall -D_FILE_OFFSET_BITS=64 \
		    -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE
# LDFLAGS = -L/usr/local/lib -I/usr/local/include

HOST_ARCH := $(shell uname -m)
# Use TARGET as the target architecture if specified.
# Defaults to uname -m
ifeq ($(strip($TARGET)),)
TARGET := $(HOST_ARCH)
endif

ARCH := $(shell echo ${TARGET}  | sed -e s/i.86/x86/ -e s/sun4u/sparc64/ \
			       -e s/arm.*/arm/ -e s/sa110/arm/ \
			       -e s/s390x/s390/ -e s/parisc64/parisc/ \
			       -e s/ppc64/powerpc64/ -e s/ppc/powerpc32/)

CROSS :=
ifneq ($(TARGET), $(HOST_ARCH))
CROSS := -U__$(HOST_ARCH)__
endif

CFLAGS += -D__$(ARCH)__ $(CROSS)
CFLAGS_ARCH += -D__$(ARCH)__ $(CROSS)

ifeq ($(ARCH), powerpc64)
CFLAGS += -m64
CFLAGS_ARCH += -m64
endif

ifeq ($(ARCH), powerpc32)
CFLAGS += -m32
CFLAGS_ARCH += -m32
endif

SRC_BASE = makedumpfile.c makedumpfile.h diskdump_mod.h sadump_mod.h sadump_info.h
SRC_PART = print_info.c dwarf_info.c elf_info.c erase_info.c sadump_info.c cache.c tools.c
OBJ_PART=$(patsubst %.c,%.o,$(SRC_PART))
SRC_ARCH = arch/arm.c arch/arm64.c arch/x86.c arch/x86_64.c arch/ia64.c arch/ppc64.c arch/s390x.c arch/ppc.c arch/sparc64.c
OBJ_ARCH=$(patsubst %.c,%.o,$(SRC_ARCH))

LIBS = -ldw -lbz2 -lebl -ldl -lelf -lz
ifneq ($(LINKTYPE), dynamic)
LIBS := -static $(LIBS)
endif

ifeq ($(USELZO), on)
LIBS := -llzo2 $(LIBS)
CFLAGS += -DUSELZO
endif

ifeq ($(USESNAPPY), on)
LIBS := -lsnappy $(LIBS)
CFLAGS += -DUSESNAPPY
endif

LIBS := -lpthread $(LIBS)

try-run = $(shell set -e;		\
	TMP=".$$$$.tmp";		\
	if ($(1)) >/dev/null 2>&1;	\
	then echo "$(2)";		\
	else echo "$(3)";		\
	fi;				\
	rm -f "$$TMP")

LINK_TEST_PROG="int clock_gettime(); int main(){ return clock_gettime(); }"
LIBS := $(LIBS) $(call try-run,\
	echo $(LINK_TEST_PROG) | $(CC) $(CFLAGS) -o "$$TMP" -x c -,,-lrt)

all: makedumpfile

$(OBJ_PART): $(SRC_PART)
	$(CC) $(CFLAGS) -c -o ./$@ $(VPATH)$(@:.o=.c)

$(OBJ_ARCH): $(SRC_ARCH)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS_ARCH) -c -o ./$@ $(VPATH)$(@:.o=.c)

makedumpfile: $(SRC_BASE) $(OBJ_PART) $(OBJ_ARCH)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJ_PART) $(OBJ_ARCH) -rdynamic -o $@ $< $(LIBS)
	echo .TH MAKEDUMPFILE 8 \"$(DATE)\" \"makedumpfile v$(VERSION)\" \"Linux System Administrator\'s Manual\" > temp.8
	grep -v "^.TH MAKEDUMPFILE 8" $(VPATH)makedumpfile.8 >> temp.8
	mv temp.8 makedumpfile.8
	gzip -c ./makedumpfile.8 > ./makedumpfile.8.gz
	echo .TH MAKEDUMPFILE.CONF 5 \"$(DATE)\" \"makedumpfile v$(VERSION)\" \"Linux System Administrator\'s Manual\" > temp.5
	grep -v "^.TH MAKEDUMPFILE.CONF 5" $(VPATH)makedumpfile.conf.5 >> temp.5
	mv temp.5 makedumpfile.conf.5
	gzip -c ./makedumpfile.conf.5 > ./makedumpfile.conf.5.gz

eppic_makedumpfile.so: extension_eppic.c
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -rdynamic -o $@ extension_eppic.c -fPIC -leppic -ltinfo

clean:
	rm -f $(OBJ) $(OBJ_PART) $(OBJ_ARCH) makedumpfile makedumpfile.8.gz makedumpfile.conf.5.gz

install:
	install -m 755 -d ${DESTDIR}/usr/sbin ${DESTDIR}/usr/share/man/man5 ${DESTDIR}/usr/share/man/man8 ${DESTDIR}/etc
	install -m 755 -t ${DESTDIR}/usr/sbin makedumpfile $(VPATH)makedumpfile-R.pl
	install -m 644 -t ${DESTDIR}/usr/share/man/man8 makedumpfile.8.gz
	install -m 644 -t ${DESTDIR}/usr/share/man/man5 makedumpfile.conf.5.gz
	install -m 644 -D $(VPATH)makedumpfile.conf ${DESTDIR}/etc/makedumpfile.conf.sample
	mkdir -p ${DESTDIR}/usr/share/makedumpfile-${VERSION}/eppic_scripts
	install -m 644 -t ${DESTDIR}/usr/share/makedumpfile-${VERSION}/eppic_scripts/ $(VPATH)eppic_scripts/*
