# WLAN Connection Daemon Makefile

VERSION = $(shell dpkg-parsechangelog | sed -n 's/^Version: \(.*:\|\)//p')
#
CC = gcc
SRC = ./
DESTDIR =
LIBDIR ?= libs
BINDIR = $(DESTDIR)/usr/sbin
DBUSDIR = $(DESTDIR)/etc/dbus-1/system.d
BINARY = wlancond

INSTALL = install
INSTALL_PROGRAM = $(INSTALL)
INSTALL_DATA = $(INSTALL) -m644

# Disable deprecated APIs
CPPFLAGS += -DGCONF_DISABLE_DEPRECATED -DG_DISABLE_DEPRECATED

# Build system flags
CFLAGS += $(BCFLAGS)

# General flags
CFLAGS += -DVERSION=\"$(VERSION)\" -D_GNU_SOURCE -I$(LIBDIR)

# Debug flags
#CFLAGS += -g -ggdb -DDEBUG -O0 -rdynamic 
CFLAGS += -DDEBUG
CFLAGS += -DUSE_MCE_MODE -DACTIVITY_CHECK

# Library flags
CFLAGS   += `pkg-config --cflags glib-2.0 gconf-2.0 dbus-1 osso-ic`
LDFLAGS  += `pkg-config --libs glib-2.0 gconf-2.0 dbus-1`

# Wireless tools library, NOTE under GPL
LDFLAGS += -liw

LINTFLAGS := $(CFLAGS) +posixlib +unixlib +ignorequals -predboolint \
                -shiftnegative -nullassign -compdef +charintliteral \
                +longunsignedintegral -nullret -usedef -nullpass -preproc 

# Removed -Wcast-align because of warnings in scratchbox
DEBUG_CFLAGS = -Wall -Wwrite-strings -Wmissing-declarations \
        -Wmissing-prototypes -Wstrict-prototypes \
	-Wunused -Wunused-function -Wunused-variable -Wunused-value \
	-Wsign-compare -Wpointer-arith -Wundef -Wbad-function-cast \
	-Waggregate-return -Wmissing-noreturn -Wnested-externs \
	-Wchar-subscripts -Wformat-security -Wformat=2 -Wno-format-nonliteral
	#-Wunreachable-code -Wshadow -std=c99 -Werror

MCFLAGS := $(CFLAGS) $(DEBUG_CFLAGS)

CFLAGS += $(DEBUG_CFLAGS)

OBJECTS = main.o dbus-handler.o dbus-signal.o wpa.o wps.o

EXT_OBJ = $(LIBDIR)/daemon.o $(LIBDIR)/dbus-helper.o $(LIBDIR)/dbus.o

all: $(BINARY)

$(BINARY): $(OBJECTS) $(EXT_OBJ)
	$(CC) $(LDFLAGS) $(OBJECTS) $(EXT_OBJ) -o $(BINARY)

.PHONY: clean doc install

install: $(BINARY)
	$(INSTALL_PROGRAM) -d $(BINDIR) $(DBUSDIR)
	$(INSTALL_PROGRAM) $(BINARY) $(BINDIR)
	$(INSTALL_DATA) wlancond.conf $(DBUSDIR)

clean:
	$(RM) $(OBJECTS) $(BINARY) $(BINARY_WI) *~
	$(MAKE) -C $(LIBDIR) clean

doc:
	doxygen doxygen.cfg

