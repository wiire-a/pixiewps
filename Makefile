CFLAGS = -O3

PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin
MANDIR = $(PREFIX)/share/man

SRCDIR = src
HDRS = $(SRCDIR)/config.h $(SRCDIR)/endianness.h $(SRCDIR)/version.h
HDRS += $(SRCDIR)/pixiewps.h $(SRCDIR)/utils.h $(SRCDIR)/wps.h

# Internal flags so one can safely override CFLAGS, CPPFLAGS and LDFLAGS
INTFLAGS = -std=c99
LIBS = -lpthread

ifeq ($(OPENSSL),1)
LIBS += -lcrypto
INTFLAGS += -DUSE_OPENSSL
endif

TARGET = pixiewps
TFMSRC = $(sort $(wildcard $(SRCDIR)/crypto/tfm/*.c))
TFMOBJS = $(TFMSRC:.c=.o)

SOURCE = $(SRCDIR)/pixiewps.c

-include config.mak

.PHONY: all install install-bin install-man strip clean

all: $(TARGET)

$(TARGET): $(SOURCE) $(HDRS) $(TFMOBJS)
	$(CC) $(INTFLAGS) $(CFLAGS) $(CPPFLAGS) -o $(TARGET) $(SOURCE) $(LIBS) $(LDFLAGS) $(TFMOBJS)

$(SRCDIR)/crypto/tfm/%.o: $(SRCDIR)/crypto/tfm/%.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -I$(SRCDIR)/crypto/tfm -c -o $@ $<

install: install-bin install-man

install-bin: $(TARGET)
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $< $(DESTDIR)$(BINDIR)

install-man: pixiewps.1
	install -d $(DESTDIR)$(MANDIR)/man1
	install -m 644 $< $(DESTDIR)$(MANDIR)/man1

strip: $(TARGET)
	strip $(TARGET)

clean:
	rm -f $(TARGET) $(TFMOBJS)
