CFLAGS = -std=c99 -O3

PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin
MANDIR = $(PREFIX)/share/man

SRCDIR = src
HDRS = $(SRCDIR)/config.h $(SRCDIR)/endianness.h $(SRCDIR)/version.h
HDRS += $(SRCDIR)/pixiewps.h $(SRCDIR)/utils.h $(SRCDIR)/wps.h

LIBS = -lpthread
ifeq ($(OPENSSL),1)
LIBS += -lcrypto
CFLAGS += -DUSE_OPENSSL
endif

TARGET = pixiewps
SOURCE = $(SRCDIR)/pixiewps.c

-include config.mak

.PHONY: all install install-bin install-man strip clean

all: $(TARGET)

$(TARGET): $(SOURCE) $(HDRS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $(TARGET) $(SOURCE) $(LIBS) $(LDFLAGS)

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
	rm -f $(TARGET)
