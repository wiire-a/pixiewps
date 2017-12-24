CFLAGS = -std=c99 -O3

PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin
MANDIR = $(PREFIX)/share/man

SRCDIR = src

LIBS = -lpthread
ifeq ($(OPENSSL),1)
LIBS += -lcrypto
CFLAGS += -DUSE_OPENSSL
else
CRYDIR = $(SRCDIR)/mbedtls
CRYPTO = $(CRYDIR)/sha256.c $(CRYDIR)/md.c $(CRYDIR)/md_wrap.c
endif

TARGET = pixiewps
SOURCE = $(SRCDIR)/pixiewps.c $(CRYPTO)

-include config.mak

.PHONY: all install install-bin install-man clean

all: $(TARGET)

$(TARGET):
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $(TARGET) $(SOURCE) $(LIBS) $(LDFLAGS)

install: install-bin install-man

install-bin: $(TARGET)
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $< $(DESTDIR)$(BINDIR)

install-man: pixiewps.1
	install -d $(DESTDIR)$(MANDIR)/man1
	install -m 644 $< $(DESTDIR)$(MANDIR)/man1

clean:
	rm -f $(TARGET)
