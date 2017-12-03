CFLAGS = -std=c99 -O3

LIBS   = -lpthread
ifeq ($(OPENSSL),1)
LIBS += -lcrypto
CFLAGS += -DUSE_OPENSSL
else
CRYPTO = mbedtls/sha256.c mbedtls/md.c mbedtls/md_wrap.c
endif

PREFIX = /usr/local
BINDIR = $(PREFIX)/bin

TARGET = pixiewps
SOURCE = $(TARGET).c $(CRYPTO)

-include config.mak

all:
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $(TARGET) $(SOURCE) $(LIBS) $(LDFLAGS)

debug:
	$(CC) $(CFLAGS) $(CPPFLAGS) -DDEBUG -o $(TARGET) $(SOURCE) $(LIBS) $(LDFLAGS)

install:
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)

clean:
	rm -f $(TARGET)
