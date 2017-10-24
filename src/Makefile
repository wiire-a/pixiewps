CFLAGS ?= -std=c99 -O3

TARGET = pixiewps
CRYPTO = mbedtls/sha256.c mbedtls/md.c mbedtls/md_wrap.c
SOURCE = $(TARGET).c random_r.c $(CRYPTO)
LIBS   = -lpthread

PREFIX ?= /usr
BINDIR = $(PREFIX)/bin

all:
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $(TARGET) $(SOURCE) $(LIBS) $(LDFLAGS)

debug:
	$(CC) $(CLFAGS) $(CPPFLAGS) -DDEBUG -o $(TARGET) $(SOURCE) $(LIBS) $(LDFLAGS)

install:
	install -d $(BINDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)

clean:
	rm -f $(TARGET)
