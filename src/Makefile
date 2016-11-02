CCFLAGS += -std=c99 -O3

TARGET = pixiewps
CRYPTO = crypto/sha256.c crypto/md.c crypto/md_wrap.c
SOURCE = $(TARGET).c random_r.c $(CRYPTO)
PREFIX ?= $(DESTDIR)/usr
BINDIR = $(PREFIX)/bin

all:
	$(CC) $(CFLAGS) $(CCFLAGS) $(CPPFLAGS) -o $(TARGET) $(SOURCE) $(LDFLAGS)

debug:
	$(CC) $(CCFLAGS) -DDEBUG -o $(TARGET) $(SOURCE)

install:
	rm -f $(BINDIR)/$(TARGET)
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)

uninstall:
	rm -f $(BINDIR)/$(TARGET)

clean:
	rm -f $(TARGET)
