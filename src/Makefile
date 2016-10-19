CCFLAGS += -std=c99 -O3

TARGET = pixiewps
CRYPTO = crypto/sha256.c crypto/md.c crypto/md_wrap.c
SOURCE = $(TARGET).c random_r.c $(CRYPTO)
PREFIX ?= $(DESTDIR)/usr
PREFIX = $(DESTDIR)/usr
BINDIR = $(PREFIX)/bin
LOCDIR ?= $(PREFIX)/local

all:
	$(CC) $(CFLAGS) $(CCFLAGS) $(CPPFLAGS) -o $(TARGET) $(SOURCE) $(LDFLAGS)

debug:
	$(CC) $(CCFLAGS) -DDEBUG -o $(TARGET) $(SOURCE)

install:
	rm -f $(BINDIR)/$(TARGET)
	rm -f $(LOCDIR)/$(TARGET)
	install -d $(DESTDIR)$(LOCDIR)$(BINDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(LOCDIR)$(BINDIR)

uninstall:
	rm $(LOCDIR)/$(TARGET)

clean:
	rm -f $(TARGET)
