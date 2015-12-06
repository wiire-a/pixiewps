CCFLAGS = -std=c99 -O3

TARGET = pixiewps
CRYPTO = crypto/sha256.c crypto/md.c crypto/md_wrap.c
SOURCE = $(TARGET).c random_r.c $(CRYPTO)
PREFIX = $(DESTDIR)/usr
BINDIR = $(PREFIX)/bin
OLDDIR = $(PREFIX)/local/bin

all:
	$(CC) $(CCFLAGS) -o $(TARGET) $(SOURCE)

debug:
	$(CC) $(CCFLAGS) -DDEBUG -o $(TARGET) $(SOURCE)

install:
	rm -f $(OLDDIR)/$(TARGET)
	install $(TARGET) $(BINDIR)/$(TARGET)
	install -m 755 $(TARGET) $(BINDIR)

uninstall:
	rm $(BINDIR)/$(TARGET)

clean:
	rm -f $(TARGET)
