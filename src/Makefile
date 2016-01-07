CCFLAGS = -std=c99 -O3

TARGET = pixiewps
CRYPTO = crypto/sha256.c crypto/md.c crypto/md_wrap.c
SOURCE = $(TARGET).c random_r.c $(CRYPTO)
PREFIX = $(DESTDIR)/usr
BINDIR = $(PREFIX)/bin
LOCDIR = $(PREFIX)/local/bin

all:
	$(CC) $(CCFLAGS) -o $(TARGET) $(SOURCE)

debug:
	$(CC) $(CCFLAGS) -DDEBUG -o $(TARGET) $(SOURCE)

install:
	rm -f $(BINDIR)/$(TARGET)
	rm -f $(LOCDIR)/$(TARGET)
	install -d $(LOCDIR)
	install -m 755 $(TARGET) $(LOCDIR)

uninstall:
	rm $(BINDIR)/$(TARGET)

clean:
	rm -f $(TARGET)
