CCFLAGS = -std=c99 -O3 -Wno-deprecated-declarations
LDFLAGS = -lcrypto -I../include

TARGET = pixiewps
SOURCE = $(TARGET).c random_r.c
PREFIX = $(DESTDIR)/usr
BINDIR = $(PREFIX)/bin
OLDDIR = $(PREFIX)/local/bin

all:
	$(CC) $(CCFLAGS) -o $(TARGET) $(SOURCE) $(LDFLAGS)

install:
	rm -f $(OLDDIR)/$(TARGET)
	install $(TARGET) $(BINDIR)/$(TARGET)
	install -m 755 $(TARGET) $(BINDIR)

uninstall:
	rm $(BINDIR)/$(TARGET)

clean:
	rm -f $(TARGET)
