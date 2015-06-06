CCFLAGS = -std=c99 -O3 -Wno-error=deprecated-declarations
LDFLAGS = -lcrypto -I../include

TARGET = pixiewps
PREFIX = $(DESTDIR)/usr
BINDIR = $(PREFIX)/bin
OLDDIR = $(PREFIX)/local/bin

all:
	$(CC) $(CCFLAGS) -o $(TARGET) $(TARGET).c $(LDFLAGS)

install:
	rm -f $(OLDDIR)/$(TARGET)
	install -D $(TARGET) $(BINDIR)/$(TARGET)
	install -m 755 $(TARGET) $(BINDIR)

uninstall:
	rm $(BINDIR)/$(TARGET)

clean:
	rm -f $(TARGET)
