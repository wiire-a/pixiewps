CCFLAGS = -std=c99 -O3 -Wno-error=deprecated-declarations
LDFLAGS = -lcrypto -I../include

TARGET = pixiewps
PREFIX = $(DESTDIR)/usr
BINDIR = $(PREFIX)/bin

all:
	$(CC) $(CCFLAGS) -o $(TARGET) $(TARGET).c $(LDFLAGS)

install:
	install -D $(TARGET) $(BINDIR)/$(TARGET)
	install -m 755 $(TARGET) $(BINDIR)

uninstall:
	rm $(BINDIR)/$(TARGET)

clean:
	rm -f $(TARGET)
