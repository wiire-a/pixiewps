CC = gcc
CCFLAGS = -std=c99
LDFLAGS = -lssl -lcrypto

TARGET = pixiewps
PREFIX = $(DESTDIR)/usr/local
BINDIR = $(PREFIX)/bin

all:
	$(CC) $(CCFLAGS) -o $(TARGET) $(TARGET).c random_r.c $(LDFLAGS)

install:
	install -D pixiewps $(BINDIR)/$(TARGET)
	install -m 755 $(TARGET) $(BINDIR)

uninstall:
	rm $(BINDIR)/$(TARGET)

clean:
	rm -f $(TARGET)
