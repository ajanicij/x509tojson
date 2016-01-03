CFLAGS += -g
LDFLAGS += -lssl -lcrypto -ljson

all: build
build: x509tojson

x509tojson: prog.c
	$(CC) $(CFLAGS) -o $@ prog.c $(LDFLAGS)

clean:
	rm -f *.o x509tojson

rebuild: clean build
