CGLAGS=`pkg-config --cflags glib-2.0` -I./ieee802_11 -g

.PHONY: all clean valgrind

all: server client

clean:
	rm -f ieee802_11/*.o 2>/dev/null
	rm -f *.o 2>/dev/null
	rm -f client 2>/dev/null
	rm -f server 2>/dev/null

#----
server: server.c ieee802_11/ieee802_11.o model.o debug.o util.o internals.o
	gcc -Wall $(CGLAGS) -o $@ $^ `pkg-config --libs glib-2.0` -lpcap

client: client.c util.o model.o debug.o
	gcc -Wall $(CGLAGS) -o $@ $^ `pkg-config --libs glib-2.0`

internals.o: internals.c
	gcc -Wall $(CGLAGS) -c -o $@ $<

model.o: model.c
	gcc -Wall $(CGLAGS) -c -o $@ $<

util.o: util.c
	gcc -Wall $(CGLAGS) -c -o $@ $<

debug.o: debug.c
	gcc -Wall $(CGLAGS) -c -o $@ $<

ieee802_11/ieee802_11.o: ieee802_11/ieee802_11_common.c
	gcc -Wall $(CGLAGS) -c -o $@ $<

valgrind_server: server
	# glib fake leaks still visible...
	sudo G_DEBUG=gc-friendly G_SLICE=always-malloc valgrind --leak-check=full ./server

valgrind_client: client
	G_DEBUG=gc-friendly G_SLICE=always-malloc valgrind --leak-check=full ./client
