cd commun

cc -Wall -DUNIX -DLINUX -DLITTLE_ENDIAN_BITFIELD    -c sockets.c
cc -Wall -DUNIX -DLINUX -DLITTLE_ENDIAN_BITFIELD    -c dump_headers.c
cc -Wall -DLITTLE_ENDIAN_BITFIELD                   -c dump_body.c
cc -Wall -DUNIX -DLINUX -DLITTLE_ENDIAN_BITFIELD    -c packet_filter.c
cc -Wall -DUNIX -DLINUX -DLITTLE_ENDIAN_BITFIELD    -c cline.c
cc -Wall -DUNIX -DLINUX -DLITTLE_ENDIAN_BITFIELD    -c packet_handler.c

cd ..

cc -Icommun/ -Wall -DUNIX -DLINUX -DLITTLE_ENDIAN_BITFIELD    -o dump unix/dump.c commun/sockets.o commun/dump_headers.o commun/packet_filter.o commun/dump_body.o commun/cline.o commun/packet_handler.o

rm commun/*.o
