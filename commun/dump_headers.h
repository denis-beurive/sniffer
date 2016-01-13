#ifndef DUMP_HEADERS_H

  #include "sockets.h" 

  void  print_proto (int);
  void  dump_ip_header (IP_Header*, int);
  void  dump_udp_header (UDP_Header*, int);
  int   dump_tcp_header (TCP_Header*, int);
  void  dump_eth_header (ETH_Header*, int);
  int   dump_ARP_header (ARP_Header*, int);
  int   dump_rip1_header (char*, int);

  #define SHORT_DESC  0
  #define LONG_DESC   1

  #define DUMP_HEADERS_H
#endif
