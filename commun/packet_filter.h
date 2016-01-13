#ifndef PACKET_FILTER_H

  #include "sockets.h"

    /* IP macros */
    #define IP_HEADER(buff)     ((IP_Header*)((char*)buff+ETH_HD_LEN))
    #define UDP_HEADER(buff)    ((UDP_Header*)((char*)(IP_HEADER(buff)) + (4*(IP_HEADER(buff)->ip_length))))
    #define TCP_HEADER(buff)    ((TCP_Header*)((char*)(IP_HEADER(buff)) + (4*(IP_HEADER(buff)->ip_length))))
    #define PROTOCOL(buff)      (IP_HEADER(buff)->ip_protocol)
    #define IP_FROM(buff)       (IP_HEADER(buff)->ip_source)
    #define IP_TO(buff)         (IP_HEADER(buff)->ip_dest)
    
    /* Ethernet macros */
    #define ETH_HEADER(buff)    ((ETH_Header*)buff)
    #define ETH_TYPE(buff)      ntohs(ETH_HEADER(buff)->type)
    #define ETH_FORMAT(buff)    (((ETH_TYPE(buff))>0x05dc) ? ETHERNET_II : IEEE_802_3)
    #define ETH_ADDR_SRC_TYPE(buff) (((((ETH_HEADER(buff))->addr_src)[0] & 0x01) == 0) ? ETH_UNICAST : ETH_MULTICAST)
    #define ETH_ADDR_DEST_TYPE(buff) (((((ETH_HEADER(buff))->addr_dest)[0] & 0x01) == 0) ? ETH_UNICAST : ETH_MULTICAST)
    
    /* Test if an ethernet address is a broadcast */
    /* The type of 'addr' is 'unsigned char*'.    */
    #define ETH_ADDR_BROADCAST(addr)  (((*((unsigned int*)addr)) == 0xFFFFFFFF) && ((*((unsigned int*)(addr+2))) == 0xFFFFFFFF))

    /* ARP macros */
    #define ARP_HEADER(buff)    ((ARP_Header*)(buff+ETH_HD_LEN))
    #define ARP_HARD_TYPE(buff) (ntohs(ARP_HRADER(buff)->hardware_type))

    /* UDP macros */
    #define UDP_SRC_PORT(buff)       (ntohs(UDP_HEADER(buff)->udp_source_port))
    #define UDP_DST_PORT(buff)       (ntohs(UDP_HEADER(buff)->udp_dest_port))
    #define UDP_LENGTH(buff)         (ntohs(UDP_HEADER(buff)->udp_length))

    /* RIP header */
    #define RIP_VERSION(buff)        (((RIP_Header*)(((char*)UDP_HEADER(buff))+UDP_HD_LENGTH))->version)
    #define RIP_COMMAND(buff)        (((RIP_Header*)(((char*)UDP_HEADER(buff))+UDP_HD_LENGTH))->command)

    #define RIP1_HEADER(buff)        ((RIP1_Header*)(((char*)UDP_HEADER(buff))+UDP_HD_LENGTH))
    #define RIP1_DATA(buff,n)        ((RIP1_Data_Record*)(((char*)RIP1_HEADER(buff))+(RIP1_HD_LENGTH+RIP1_RECORD_LENGTH*n)))
    #define RIP1_RECORD_NUMBER(buff) ((UDP_LENGTH(buff)-RIP1_HD_LENGTH)/RIP1_RECORD_LENGTH)

    


    void body_info (char*, unsigned int*, unsigned int*);
    void get_addr (unsigned int, int*);
    int set_mask (char*, int*);
    int test_address (int*, int*);
    int get_src_port_number (char*);
    int get_dst_port_number (char*);

    /* IP mask */
    #define BAD_MASK     1
    #define GOOD_MASK    0
    
    /* port number */
    #define PORT_UNDEFINED -1

  #define PACKET_FILTER_H
#endif

