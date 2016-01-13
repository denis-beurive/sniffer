/*****************************************************************************/
/*                   Sockets management under AIX and vxWorks                */
/*****************************************************************************/



#ifndef SOCKETS_H

  #ifdef UNIX
  #include <sys/socket.h>
  #endif

  #ifdef LINUX
    #include <linux/if_ether.h> /* for ETH_HLEN and ETH_ALEN */
    #define ETH_HD_LEN   ETH_HLEN  /* 14 (bytes) */
    #define ETH_ADDR_LEN ETH_ALEN  /* 6  (bytes) */
  #endif

  #ifdef NT
    #include <winsock.h>  
  #endif



  /* Just in case ... but these information should be somewhere in the */
  /* header files. It's better to do things properly ;)                */
  #ifndef ETH_HD_LEN
    #define ETH_HD_LEN    14 
  #endif
  #ifndef ETH_ADDR_LEN
    #define ETH_ADDR_LEN  6
  #endif

  #define SCK_OK                     0
  #define SCK_ERROR                  -1
  #define SCK_CREATE_ERROR           -1
  #define SCK_BIN_ERROR              -2
  #define SCK_SERVER_NAME_ERROR      -3
  #define SCK_BROADCAST_ERROR        -4
  #ifdef NT   /* 'winsock.dll' initialization */
    #define SCK_NT_SOCK_INIT_ERR           -5
    #define SCK_NT_SOCK_INIT_DLL_CHECK_ERR -6
  #endif
  #ifdef UNIX /* used to set the interface in promiscuous mode */
    #define SCK_IOCTL_SIOCGIFFLAGS_GET_ERR -7
    #define SCK_IOCTL_SIOCGIFFLAGS_SET_ERR -8
  #endif

  #define SCK_BROADCAST              1
  #define SCK_NO_BROADCAST           0
  #define SCK_ADDR_LEN               16 /* size of an IP address */
  #define SCK_NAME_ERROR             -1
  #define SCK_IP_ERROR               -2

  /* header management */
  #define HD_ERROR                   1
  #define HD_OK                      0


  #ifdef UNIX
    /* usual sockets */

    int Creer_Sock_INET (int, int*, int, struct sockaddr_in*);
    int Get_Sock_Adress (char*, int, struct sockaddr_in*);
    int Get_Broadcast_Adress (int, struct sockaddr_in*);

    #ifdef LINUX
    int Get_Net_Broadcast_address (char*, int, unsigned long int*);
    #endif

    #ifdef AIX
    int Get_Net_Broadcast_address (char*, int, unsigned long int*);
    #endif

    void Get_Send_Addr(struct sockaddr_in*, char*, int*);
    int Get_Host_Info (char*, char *);

    /* Promiscuous mode */

    #ifdef LINUX /* Only Linux can access the Link layer */
      int Open_Link_Socket();
      int Set_Promisc(char*, int);
      int Unset_Promisc(char*, int);
    #endif

    #ifdef AIX
      int Set_Promisc(char*, int);
      int Unset_Promisc(char*, int);
    #endif
  #endif

  #ifdef NT
    SOCKET Creer_Sock_INET (int, u_short*, int, SOCKADDR_IN*);
    int Get_Sock_Adress (char*, int, SOCKADDR_IN*);
    int Get_Broadcast_Adress (int, SOCKADDR_IN*);
    void Get_Send_Addr(SOCKADDR_IN*, char*, int*);
    int Get_Host_Info (char*, char *);
  #endif

  /* for Windows (just in case) */
  #ifndef MAXHOSTNAMELEN
    #define MAXHOSTNAMELEN 300 /* should be plenty */
  #endif

  #define PACKET_BUFF_SIZE 1600


  /***************************************************************************/
  /*               IP/TCP/UDP headers - use with raw sockets                 */
  /***************************************************************************/

  /* UDP services */
  #define SER_RIP 520

  /* protocol type for IP headers */
  #define TCP_PACKET  6
  #define UDP_PACKET  17
  #define ICMP_PACKET 1 
  #define IGMP_PACKET 2 
  #define IPIP_PACKET 4 
  #define EGP_PACKET  8
  #define PUP_PACKET  12
  #define IDP_PACKET  22
  #define RSVP_PACKET 46 
  #define GRE_PACKET  47
  #define IPV6_PACKET 41 
  #define PIM_PACKET  103
  #define RAW_PACKET  255

  /* stuffes for UDP */
  #define UDP_HD_LENGTH 8    /* bytes */
 
  /* protocol type for ethernet headers */
  #define PUP_ETH     0x0200 /* Xerox PUP  */
  #define IP_ETH      0x0800 /* IP         */
  #define ARP_ETH     0x0806 /* ARP        */
  #define REVARP_ETH  0x8035 /* Revers ARP */

  /* ethernet format */
  #define IEEE_802_3   0
  #define ETHERNET_II  1

  /* ethernet address type */
  #define ETH_UNICAST   0
  #define ETH_MULTICAST 1

  /* RIP1 macros */
  #define RIP1_IP            0x0020
  #define RIP1_REQUEST       1
  #define RIP1_REPLY         2
  #define RIP1_SUN           3   /* SUN private  */
  #define RIP1_UNREACHABLE   16  /* hops         */
  #define RIP1_MAX_RECORD    25  /* data records */
  #define RIP1_HD_LENGTH     8   /* bytes        */
  #define RIP1_RECORD_LENGTH 16  /* bytes        */


  /* define LITTLE_ENDIAN_BITFIELD if you are using a little endian */
  /* architechture. Otherwise defines BIG_ENDIAN_BITFIELD.          */
 
  /*************************************************************/
  /*                          IP data                          */
  /*************************************************************/

  /* structure of an ip header */
  struct S_ip
  {
    #ifdef LITTLE_ENDIAN_BITFIELD
	      unsigned short ip_length:4; 
	      unsigned short ip_version:4;
    #else
          unsigned short ip_version:4;
	      unsigned short ip_length:4; 
    #endif
	unsigned char        ip_tos;
	unsigned short       ip_total_length;
	unsigned short       ip_id;
	unsigned short       ip_flags;
	unsigned char        ip_ttl;
	unsigned char        ip_protocol;
	unsigned short       ip_cksum;
	unsigned int         ip_source;
	unsigned int         ip_dest;
  };

  /*************************************************************/
  /*                         TCP data                          */
  /*************************************************************/

  /* Structure of a TCP header */
  struct S_tcp
  {
	unsigned short          tcp_source_port;
	unsigned short          tcp_dest_port;
	unsigned long int       tcp_seqno;
	unsigned long int       tcp_ackno;
    #ifdef LITTLE_ENDIAN_BITFIELD
          unsigned short    tcp_reserved_1:4;
	      unsigned int      tcp_hlen:4;
          unsigned short    tcp_urg:1;
          unsigned short    tcp_ack:1;
          unsigned short    tcp_psh:1;
          unsigned short    tcp_rst:1;
          unsigned short    tcp_syn:1;
          unsigned short    tcp_fin:1;
          unsigned short    tcp_reserved_2:2;
    #else
	      unsigned int      tcp_hlen:4;
          unsigned short    tcp_reserved_1:4;
          unsigned short    tcp_reserved_2:2;
          unsigned short    tcp_urg:1;
          unsigned short    tcp_ack:1;
          unsigned short    tcp_psh:1;
          unsigned short    tcp_rst:1;
          unsigned short    tcp_syn:1;
          unsigned short    tcp_fin:1;
    #endif
	unsigned short          tcp_winsize;
	unsigned short          tcp_cksum;
	unsigned short          tcp_urgent;
  };

  /*************************************************************/
  /*                          UDP data                         */
  /*************************************************************/

  /* Structure of a UDP header */
  struct S_udp
  {
	unsigned short      udp_source_port;
	unsigned short      udp_dest_port;
	unsigned short      udp_length;
	unsigned short      udp_cksum;
  };

  /*************************************************************/
  /*                        Ethernet data                      */
  /*************************************************************/

  /* Structure of an ethernet header */
  struct S_eth
  {
    unsigned char       addr_dest[ETH_ADDR_LEN];    
    unsigned char       addr_src[ETH_ADDR_LEN];
    unsigned short      type;                   /* 16 bits */
  };


  /*************************************************************/
  /*                           ARP data                        */
  /*************************************************************/
  
  struct S_arp
  {
    unsigned short int hardware_type;    /* Format of hardware address.  */
    unsigned short int protocol_type;    /* Format of protocol address.  */
                                         /* for example: IP              */
                                         /* This field is the same than  */
                                         /* the filed 'type' of the      */
                                         /* ethernet header.             */
                                         /* If 'IP' this means that we   */
                                         /* use ARP to associate an      */
                                         /* hardware address to an IP    */
                                         /* address.                     */
    unsigned char      hardware_length;  /* Length of hardware address.  */
    unsigned char      protocol_length;  /* Length of protocol address.  */
                                         /* For example, if              */
                                         /* 'protocol_type' = IP, then   */
                                         /* 'protocol_lenght' = 4        */
                                         /* bacause an IP address is 4   */
                                         /* bytes long.                  */
    unsigned short int operation;		 /* ARP opcode (command).        */

    /* WARNING ! The following declaration assumes that we are using ethernet */
    /* The size of the following data depends on the hardware type.           */

    unsigned char addr_sender[ETH_ADDR_LEN]; /* Sender hardware address.  */
    unsigned char source_proto_addr[4];	     /* Sender IP address.        */
    unsigned char addr_target[ETH_ADDR_LEN]; /* Target hardware address.  */
    unsigned char target_proto_addr[4];	     /* Target IP address.        */
  };

  /*************************************************************/
  /*                            RIP data                       */
  /* RIPv1: RFC 1058                                           */
  /* RIPv2: RFC 1388                                           */
  /*************************************************************/
  
  struct S_rip
  {
    unsigned char    command;          /* 1 request for routing information */
    unsigned char    version;          /* RIP version 1 or 2                */
  };  

  struct S_rip1_record
  {
    unsigned char  network_addr[16]; /* address of the network            */
                                     /* *left justified*.                 */
    unsigned int   hops;             /* number of hops to reach the       */
                                     /* from 1 to 16.                     */
                                     /* 1:  immediatly reachable.         */
                                     /* 16: unreachable.                  */
  };

  struct S_rip1
  {
    unsigned char    command;          /* 1 request for routing information */
    unsigned char    version;          /* RIP version 1 or 2                */
    unsigned short   reserved1;        /* reserved - value of 00            */
    unsigned short   proto;            /* protocol family 0x0020 = IP       */
    unsigned short   reserved2;        /* reserved - value of 00            */
  };




  typedef struct S_ip           IP_Header;
  typedef struct S_tcp          TCP_Header;
  typedef struct S_udp          UDP_Header;
  typedef struct S_eth          ETH_Header;
  typedef struct S_arp          ARP_Header;
  typedef struct S_rip1_record  RIP1_Data_Record;
  typedef struct S_rip1         RIP1_Header;
  typedef struct S_rip          RIP_Header;


  #define SOCKETS_H
#endif
