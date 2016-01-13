/******************************************************************************/
/*                 Sockets management under UNIX and Windows                  */
/*                 author: Denis BEURIVE.                                     */
/******************************************************************************/



#include <stdio.h>
#include <stdlib.h>

#ifdef UNIX
  #include <unistd.h>
  #include <sys/types.h>
  #include <netinet/in.h>
  #include <string.h>
  #include <netdb.h>
  #include <sys/param.h>

  #ifdef VXWORKS
    #include <sockLib.h>
    #include <inetLib.h>
  #endif

  #ifdef AIX
    #include <netdb.h>
    #include <sys/socket.h>
    #include <arpa/inet.h>
    #include <net/if.h>          /* for promiscuous mode          */
    #include <sys/ioctl.h>       /* for SIOCGIFFLAGS and ioctl    */
  #endif

  #ifdef LINUX
    #include <netdb.h>
    #include <sys/socket.h>
    #include <arpa/inet.h>
    #include <net/if.h>          /* for promiscuous mode       */
    #include <linux/sockios.h>   /* for SIOCGIFFLAGS           */
    #include <linux/if_ether.h>  /* for ETH_HLEN and ETH_P_ALL */
    #include <sys/ioctl.h>       /* for ioctl                  */
  #endif
#endif /* UNIX */

#ifdef NT
  #include <winsock.h>
  #include <mem.h>
#endif

#include "sockets.h"


/*****************************************************************************/
/*                           Creer_Sock_INET                                 */
/*                                                                           */
/* Create a socket (type SOCK_DGRAM or SOCK_STREAM only) and attach it to a  */
/* port number. This function requires:                                      */
/*   o the socket type SOCK_DGRAM (for UDP) or SOCK_STREAM (for TCP).        */
/*   o the port number.                                                      */
/*   o flag that indicates if you need to include broadcast capability.      */
/*                                                                           */
/* -> type    = (in) SOCK_DGRAM or SOCK_STREAM                               */
/*              SOCK_DGRAM  => UDP protocol.                                 */
/*              SOCK_STREAM => TCP protocol.                                 */
/* -> port    = (in) pointeur sur le numero de port                          */
/* -> broad   = (in) wether or not you need to send broadcast messages.      */
/*              SCK_BROADCAST: BROADCAST activated.                          */
/*              SCK_NO_BROADCAST: BROADCAST not activated.                   */
/* <- adresse = (out) pointeur sur adresse de la socket                      */
/*                                                                           */
/* return value: SCK_CREATE_ERROR  => error while creating the socket.       */
/*                                    the call the function "socket" failed. */
/*               SCK_BIN_ERROR     => can not attached the socket.           */
/*                                    the call the function "bind" failes.   */
/*                                                                           */
/* Remarks:                                                                  */
/* (1) A socket is defined by:                                               */
/*     o a port number.                                                      */
/*     o protocol (UDP or TCP).                                              */
/*     o an interface (IP address).                                          */
/*                                                                           */
/* (2) The socket function definition is:                                    */
/*     int socket(int domain, int type, int protocol)                        */
/*     -- The only currently supported address domains are:                  */
/*           + AF_INET        (DARPA Internet addresses)                     */
/*           + AF_UNIX        (path names on a local node)                   */
/*     -- The type specifies the semantics of communication for the socket.  */
/*        Currently defined types are:                                       */
/*           + SOCK_STREAM    Sequenced, reliable, two-way-connection-based  */
/*                            byte streams.                                  */
/*           + SOCK_DGRAM     Datagrams (connectionless, unreliable messages */ 
/*                            of a fixed, typically small, maximum length;   */
/*                            for AF_INET only).                             */
/*           + SOCK_RAW       used to bypass the transport layer and         */
/*                            directly access the IP layer.                  */
/*           + SOCK_PACKET    this is linux specific, it is similuar to      */
/*                            SOCK_RAW except it accesses the DATA LINK      */
/*                            layer.                                         */
/*     -- The protocol can be:                                               */
/*           + IPPROTO_TCP    TCP protocol.                                  */
/*           + IPPROTO_UDP    UDP protocol.                                  */
/*           + IPPROTO_RAW    Internet protocol (IP).                        */
/*           + IPPROTO_ICMP   Internet Control Message Protocol.             */
/*           + IPPROTO_IGMP   Internet Group Management Protocol.            */
/*                                                                           */
/*         If "0" (zero) is specified, then the default protocol is used.    */
/*         o if SOCK_STEAM => default is IPPROTO_TCP                         */
/*         o if SOCK_DGRAM => default is IPPROTO_UDP                         */
/*                                                                           */
/* (3) unsigned short htons (unsigned short HostShort)                       */
/* Converts an unsigned short integer from host byte order to Internet       */
/* network byte order.                                                       */
/*                                                                           */
/* (4) Byte-ordering,is the way that the operating system stores bytes in    */
/* memory. There are two ways that this is done first with the low-order     */
/* byte at the starting address this is known as "little-endian" or          */
/* host-byte order. Next bytes can be stored with the high order byte at the */
/* starting address, this is called "big-endian" or network byte order. The  */
/* Internet protocol uses >>>>>> network byte order.                         */
/*                                                                           */
/* (5) struct sockaddr                                                       */
/*     {                                                                     */
/*	      unsigned short sa_family;                                      */
/*            char           sa_data[14];                                    */
/*     };                                                                    */
/* sa_family: socket domain (AF_INET / AF_UNIX).                             */
/* sa_data:   holds the destination port and address for the socket.         */
/*                                                                           */
/* (6) To make it easier to deal with the sockaddr struct the use of the     */
/* sockaddr_in structure is commonly used. Sockaddr_in makes it easier to    */
/* reference all of the elements that are contained by sockaddr.             */
/*                                                                           */
/*   struct sockaddr_in {                                                    */
/*             short int          sin_family;   Address family               */
/*             unsigned short int sin_port;     Port number                  */
/*             struct in_addr     sin_addr;     Internet address             */
/*             unsigned char      sin_zero[8];  Same size as struct sockaddr */
/*   };                                                                      */
/*                                                                           */
/* Note that sizeof(struct sockaddr)    = 2 + 14 = 16.                       */
/*           sizeof(struct sockaddr_in) = 2 + 2 + 4 + 8 = 16.                */
/*                                                                           */
/* 'sockaddr_in' is used only because it makes address manipulation easier.  */
/* But 'sockaddr_in' and 'sockaddr' contain exactly the same date (bite per  */
/* byte).                                                                    */
/*                                                                           */
/* (7) if the value of 'sin_addr' is 'INADDR_ANY', it means that we attach   */
/* the socket to the first interface (IP address) available.                 */
/*                                                                           */
/* (8) 'sin_zero' should be filled with zeros.                               */
/*                                                                           */
/* (9) '(sin_addr).s_addr' is a 32 bits (4 bytes) long integer. If it is set */
/*     to 'INADDR_BROADCAST', it means that this socket address will be used */
/*     for *LIMITED* broadcasting (IP address "255.255.255.255").            */
/*     To get the "net-directed" broadcast address associated with an speci- */
/*     -fic interface a "ioctl" call must be performed.                      */
/*****************************************************************************/

#ifdef UNIX
  int Creer_Sock_INET (int type, int *port, int broad, struct sockaddr_in *add)
#endif

#ifdef NT
  SOCKET Creer_Sock_INET (int type, u_short *port, int broad, SOCKADDR_IN *add)
#endif
{
  #ifdef UNIX
    int                 desc;
    #ifdef AIX
      int               on;
    #endif

    #ifdef LINUX
      int               on;
    #endif
  #endif

  #ifdef NT
    SOCKET              desc;
    int                 on;
    WORD                wVersionRequested; 
    WSADATA             wsaData; 
    int                 err;
  #endif

  int                 longueur;
  int                 i;



  #ifdef NT

    /* Initialize NT winsock.dll */

    wVersionRequested = MAKEWORD(2, 0); 
 
    err = WSAStartup(wVersionRequested, &wsaData); 
    if (err != 0) { return SCK_NT_SOCK_INIT_ERR; }

    if ( (LOBYTE( wsaData.wVersion ) != 2) || (HIBYTE( wsaData.wVersion ) != 0) )
    { 
      WSACleanup();
      return SCK_NT_SOCK_INIT_DLL_CHECK_ERR;
    }
 
    /* The Windows Sockets DLL is acceptable. Proceed. */ 

    if ((desc = socket (AF_INET, type, 0)) == INVALID_SOCKET)
    {
      #ifdef DEBUG
        switch (WSAGetLastError())
        {
          case WSANOTINITIALISED:	    printf("\n\nA successful WSAStartup must occur before using this function."); break;
          case WSAENETDOWN:	        printf("\n\nThe Windows Sockets implementation has detected that the network subsystem has failed."); break;
          case WSAEAFNOSUPPORT:		printf("\n\nThe specified address family is not supported."); break;
          case WSAEINPROGRESS:		printf("\n\nA blocking Windows Sockets operation is in progress."); break;
          case WSAEMFILE:		        printf("\n\nNo more file descriptors are available."); break;
          case WSAENOBUFS:		    printf("\n\nNo buffer space is available. The socket cannot be created."); break;
          case WSAEPROTONOSUPPORT:	printf("\n\nThe specified protocol is not supported."); break;
          case WSAEPROTOTYPE:		    printf("\n\nThe specified protocol is the wrong type for this socket."); break;
          case WSAESOCKTNOSUPPORT:	printf("\n\nThe specified socket type is not supported in this address family."); break;
        }
      #endif
      return (SCK_CREATE_ERROR);
    };

  longueur = (int)sizeof (SOCKADDR_IN);
  #endif

  #ifdef UNIX
    #ifdef VXWORKS
      if ((desc = socket (PF_INET, type, 0)) == -1)
    #endif
    #ifdef AIX
      if ((desc = socket (AF_INET, type, 0)) == -1)
    #endif
    #ifdef LINUX
      if ((desc = socket (AF_INET, type, 0)) == -1)
    #endif
    { return (SCK_CREATE_ERROR); }

    /* utilise pour la fonction bind                                           */
    longueur = (int)sizeof ((*add));
  #endif /* UNIX */


  #ifdef NT
    add->sin_family      = AF_INET;
    add->sin_addr.s_addr = INADDR_ANY;
    add->sin_port        = htons((u_short)*port);

    #ifdef DEBUG    
      printf ("\n\nport number %d (-- %d --)\n\n", add->sin_port, *port);
    #endif
    
  #endif

  #ifdef UNIX
    #ifdef VXWORKS
      add->sin_family    = PF_INET;          /* socket internet                */
    #endif

    #ifdef AIX
      add->sin_family    = AF_INET;          /* socket internet                */
    #endif

    #ifdef LINUX
      add->sin_family    = AF_INET;          /* socket internet                */
    #endif

    add->sin_port        = htons((unsigned short)*port);
    add->sin_addr.s_addr = INADDR_ANY;
    for (i=0; i<8; i++) { add->sin_zero[i] = 0; }

  #endif /* UNIX */

  #ifdef NT
    if (broad == SCK_BROADCAST)
    {
      on = 1;
      if (setsockopt(desc, SOL_SOCKET, SO_BROADCAST, (char FAR*)&on, sizeof(int)) == SOCKET_ERROR)
      { return SCK_BROADCAST_ERROR; }
    }

    if (bind(desc, (LPSOCKADDR)add, longueur) == SOCKET_ERROR)
    { return (SCK_BIN_ERROR); }

    if (getsockname (desc, (LPSOCKADDR)add, (int FAR *)&longueur) == SOCKET_ERROR)
    { return (SCK_BIN_ERROR); }
  #endif

  #ifdef UNIX
    #ifdef VXWORKS
      if (bind(desc, (struct sockaddr*)add, longueur) != 0)
      { return (SCK_BIN_ERROR); }
    #endif

    #ifdef AIX
      if (broad == SCK_BROADCAST)
      {
        on = 1;
        if (setsockopt(desc, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)) < 0)
        { return SCK_BROADCAST_ERROR; }
      }

      if (bind(desc, (struct sockaddr*)add, longueur) == -1)
      { return (SCK_BIN_ERROR); }
    #endif

    #ifdef LINUX
      if (broad == SCK_BROADCAST)
      {
        on = 1;
        if (setsockopt(desc, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)) < 0)
        { return SCK_BROADCAST_ERROR; }
      }

      if (bind(desc, (struct sockaddr*)add, longueur) == -1)
      { return (SCK_BIN_ERROR); }
    #endif
  #endif /* UNIX */

  return (desc);
};

#ifdef UNIX

#ifdef LINUX

/***************************************************************************/
/*                             Open_Link_Socket                            */
/*                                                                         */
/* Open a socket for accessing the link layer directly.                    */
/*                                                                         */
/* return value:                                                           */
/*   SCK_CREATE_ERROR if error.                                            */
/*   socket descriptor if everything OK.                                   */
/*                                                                         */
/* Note: the mode SOCK_PACKET is Linux specific.                           */
/***************************************************************************/

int Open_Link_Socket()
{
 int sock;

 if((sock = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ALL))) == -1)
 { return (SCK_CREATE_ERROR); }
 
 return(sock);
}

#endif /* LINUX */

/***************************************************************************/
/*                                 Set_Promisc                             */
/*                                                                         */
/* Set the specified interface in Promiscuous mode. Promiscuous mode on a  */
/* network interface enables an interface that is intended to look at      */
/* traffic addressed only to its 6 bytes mac address to look at ALL        */
/* traffic on the broadcast medium.                                        */
/*                                                                         */
/* -> interface: (in) interface name (ex: "eth0").                         */
/* -> sock:      (in) socket decriptor.                                    */
/*                                                                         */
/* return value:                                                           */
/*  o SCK_IOCTL_SIOCGIFFLAGS_GET_ERR: can not get interface flags.         */
/*  o SCK_IOCTL_SIOCGIFFLAGS_SET_ERR: can not set interface flags.         */
/*  o SCK_OK: every thing OK.                                              */
/*                                                                         */
/* Note: has been tested under LINUX and AIX only.                         */
/***************************************************************************/

#ifdef LINUX
  int Set_Promisc(char *interface, int sock )
  {
       struct ifreq ifr;
       
       strncpy(ifr.ifr_name, interface,strlen(interface)+1);
       if((ioctl(sock, SIOCGIFFLAGS, &ifr) == -1))
       { return SCK_IOCTL_SIOCGIFFLAGS_GET_ERR; }

        /* now that the flags have been retrieved */
        /* set the flags to PROMISC               */
       ifr.ifr_flags |= IFF_PROMISC;
       if (ioctl (sock, SIOCSIFFLAGS, &ifr) == -1 )
       { return SCK_IOCTL_SIOCGIFFLAGS_GET_ERR; }

       return SCK_OK;
   }

#endif /* LINUX */

#ifdef AIX
   int Set_Promisc(char *interface, int sock )
   {
       struct ifreq ifr;
       
       strncpy(ifr.ifr_name, interface,strnlen(interface)+1);
       if((ioctl(sock, SIOCGIFFLAGS, &ifr) == -1))
       { return SCK_IOCTL_SIOCGIFFLAGS_GET_ERR; }

        /* now that the flags have been retrieved */
        /* set the flags to PROMISC               */
       ifr.ifr_flags |= IFF_PROMISC;
       if (ioctl (sock, SIOCSIFFLAGS, &ifr) == -1 )
       { return SCK_IOCTL_SIOCGIFFLAGS_GET_ERR; }

       return SCK_OK;
   }
#endif /* AIX */

#endif /* UNIX */

/***************************************************************************/
/*                             Unset_Promisc                               */
/*                                                                         */
/* Remove the promiscuous mode.                                            */
/***************************************************************************/

#ifdef UNIX

  #ifdef LINUX
  int Unset_Promisc(char *interface, int sock )
  {
       struct ifreq ifr;
       
       strncpy(ifr.ifr_name, interface,strlen(interface)+1);
       if((ioctl(sock, SIOCGIFFLAGS, &ifr) == -1))
       { return SCK_IOCTL_SIOCGIFFLAGS_GET_ERR; }

        /* now that the flags have been retrieved */
        /* unset the PROMISC flag                 */
       ifr.ifr_flags &= ~IFF_PROMISC;
       if (ioctl (sock, SIOCSIFFLAGS, &ifr) == -1 )
       { return SCK_IOCTL_SIOCGIFFLAGS_GET_ERR; }

       return SCK_OK;
   }
  #endif

  #ifdef AIX
  int Unset_Promisc(char *interface, int sock )
  {
       struct ifreq ifr;
       
       strncpy(ifr.ifr_name, interface,strlen(interface)+1);
       if((ioctl(sock, SIOCGIFFLAGS, &ifr) == -1))
       { return SCK_IOCTL_SIOCGIFFLAGS_GET_ERR; }

        /* now that the flags have been retrieved */
        /* unset the PROMISC flag                 */
       ifr.ifr_flags &= ~IFF_PROMISC;
       if (ioctl (sock, SIOCSIFFLAGS, &ifr) == -1 )
       { return SCK_IOCTL_SIOCGIFFLAGS_GET_ERR; }

       return SCK_OK;
   }
   #endif
#endif /* UNIX */

/***************************************************************************/
/*                              Get_Sock_Adress                            */
/*                                                                         */
/* Get an socket address using the following information:                  */
/*   o host name (or IP address).                                          */
/*   o port number.                                                        */
/*                                                                         */
/* -> Machine_serveur     : (in) IP Adresse                                */
/* -> port_serveur        : (in) port number                               */
/* <- adresse_UDP_serveur : (out) socket adresse                           */
/*                                                                         */
/*                                                                         */
/* return:                                                                 */
/*  always SCK_OK                                                          */
/*                                                                         */
/* NB: le nom de la machine sur laquelle s'execute le processus serveur    */
/*     peut etre obtenu par la commande "uname".                           */
/***************************************************************************/


#ifdef UNIX
  int Get_Sock_Adress (char *Machine_serveur, int port_serveur, struct sockaddr_in *adresse_UDP_serveur)
#endif

#ifdef NT
  int Get_Sock_Adress (char *Machine_serveur, int port_serveur, SOCKADDR_IN *adresse_UDP_serveur)
#endif
{
  #ifdef NT
    memset ((void*)adresse_UDP_serveur, 0, sizeof(SOCKADDR_IN));
    adresse_UDP_serveur->sin_family        = AF_INET;
    adresse_UDP_serveur->sin_port          = htons((u_short)port_serveur);
    (adresse_UDP_serveur->sin_addr).s_addr = inet_addr(Machine_serveur);
  #endif

  #ifdef UNIX
    memset ((void*)adresse_UDP_serveur, 0, sizeof(struct sockaddr_in));

    #ifdef VXWORKS
      adresse_UDP_serveur->sin_family      = PF_INET;
    #endif

    #ifdef AIX
      adresse_UDP_serveur->sin_family      = AF_INET;
    #endif

    #ifdef LINUX
      adresse_UDP_serveur->sin_family      = AF_INET;
    #endif

    adresse_UDP_serveur->sin_port          = htons(port_serveur);
    (adresse_UDP_serveur->sin_addr).s_addr = inet_addr(Machine_serveur);
  #endif

  return (SCK_OK);
}


/***************************************************************************/
/*                         Get_Broadcast_Adress                            */
/*                                                                         */
/* Get the bradcast address.                                               */
/*                                                                         */
/* -> port_serveur    : (in) port number                                   */
/* <- adresse_UDP_serveur : (out) adresse (socket)                         */
/*                                                                         */
/* return value:                                                           */
/*  always SCK_OK                                                          */
/*                                                                         */
/* This braodcast address is the *LIMITED* broadcast address "255.255.255. */
/* 255", which is never forwarded by routers.                              */
/***************************************************************************/

#ifdef UNIX
int Get_Broadcast_Adress (int port_serveur, struct sockaddr_in *adresse_UDP_serveur)
#endif

#ifdef NT
int Get_Broadcast_Adress (int port_serveur, SOCKADDR_IN *adresse_UDP_serveur)
#endif
{
  #ifdef NT
    memset ((void*)adresse_UDP_serveur, 0, sizeof(SOCKADDR_IN));
    adresse_UDP_serveur->sin_family        = AF_INET;
    adresse_UDP_serveur->sin_port          = htons((u_short)port_serveur);
    (adresse_UDP_serveur->sin_addr).s_addr = INADDR_BROADCAST;
  #endif

  #ifdef UNIX
    memset ((void*)adresse_UDP_serveur, 0, sizeof(struct sockaddr_in));

    #ifdef VXWORKS
      adresse_UDP_serveur->sin_family      = PF_INET;
    #endif

    #ifdef AIX
      adresse_UDP_serveur->sin_family      = AF_INET;
    #endif

    #ifdef LINUX
      adresse_UDP_serveur->sin_family      = AF_INET;
    #endif

    adresse_UDP_serveur->sin_port          = htons(port_serveur);
    (adresse_UDP_serveur->sin_addr).s_addr = INADDR_BROADCAST;
  #endif /* UNIX */

  return (SCK_OK);
}


/***************************************************************************/
/*                       Get_Net_Broadcast_Address                         */
/*                                                                         */
/* Get the specific interface net directed broadcast address. This broad-  */
/* -cast address depends on the network mask associated with this inter-   */
/* -face.                                                                  */
/*                                                                         */
/* -> interface: (in) interface name (ex:"eth0").                          */
/* -> sock:      (in) socket descriptor.                                   */
/* <- baddr:     (out) net directed broadcast address (in network byte     */
/*               order <=> big endian).                                    */
/*                                                                         */
/* Return value:                                                           */
/*   -- SCK_OK: everything is OK.                                          */
/*   -- SCK_ERROR: the 'ioctl' call failed.                                */
/*                                                                         */
/* Note: has been tested under LINUX and AIX only.                         */
/***************************************************************************/

#ifdef UNIX

#ifdef AIX
int Get_Net_Broadcast_address (char *interface, int sock, unsigned long int *baddr)
{
    struct ifreq         ifr;
    struct ifreq         *pifr;  
    struct sockaddr_in   *a;


    strncpy(ifr.ifr_name, interface,strnlen(interface)+1);
    if((ioctl(sock, SIOCGIFBRDADDR, &ifr) == -1))
    { return SCK_ERROR; }

    pifr   = &ifr;
    a      = (struct sockaddr_in*)(&((pifr->ifr_ifru).ifru_broadaddr));
    *baddr = (unsigned long int)((a->sin_addr).s_addr);

    return (SCK_OK);
}
#endif

#ifdef LINUX
int Get_Net_Broadcast_address (char *interface, int sock, unsigned long int *baddr)
{
    struct ifreq         ifr;
    struct ifreq         *pifr;  
    struct sockaddr_in   *a;


    strncpy(ifr.ifr_name, interface,strlen(interface)+1);
    if((ioctl(sock, SIOCGIFBRDADDR, &ifr) == -1))
    { return SCK_ERROR; }

    pifr   = &ifr;
    a      = (struct sockaddr_in*)(&((pifr->ifr_ifru).ifru_broadaddr));
    *baddr = (unsigned long int)((a->sin_addr).s_addr);

    return (SCK_OK);
}
#endif

#endif /* UNIX */

/**************************************************************************/
/*                              Get_Send_Addr()                           */
/*                                                                        */
/* When a process receives a message, the sender address is stored in the */
/* message. This functiun extracts the sender's address form the message. */
/*                                                                        */
/* -> Address_Sender: (in) the socket address of the sender.              */
/* <- IP_Address:     (out) the IP address of the sender in dotted        */
/*                    notation (ex: "92.0.0.1").                          */
/* <- port:           (out) port number of the sender.                    */
/*                                                                        */
/* Note that 'IP_Address' and 'port' are character strings.               */
/*                                                                        */
/* recvfrom (                                                             */
/*             socket_de_reception,                                       */
/*             pointeur_sur_buffer,                                       */
/*             taille_du_buffer,                                          */
/*             options,                                                   */
/*             adresse_de_l_envoyeur,                                     */
/*             taille_de_l_adresse_de_l_envoyeur                          */
/*          )                                                             */
/*                                                                        */
/* The argument number 5 (adresse_de_l_envoyeur) contains the sender      */
/* address.                                                               */
/*                                                                        */
/* return value:                                                          */
/*     none.                                                              */
/**************************************************************************/

#ifdef UNIX
void Get_Send_Addr(struct sockaddr_in *Address_Sender, char *IP_Address, int *Port)
#endif

#ifdef NT
void Get_Send_Addr(SOCKADDR_IN *Address_Sender, char *IP_Address, int *Port)
#endif
{
  #ifdef UNIX
    #ifdef AIX
       int  i;
       char *a;
    #endif

    #ifdef LINUX
       int  i;
       char *a;
    #endif
  #endif

  #ifdef NT
     int  i;
     char *a;
  #endif


  /* getting the address */

  #ifdef NT
     a = inet_ntoa(Address_Sender->sin_addr);
     for (i=0; i<SCK_ADDR_LEN-1; i++) {IP_Address[i] = *(a+i); };
     IP_Address[SCK_ADDR_LEN-1] = 0;

     /* getting the port number */
     *Port = ntohs (Address_Sender->sin_port);
  #endif

  #ifdef UNIX
    #ifdef AIX
       a = inet_ntoa(Address_Sender->sin_addr);
       for (i=0; i<SCK_ADDR_LEN-1; i++) {IP_Address[i] = *(a+i); };
       IP_Address[SCK_ADDR_LEN-1] = 0;
    #endif

    #ifdef LINUX
       a = inet_ntoa(Address_Sender->sin_addr);
       for (i=0; i<SCK_ADDR_LEN-1; i++) {IP_Address[i] = *(a+i); };
       IP_Address[SCK_ADDR_LEN-1] = 0;
    #endif

    #ifdef VXWORKS
       inet_ntoa_b (Address_Sender->sin_addr, IP_Address);
    #endif

    /* getting the port number */
    *Port = ntohs (Address_Sender->sin_port);
  #endif
}

/**************************************************************************/
/*                             Get_Host_Info()                            */
/*                                                                        */
/* Get the hostname and the IP address of the local host.                 */
/*                                                                        */
/* <- hostname: (out) hostname of the local host.                         */
/* <- IP_adrs:  (out) IP address of the host.                             */
/*                                                                        */
/*    return SCK_NAME_ERROR if can't get the hostname                     */
/*           SCK_IP_ERROR if can't get the IP address                     */
/*           SCK_OK if no error                                           */
/*                                                                        */
/* Notes:                                                                 */
/*  o 'hostame' must be at least MAXHOSTNAMELEN characteres long.         */
/*    (should be defined in "sys/param.h".                                */
/*  o 'IP_adrs' must be at least 4 characters long.                       */
/**************************************************************************/

int Get_Host_Info (char *hostname, char *IP_adrs)
{
  #ifdef UNIX
    struct hostent *ht;
  #endif

  #ifdef NT
    struct hostent FAR *ht;
  #endif

  int            i;


  if (gethostname (hostname, MAXHOSTNAMELEN) != 0)  { return SCK_NAME_ERROR; }

  ht = gethostbyname (hostname);
  if (ht == NULL) { return SCK_IP_ERROR; }

  for (i=0; i<4; i++) { IP_adrs[i] = (ht->h_addr_list)[0][i]; }

  return SCK_OK;
}

