#include <stdio.h>

#ifdef UNIX
  #include <netinet/in.h>
  #include <sys/socket.h>
  #include <arpa/inet.h>
#endif

#ifdef NT
  #include <winsock.h>
#endif

#include "sockets.h" 
#include "dump_headers.h"
#include "packet_filter.h"

#define IP_PRINT(f,x)  fprintf (f, "\n"); fprintf (f, x); 
#define UDP_PRINT(f,x) fprintf (f, "\n"); fprintf (f, x); 
#define TCP_PRINT(f,x) fprintf (f, "\n"); fprintf (f, x);
#define ETH_PRINT(f,x) fprintf (f, "\n"); fprintf (f, x);
#define ARP_PRINT(f,x) fprintf (f, "\n"); fprintf (f, x);
#define RIP1_PRINT(f,x) fprintf (f, "\n"); fprintf (f, x);




/***************************************************************************/
/*                                IP headers                               */
/***************************************************************************/

void print_proto (int proto)
{
     switch(proto)
     {
       case TCP_PACKET  : fprintf (stdout, "TCP");   break;
       case UDP_PACKET  : fprintf (stdout, "UDP");   break;
       case ICMP_PACKET : fprintf (stdout, "ICMP");  break;
       case IGMP_PACKET : fprintf (stdout, "IGMP");  break;
       case IPIP_PACKET : fprintf (stdout, "IPIP");  break;
       case EGP_PACKET  : fprintf (stdout, "EGP");   break;
       case PUP_PACKET  : fprintf (stdout, "PUP");   break;
       case IDP_PACKET  : fprintf (stdout, "IDP");   break;
       case RSVP_PACKET : fprintf (stdout, "RSVP");  break;
       case GRE_PACKET  : fprintf (stdout, "GRE");   break;
       case IPV6_PACKET : fprintf (stdout, "IPV6");  break;
       case PIM_PACKET  : fprintf (stdout, "PIM");   break;
       case RAW_PACKET  : fprintf (stdout, "RAW");   break;
       default          : fprintf (stdout, "???");
     }
}

void dump_ip_header (IP_Header *hd, int v)
{
   unsigned char   uchar, aux;
   unsigned short  s;
   struct in_addr  addr;

   if (v == LONG_DESC)
   {

   /***********************************************************************/
   /*                             IP version                              */
   /***********************************************************************/

   IP_PRINT(stdout, "IP version              : ")
   fprintf (stdout, "%u", hd->ip_version);

   /***********************************************************************/
   /*                           IP header length                          */
   /***********************************************************************/

   IP_PRINT(stdout, "IP header length        : ")
   fprintf (stdout, "%u", hd->ip_length);
   if (hd->ip_length < 5)
   { fprintf (stdout, " (error, IP length must be greater than 5)"); }
   else
   { fprintf (stdout, " (4*%d=%d bytes)", hd->ip_length, hd->ip_length*4); }

   /***********************************************************************/
   /*                            Type of service                          */
   /***********************************************************************/

   IP_PRINT(stdout, "IP type of service      : ")
   uchar = hd->ip_tos;
   /* extracting bits 0,1,2 */
   fprintf (stdout, "precedence - ");
   
   fprintf (stdout, "%d%d%d ", 
                    (uchar & 0x80) >> 7,
                    (uchar & 0x40) >> 6,
                    (uchar & 0x20) >> 5);

   aux = (uchar & 0xE0) >> 5;
   switch (aux)
   {
     case 0x07: fprintf (stdout, "(Network Control)"); break;
     case 0x06: fprintf (stdout, "(Internetwork Control)"); break;
     case 0x05: fprintf (stdout, "(CRITIC/ECP)"); break;
     case 0x04: fprintf (stdout, "(Flash Override)"); break;
     case 0x03: fprintf (stdout, "(Flash)"); break;
     case 0x02: fprintf (stdout, "(Immediate)"); break;
     case 0x01: fprintf (stdout, "(Priority)"); break;
     case 0x00: fprintf (stdout, "(Routine)"); break;
     default  : fprintf (stdout, "(Unknown value, internal error)");
   }

   /* extracting bit 3 */
   IP_PRINT(stdout, "                          ");
   fprintf (stdout, "Delay - "); 
   aux = (uchar & 0x10) >> 4;
   fprintf (stdout, "%u ", aux);

   switch (aux)
   {
     case 0 : fprintf (stdout, "(Normal)"); break;
     case 1 : fprintf (stdout, "(Low)"); break;
     default: fprintf (stdout, "(Unknown value, internal error)");
   }

   /* extracting bit 4 */
   IP_PRINT(stdout, "                          ");
   fprintf (stdout, "Throughput - "); 
   aux = (uchar & 0x08) >> 3;
   fprintf (stdout, "%u ", aux);

   switch (aux)
   {
     case 0 : fprintf (stdout, "(Normal)"); break;
     case 1 : fprintf (stdout, "(High)"); break;
     default: fprintf (stdout, "(Unknown value, internal error)");
   }

   /* extracting bit 5 */
   IP_PRINT(stdout, "                          ");
   fprintf (stdout, "Reliability - "); 
   aux = (uchar & 0x04) >> 2;
   fprintf (stdout, "%u ", aux);

   switch (aux)
   {
     case 0 : fprintf (stdout, "(Normal)"); break;
     case 1 : fprintf (stdout, "(High)"); break;
     default: fprintf (stdout, "(Unknown value, internal error)");
   }

   /***********************************************************************/
   /*                            Total length                             */
   /***********************************************************************/

   IP_PRINT(stdout, "IP total length         : ")
   fprintf (stdout, "%u", ntohs(hd->ip_total_length));
   fprintf (stdout, " bytes"); 

   /***********************************************************************/
   /*                         identification number                       */
   /***********************************************************************/

   IP_PRINT(stdout, "IP id                   : ")
   fprintf (stdout, "%u", ntohs(hd->ip_id));

   /***********************************************************************/
   /*                                    Flags                            */
   /***********************************************************************/

   IP_PRINT(stdout, "IP flags                : ")

   s = hd->ip_flags; /* network order (big endian) */
   uchar = (unsigned char)((s & 0x4000) >> 8);

   /* extracting bit 1 */
   fprintf (stdout, "bit number 1 - "); 
   aux = (uchar & 0x40) >> 6;
   fprintf (stdout, "%u ", aux);

   switch (aux)
   {
     case 0 : fprintf (stdout, "(May Fragment)"); break;
     case 1 : fprintf (stdout, "(Don't Fragment)"); break;
     default: fprintf (stdout, "(Unknown value, internal error)");
   }
      
   /* extracting bit 2 */
   IP_PRINT(stdout, "                          ")
   fprintf (stdout, "bit number 2 - "); 
   aux = (uchar & 0x20) >> 5;
   fprintf (stdout, "%u ", aux);

   switch (aux)
   {
     case 0 : fprintf (stdout, "(Last Fragment)"); break;
     case 1 : fprintf (stdout, "(More Fragments)"); break;
     default: fprintf (stdout, "(Unknown value, internal error)");
   }

   /***********************************************************************/
   /*                             Fragment's position                     */
   /***********************************************************************/

   IP_PRINT(stdout, "IP fragment pos         : ")   
   /* 0x1FFFF = 00011111.11111111  --  3 first bytes set to 0 */
   /* and then converting into "host order" if necessary.     */
   s = s & 0x1FFF;
   s = ntohs(s);
   fprintf (stdout, "%u ", s);
   fprintf (stdout, "(%u*8=%u bytes)", s, s*8); 

   /***********************************************************************/
   /*                             Time to live                            */
   /***********************************************************************/

   IP_PRINT(stdout, "IP ttl                  : ")
   fprintf (stdout, "%u", hd->ip_ttl);

   /***********************************************************************/
   /*                               Protocol                              */
   /***********************************************************************/

   IP_PRINT(stdout, "IP protocol             : ")
   fprintf (stdout, "%u ", hd->ip_protocol);
   print_proto (hd->ip_protocol); 

   /***********************************************************************/
   /*                               Checksum                              */
   /***********************************************************************/

   IP_PRINT(stdout, "IP checksum             : ")
   fprintf (stdout, "%u", ntohs(hd->ip_cksum));

   /***********************************************************************/
   /*                                Source                               */
   /***********************************************************************/

   IP_PRINT(stdout, "IP source               : ")
   addr.s_addr = hd->ip_source;
   fprintf (stdout, "%s", inet_ntoa(addr));

   /***********************************************************************/
   /*                             Destination                             */
   /***********************************************************************/
 
   IP_PRINT(stdout, "IP destination          : ")
   addr.s_addr = hd->ip_dest;
   fprintf (stdout, "%s", inet_ntoa(addr));

   }     /* if on v == LONG_DESC */
   else
   {
   addr.s_addr = hd->ip_source;
   fprintf (stdout, "\nIP            : %s => ", inet_ntoa(addr));
   addr.s_addr = hd->ip_dest;
   fprintf (stdout, "%s", inet_ntoa(addr));
   }
}

/***************************************************************************/
/*                               UDP headers                               */
/***************************************************************************/

void dump_udp_header (UDP_Header *hd, int v)
{
   if (v == LONG_DESC)
   {
   UDP_PRINT(stdout, "UDP source port         : ")
   fprintf (stdout, "%u", ntohs(hd->udp_source_port));

   UDP_PRINT(stdout, "UDP destination port    : ")
   fprintf (stdout, "%u", ntohs(hd->udp_dest_port));

   UDP_PRINT(stdout, "UDP length              : ")
   fprintf (stdout, "%u", ntohs(hd->udp_length));

   UDP_PRINT(stdout, "UDP checksum            : ")
   fprintf (stdout, "%u", ntohs(hd->udp_cksum));
   } /* if on v == LONG_DESC */
   else
   {
   fprintf (stdout, "\nPort          : %d => %d (UDP)", ntohs(hd->udp_source_port), ntohs(hd->udp_dest_port));
   }
}

/***************************************************************************/
/*                              TCP header                                 */
/***************************************************************************/

int dump_tcp_header (TCP_Header *hd, int v)
{
   unsigned char uchar;
   int           err;

   if (v == LONG_DESC)
   {
   err = HD_OK;

   TCP_PRINT(stdout, "TCP source port         : ")
   fprintf (stdout, "%u", ntohs(hd->tcp_source_port));

   TCP_PRINT(stdout, "TCP destination port    : ")
   fprintf (stdout, "%u", ntohs(hd->tcp_dest_port));

   TCP_PRINT(stdout, "TCP sequence number     : ")
   fprintf (stdout, "%u", ntohl(hd->tcp_seqno));

   TCP_PRINT(stdout, "TCP ack number          : ")
   fprintf (stdout, "%u", ntohl(hd->tcp_ackno));
   
   /***********************************************************************/
   /*             LITTLE/BIG ENDIAN dependant -- see sockets.h            */
   /***********************************************************************/

   TCP_PRINT(stdout, "TCP header length       : ")
   uchar = hd->tcp_hlen;
   fprintf (stdout, "%u", uchar);
   if (hd->tcp_hlen < 5) { err = HD_ERROR; }
   if (hd->tcp_hlen < 5)
   { fprintf (stdout, " (Impossible, minimum is 5)"); }
   else
   { fprintf (stdout, " (4*%u=%u bytes)", hd->tcp_hlen, hd->tcp_hlen*4); }

   TCP_PRINT(stdout, "TCP reserved bits       : ")
   uchar = hd->tcp_reserved_1;
   fprintf (stdout, "%d", uchar & 0x01);         /* 0001 */
   fprintf (stdout, "%d", (uchar & 0x02) >> 1);  /* 0010 */
   fprintf (stdout, "%d", (uchar & 0x04) >> 2);  /* 0100 */
   fprintf (stdout, "%d", (uchar & 0x08) >> 3);  /* 1000 */
   uchar = hd->tcp_reserved_2;
   fprintf (stdout, "%d", uchar & 0x01);         /* 0001 */
   fprintf (stdout, "%d", (uchar & 0x02) >> 1);  /* 0010 */

   TCP_PRINT(stdout, "TCP urgent flag         : ")
   fprintf (stdout, "%u", hd->tcp_urg);

   TCP_PRINT(stdout, "TCP ACK                 : ")
   fprintf (stdout, "%u", hd->tcp_ack);

   TCP_PRINT(stdout, "TCP Push flag           : ")
   fprintf (stdout, "%u", hd->tcp_psh);
   if (hd->tcp_psh == 1)  
   { fprintf (stdout, " (receiver must pass data to the application)"); }

   TCP_PRINT(stdout, "TCP Reset flag          : ")
   fprintf (stdout, "%u", hd->tcp_rst);

   TCP_PRINT(stdout, "TCP SYN                 : ")
   fprintf (stdout, "%u", hd->tcp_syn);

   TCP_PRINT(stdout, "TCP FIN flag            : ")
   fprintf (stdout, "%u", hd->tcp_fin);
   if (hd->tcp_fin == 1)
   { fprintf (stdout, " (end of data flow)"); }
  

   TCP_PRINT(stdout, "TCP window size         : ")
   fprintf (stdout, "%u", ntohs(hd->tcp_winsize));

   TCP_PRINT(stdout, "TCP checksum            : ")
   fprintf (stdout, "%u", ntohs(hd->tcp_cksum));

   TCP_PRINT(stdout, "TCP urgent pointer      : ")
   fprintf (stdout, "%u", ntohs(hd->tcp_urgent));
   } /* if on v == LONG_DESC */
   else
   {
   fprintf (stdout, "\nPort          : %d => %d (TCP)", ntohs(hd->tcp_source_port), ntohs(hd->tcp_dest_port));
   }

   return err;
}



/***************************************************************************/
/*                         Ethernet header                                 */
/***************************************************************************/

void dump_eth_header (ETH_Header *hd, int v)
{
   int i;

   if (v == LONG_DESC)
   {
     ETH_PRINT(stdout, "ETH destination address : ")
     for (i=0; i<ETH_ADDR_LEN-1; i++)
     { fprintf (stdout, "%2x:", (hd->addr_dest)[i]); }
     fprintf (stdout, "%2x", (hd->addr_dest)[ETH_ADDR_LEN-1]);
     if ((ETH_ADDR_DEST_TYPE(hd)) == ETH_UNICAST)
     { fprintf (stdout, " - Unicast -"); }
     else
     {
       if (ETH_ADDR_BROADCAST(hd->addr_dest))
       { fprintf (stdout, " - Broadcast -"); }
       else
       { fprintf (stdout, " - Multicast -"); }
     }
   
     ETH_PRINT(stdout, "ETH sender address      : ")
     for (i=0; i<ETH_ADDR_LEN-1; i++)
     { fprintf (stdout, "%2x:", (hd->addr_src)[i]); }
     fprintf (stdout, "%2x", (hd->addr_src)[ETH_ADDR_LEN-1]);
     if ((ETH_ADDR_SRC_TYPE(hd)) == ETH_UNICAST)
     { fprintf (stdout, " - Unicast -"); }
     else
     { 
       if (ETH_ADDR_BROADCAST(hd->addr_src))
       { fprintf (stdout, " - Broadcast -"); }
       else
       { fprintf (stdout, " - Multicast -"); }     
     }

     if (ETH_FORMAT(hd) == ETHERNET_II)
     {
       ETH_PRINT(stdout, "ETH Ethernet II type    : ")
       fprintf (stdout, "0x%x", ntohs(hd->type));
       switch (ntohs(hd->type))
       { 
         case PUP_ETH    :  fprintf (stdout, " (Xerox PUP)"); break;
         case IP_ETH     :  fprintf (stdout, " (IP)"); break;
         case ARP_ETH    :  fprintf (stdout, " (ARP)"); break;
         case REVARP_ETH :  fprintf (stdout, " (Revers ARP)"); break;
         default: fprintf (stdout, " (Unknown)");
       }
     }
     else
     {
       ETH_PRINT(stdout, "ETH IEEE 802.3 length   : ")
       fprintf (stdout, "%d bytes", ntohs(hd->type));
     }
   }
   else
   {
     fprintf (stdout, "\nEthernet type : 0x%x", ntohs(hd->type));
     switch (ntohs(hd->type))
     {
       case PUP_ETH    :  fprintf (stdout, " (Xerox PUP)"); break;
       case IP_ETH     :  fprintf (stdout, " (IP)"); break;
       case ARP_ETH    :  fprintf (stdout, " (ARP)"); break;
       case REVARP_ETH :  fprintf (stdout, " (Revers ARP)"); break;
       default: fprintf (stdout, " (Unknown)");
     }   
   }
}


/***************************************************************************/
/*                              ARP header                                 */
/***************************************************************************/

int dump_ARP_header (ARP_Header *hd, int v)
{
   int             aux;
   struct in_addr  addr;
   unsigned int    *adr;



     /**********************************************************/
     /*                    Hardware type                       */
     /**********************************************************/

     aux = ntohs(hd->hardware_type);
   
     ARP_PRINT(stdout, "ARP hardware type       : ")
     fprintf (stdout, "%d", aux);

     switch (aux)
     {
       case 1:  fprintf (stdout, " - Ethernet (10 Mb)"); break;
       case 2:  fprintf (stdout, " - Experimental Ethernet (3Mb)"); break;
       case 3:  fprintf (stdout, " - Amateur radio AX25"); break;
       case 4:  fprintf (stdout, " - Proteon ProNET Token Ring"); break;
       case 5:  fprintf (stdout, " - Chaos"); break;
       case 6:  fprintf (stdout, " - IEEE 803 networks"); break;
       case 7:  fprintf (stdout, " - ARCNET"); break;
       case 8:  fprintf (stdout, " - Hyperchannel"); break;
       case 9:  fprintf (stdout, " - Lanstar"); break;
       case 10: fprintf (stdout, " - Autonet short address"); break;
       case 11: fprintf (stdout, " - LocalTalk"); break;
       case 12: fprintf (stdout, " - LocalNet"); break;
       case 13: fprintf (stdout, " - Ultra link"); break;
       case 14: fprintf (stdout, " - SMDS"); break;
       case 15: fprintf (stdout, " - Frame relay"); break;
       case 16: fprintf (stdout, " - ATM"); break;
       default: fprintf (stdout, " - unknown");
     }

     /**********************************************************/
     /*                      protocol type                     */
     /**********************************************************/
     
     aux = ntohs(hd->protocol_type);
     
     ARP_PRINT(stdout, "ARP protocol type       : ")
     fprintf (stdout, "0x%X", aux);
     
     switch (aux)
     {
       case PUP_ETH    :  fprintf (stdout, " match (Xerox PUP) address"); break;
       case IP_ETH     :  fprintf (stdout, " match (IP) address"); break;
       case ARP_ETH    :  fprintf (stdout, " match (ARP) address"); break;
       case REVARP_ETH :  fprintf (stdout, " match (Revers ARP) address"); break;
       default: fprintf (stdout, " match (Unknown) address type");
     }   

     /**********************************************************/
     /*                     hardware length                    */
     /**********************************************************/

     ARP_PRINT(stdout, "ARP hardware length     : ")
     fprintf (stdout, "%d", hd->hardware_length);
     
     if (hd->hardware_length != 6)
     {
       fprintf (stdout, " - Not a valid ethernet address length / skipping");
       return 0;
     }

     /**********************************************************/
     /*             protocol address length                    */
     /**********************************************************/

     ARP_PRINT(stdout, "ARP proto addr length   : ")
     fprintf (stdout, "%d", hd->protocol_length);

     if (hd->protocol_length != 4)
     {
       fprintf (stdout, " - Not a valid IP address length / skipping");
       return 0;
     }

     /**********************************************************/
     /*            ARP operation (request or reply)            */
     /**********************************************************/
       
     aux = ntohs(hd->operation);

     ARP_PRINT(stdout, "ARP operation           : ")
     fprintf (stdout, "%d", aux);

     switch (aux)
     {
       case 1:  fprintf (stdout, " - request"); break;
       case 2:  fprintf (stdout, " - reply"); break;
       default: fprintf (stdout, " - unknown / skipping"); return 0;
     }     

     /**********************************************************/
     /*              ARP Source hardware address               */
     /**********************************************************/

     ARP_PRINT(stdout, "ARP src hard address    : ")
     for (aux=0; aux<hd->hardware_length-1; aux++)
     {
       fprintf (stdout, "%2x:", hd->addr_sender[aux]);
     }
     fprintf (stdout, "%2x", hd->addr_sender[aux]);
     
     /**********************************************************/
     /*                  ARP Source IP address                 */
     /**********************************************************/
     
     adr         = (unsigned int*)(hd->source_proto_addr);
     addr.s_addr = *adr;
     ARP_PRINT(stdout, "ARP source IP address   : ");
     fprintf (stdout, "%s", inet_ntoa(addr));
 
     /**********************************************************/
     /*              ARP Target hardware address               */
     /**********************************************************/
 
     ARP_PRINT(stdout, "ARP target hard address : ")

     for (aux=0; aux<hd->hardware_length-1; aux++)
     { fprintf (stdout, "%2x:", hd->addr_target[aux]); }
     fprintf (stdout, "%2x", hd->addr_target[aux]);
     
     /**********************************************************/
     /*              ARP destination IP address                */
     /**********************************************************/

     adr         = (unsigned int*)(hd->target_proto_addr);
     addr.s_addr = *adr;
     ARP_PRINT(stdout, "ARP target IP address   : ");
     fprintf (stdout, "%s", inet_ntoa(addr));

     return 0;
}

/***************************************************************************/
/*                               RIP header                                */
/***************************************************************************/

int dump_rip1_header (char *buff, int v)
{
   int              i, rn, j;
   RIP1_Header      *hd;
   RIP1_Data_Record *dr;
   
   hd = RIP1_HEADER(buff);

   RIP1_PRINT(stdout, "RIP1 command            : ");
   fprintf (stdout, "%d", RIP_COMMAND(buff));

   switch (RIP_COMMAND(buff))
   {
     case RIP1_REQUEST:  fprintf (stdout, " (request)"); break;
     case RIP1_REPLY:    fprintf (stdout, " (reply)"); break;
     case RIP1_SUN:      fprintf (stdout, " (SUM special)"); break;
     default: fprintf (stdout, " (unknown: error ???)");
   }

   RIP1_PRINT(stdout, "RIP1 version            : ");
   fprintf (stdout, "%d", RIP_VERSION(buff));

   RIP1_PRINT(stdout, "RIP1 protocol           : ");
   fprintf (stdout, "%d", ntohs(hd->proto));

   if (ntohs(hd->proto) == RIP1_IP)
   { fprintf (stdout, " (IP)"); }
   else
   { fprintf (stdout, " (unknown: error ???)"); }

   /************************************************************/
   /*   Dump routing data only if the message is a RIP reply   */
   /************************************************************/

   if (RIP_COMMAND(buff) == RIP1_REPLY)
   {
     rn = RIP1_RECORD_NUMBER(buff);

     RIP1_PRINT(stdout, "RIP1 number of records  : ");
     fprintf (stdout, "%d", rn);

     for (i=0; i<rn; i++)
     {
       dr = RIP1_DATA(buff,i);

       /* print network IP address */
       RIP1_PRINT(stdout, "             ");
       for (j=0; j<3; j++)
       { fprintf (stdout, "%d.", (dr->network_addr)[j]); }
       fprintf (stdout, "%d",  (dr->network_addr)[3]);

       /* print network hops */
       fprintf (stdout, "   %d hop(s)",  ntohl(dr->hops));
     }
   }

   
   return 0;
}


