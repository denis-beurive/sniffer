#ifdef UNIX
  #include <netinet/in.h>
#endif

#ifdef NT
  #include <winsock.h>
#endif

#include <stdio.h>
#include "sockets.h"
#include "packet_filter.h"
#include "dump_headers.h"
#include "dump_body.h"
#include "packet_handler.h"
#include "cline.h"


extern S_command flags;


int Handle_Packet (char *buffer, int bytes_recieved)
{
    IP_Header     *ip;
    int           from_mask[4], to_mask[4];
    unsigned int  body_offset, body_size;    
       

     #ifdef DEBUG
     #ifdef UNIX

       addr.s_addr = IP_FROM(buffer);
       fprintf (stdout, "\n%s", inet_ntoa(addr));
       if (test_address (from_mask, flags.from_ip_mask) == 0)
       { fprintf (stdout, " (Src OK)"); }
       else
       { fprintf (stdout, " (Src WRONG)"); }

       addr.s_addr = IP_TO(buffer);
       fprintf (stdout, "\n%s", inet_ntoa(addr));
       if (test_address (to_mask, flags.to_ip_mask) == 0)
       { fprintf (stdout, " (Dest OK)"); }
       else
       { fprintf (stdout, " (Dest WRONG)"); }

       fprintf (stdout, "\nProtocol: %d", PROTOCOL(buffer));

     #endif
     #endif

     /********************************************************/
     /*               Dumping ethernet headers ?             */
     /********************************************************/
 
     if (flags.eth_hd == YES)
     { dump_eth_header(ETH_HEADER(buffer), flags.desc); }

     if (ETH_FORMAT(buffer) != ETHERNET_II) { return HANDLER_OK; }

     /********************************************************/
     /*                   Dump *IP* stuff *ONLY*             */
     /********************************************************/

     if (ETH_TYPE(buffer) == IP_ETH)
     {

        /********************************************************/
        /* Set IP masks                                         */
        /********************************************************/

        get_addr (IP_FROM(buffer), from_mask);
        get_addr (IP_TO(buffer), to_mask);

        /*******************************************************/
        /* Checking IP address with mask                       */
        /* Checking port numbers                               */
        /* Checking protocol                                   */
        /* ...                                                 */
        /*******************************************************/

        if
        (
          (test_address (from_mask, flags.from_ip_mask) == 0)
          &&
          (test_address (to_mask, flags.to_ip_mask) == 0)
          && (
               (flags.from_port_num == ALL_PORT)
               ||
               (get_src_port_number(buffer) == flags.from_port_num)
             )
          && (
               (flags.to_port_num == ALL_PORT)
               ||
               (get_dst_port_number(buffer) == flags.to_port_num)
             )
          && (
               (
                 (PROTOCOL(buffer) == UDP_PACKET)
                 &&
                 (flags.proto_udp == YES)
               )
               ||              
               (
                 (PROTOCOL(buffer) == TCP_PACKET)
                 &&
                 (flags.proto_tcp == YES)
               )
               ||              
               (
                 (PROTOCOL(buffer) == IGMP_PACKET)
                 &&
                 (flags.proto_igmp == YES)
               )
             ) /* end test on protocol */
        ) /* end if condition statement */
        {
          /******************************************************************/
          /* Sanity check                                                   */
          /******************************************************************/

          ip = IP_HEADER(buffer);
          if (
                ((ntohs(ip->ip_total_length)+ETH_HD_LEN) > bytes_recieved)
                &&
               (flags.verbose == YES)
             )
          {
             fprintf (stdout, "\nWARNING: received %d bytes", bytes_recieved);
             fprintf (stdout, "\n         total packet size ");
             fprintf (stdout, "%d bytes", ntohs(ip->ip_total_length)+ETH_HD_LEN);
             fprintf (stdout, "\n\nThis may be a network error ... skipping");
             fprintf (stdout, " the packet.\n");
             fflush (stdout);
             return HANDLER_OK;
          }

          /******************************************************************/
          /* Dump the IP header if requested                                */
          /******************************************************************/

          if (flags.ip_hd == YES) { dump_ip_header(ip, flags.desc); }

          /******************************************************************/
          /* Dump the following headers if requested:                       */
          /*    - UDP                                                       */
          /*    - TCP                                                       */
          /*                                                                */
          /* In the case of UDP, it may be a RIP message.                   */
          /******************************************************************/

          if (PROTOCOL(buffer) == UDP_PACKET)
          {
             if (flags.udp_hd == YES)
             { dump_udp_header(UDP_HEADER(buffer), flags.desc); }
             
             switch (UDP_SRC_PORT(buffer))
             {
               case SER_RIP:
                    if (RIP_VERSION(buffer) == 1)
                    { dump_rip1_header (buffer, flags.desc); }
                    else
                    { fprintf (stdout, "\nRIP version 2 !"); };
                    break;
               
               default:;
             }
          }

          if ((PROTOCOL(buffer) == TCP_PACKET) && (flags.tcp_hd == YES))
          { dump_tcp_header(TCP_HEADER(buffer), flags.desc); }

          /********************************************************************/
          /* Dump the packet bopy for the following protocols if requested:   */
          /*    - TCP                                                         */
          /*    - UDP                                                         */
          /*    - IGMP                                                        */
          /*                                                                  */
          /* Note that for IGMP the IGMP header is not separated from the bo- */
          /* -dy.                                                             */
          /********************************************************************/

          if (flags.body_level != BD_NONE)
          {
            /* Get offset and size of the body */
            body_info (buffer, &body_offset, &body_size);

           switch (flags.body_level)
           {
              case BD_HEXA   : dump_hexa (buffer+body_offset, body_size);
                               break;
              case BD_ASCII  : dump_ascii (buffer+body_offset, body_size);
                               break;
              case BD_MIX    : dump (buffer+body_offset, body_size); break;
              default : {
                          if (flags.verbose == YES)
                          { fprintf (stderr, "\nUnknown dump_body option\n"); }
                          else
                          { fprintf (stderr, "\nInternal error\n"); }
                          return HANDLER_ERR;
                        }
            } /* end switch (dump_body) */
          } /* end if for UDP/TCP/dump_body */
        } 

        return HANDLER_OK;       
     } /* end if for *IP* stuff *ONLY* */

     /*****************************************************/
     /* So it is not an IP stuff                          */
     /*****************************************************/

     /******************************************************/
     /*  May be it is ARP ?                                */
     /******************************************************/

     if ((ETH_TYPE(buffer) == ARP_ETH) && (flags.proto_arp == YES))
     {
        dump_ARP_header (ARP_HEADER(buffer), flags.desc);
     }


     return HANDLER_OK;       

}
