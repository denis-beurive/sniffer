#ifdef UNIX
  #include <netinet/in.h>
#endif

#ifdef NT
  #include <winsock.h>
#endif

#include <stdio.h>
#include <stdlib.h>

#include "packet_filter.h"
#include "sockets.h"


/***********************************************************************/
/*                         get_src_port_number                         */
/*                                                                     */
/* Return the port number of the sender, if (of course) the protocol   */
/* UDP or TCP. Otherwise return the value PORT_UNDEFINED.              */
/***********************************************************************/

int get_src_port_number (char *buff)
{
  switch (PROTOCOL(buff))
  {
    case TCP_PACKET:
         { return (ntohs((TCP_HEADER(buff))->tcp_source_port)); };
    case UDP_PACKET:
         { return (ntohs((UDP_HEADER(buff))->udp_source_port)); };
    default:
         { return PORT_UNDEFINED; }
  }
}

/***********************************************************************/
/*                         get_dst_port_number                         */
/*                                                                     */
/* Return the port number of the destination, if (of course) the       */
/* protocol UDP or TCP. Otherwise return the value PORT_UNDEFINED.     */
/***********************************************************************/

int get_dst_port_number (char *buff)
{
  switch (PROTOCOL(buff))
  {
    case TCP_PACKET:
         { return (ntohs((TCP_HEADER(buff))->tcp_dest_port)); };
    case UDP_PACKET:
         { return (ntohs((UDP_HEADER(buff))->udp_dest_port)); };
    default:
         { return PORT_UNDEFINED; }
  }
}

/***********************************************************************/
/*                              body_info                              */
/*                                                                     */
/* Get the offset and the size of the UDP/TCP body.                    */
/*                                                                     */
/* -> buff:   (in) data read from socket.                              */
/* <- off:    (out) body offset.                                       */
/* <- size:   (out) size of the body.                                  */
/*                                                                     */
/* Note: - if the packet is not UDP or TCP then the body begins just   */
/*         after the IP header.                                        */
/*       - the offset is relative to the start of the buffer.          */
/***********************************************************************/

void body_info (char *buff, unsigned int *off, unsigned int *size)
{
  unsigned int  ip_total_size;
  unsigned int  ip_header_size;
  unsigned int  udp_tcp_hd_size;

  /**************************************************************************/
  /*                                IP header                               */
  /**************************************************************************/

  /* IMPORTANT WARNING:                                      */
  /*   The 2 followinf lines are *NOT* always valid for IGMP */
  /*   The next 'switch' statement override these 2 lines    */
  /*   in the case of IGMP.                                  */

  ip_total_size  = ntohs((IP_HEADER(buff))->ip_total_length);
  ip_header_size = ((IP_HEADER(buff))->ip_length)*4;

  /**************************************************************************/
  /*                        UDP / TCP / Other header                        */
  /*                                                                        */
  /* WARNING !!                                                             */
  /*   - the IGMP protocol has a fixed size of header / body.               */
  /**************************************************************************/

  switch (PROTOCOL(buff)) 
  {
    case UDP_PACKET:  { udp_tcp_hd_size = 8; }; break;
    case TCP_PACKET:  { udp_tcp_hd_size = ((TCP_HEADER(buff))->tcp_hlen)*4; };
                      break;

    /* WARNING: after this line all protocol have a 'udp_tcp_hd_size' of 0 */

    case IGMP_PACKET: {
                        ip_total_size   = 28;
                        ip_header_size  = 20;
                        udp_tcp_hd_size = 0;
                      }; break;
    default: { udp_tcp_hd_size = 0; }
  } 

  *off  = ETH_HD_LEN + ip_header_size + udp_tcp_hd_size;
  *size = ip_total_size - ip_header_size - udp_tcp_hd_size; 
}

/***********************************************************************/
/*                              get_addr                               */
/*                                                                     */
/* Convert an network ordered IP address into a 4 intergers long mask. */
/*                                                                     */
/* -> addr: (in) network ordered IP address.                           */
/* <- mask: (out) IP mask.                                             */
/***********************************************************************/

void get_addr (unsigned int addr, int *mask)
{
  /* WARNING ! On little endian architectures bytes are reversed */

  #ifdef LITTLE_ENDIAN_BITFIELD
    mask[3] = (int)((addr & 0xFF000000) >> 24);
    mask[2] = (int)((addr & 0x00FF0000) >> 16);
    mask[1] = (int)((addr & 0x0000FF00) >> 8);
    mask[0] = (int) (addr & 0x000000FF);
  #else
    mask[0] = (int)((addr & 0xFF000000) >> 24);
    mask[1] = (int)((addr & 0x00FF0000) >> 16);
    mask[2] = (int)((addr & 0x0000FF00) >> 8);
    mask[3] = (int) (addr & 0x000000FF);
  #endif
}

/***********************************************************************/
/*                                set_mask                             */
/*                                                                     */
/* Build a mask from a user characters string that may have jocker cha-*/
/* -racters.                                                           */
/*                                                                     */
/* -> addr: (in) user IP mask (ex: "192.41.@.@").                      */
/* <- mask: (out) mask associated with the user IP mask.               */
/*                                                                     */
/* Return value:                                                       */
/*   GOOD_MASK: OK                                                     */
/*   BAD_MASK: invalid user IP mask.                                   */
/*                                                                     */
/* Note: the "@" (jocker) is translated into the value -1.             */
/***********************************************************************/

int set_mask (char *addr, int *mask)
{
  char buff[4], *c;
  int  i, d;
  
  c = addr;
  
  for (d=0; d<4; d++)
  {
    i = 0;
    while ((*c != '.') && (*c != 0))
    {
      buff[i++] = *c;
      c++;
      if (i>3) { return BAD_MASK; }
    }
    buff[i]=0;
    c++;
    
    if (buff[0] == '@') { mask[d] = -1; }
    else { mask[d] = atoi(buff); }
  }

  return GOOD_MASK;
}

/***********************************************************************/
/*                              test_address                           */
/*                                                                     */
/* Test if an address matches a mask.                                  */
/*                                                                     */
/* -> addr: (in) address to test (4 integers array long).              */
/* -> mask: (in) user IP mask.                                         */
/*                                                                     */
/* Retuen value:                                                       */
/*    0: adddress matchets the mask.                                   */
/*    1: adddress does not match that mask.                            */
/***********************************************************************/


int test_address (int *addr, int *mask)
{
  int i, comp;
  
  comp = 0;
  for (i=0; i<4; i++)
  {
    if ((addr[i] != mask[i]) && (mask[i] != -1))
    { comp = 1; break; }
  }

  return comp;
}

