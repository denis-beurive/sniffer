#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <signal.h>


/**************************************************************************/
/* sockets.h:                                                             */
/*     General socket management.                                         */
/* packet_filter.h:                                                       */
/*     Get data from packet headers.                                      */
/* dump_headers.h:                                                        */
/*     Print TCP and UDP headers.                                         */
/* dump_body.h:                                                           */
/*     Print packet body.                                                 */
/**************************************************************************/

#include "../commun/sockets.h"
#include "../commun/packet_filter.h"
#include "../commun/packet_handler.h"
#include "../commun/dump_headers.h"
#include "../commun/dump_body.h"
#include "../commun/cline.h"

S_command      flags; /* needs to be accessed by 'clean_stop'.             */
int sock;             /* needs to be accessed by the 'clean_stop' handler  */
                      /* => declare it as "global" ... not clean but it is */
                      /* the easiest and safest solution.                  */

/**************************************************************************/
/*                                     clean_stop                         */
/*                                                                        */
/* Handle for the SIGINT signal (sent when you press [CTRL][C]).          */
/*                                                                        */
/* This function close the socket and restore the initial interface con-  */
/* -figuration => clean stop.                                             */
/**************************************************************************/

void clean_stop (int signo)
{
  fprintf (stdout, "\n\nPerforming a clean exit:");
  fprintf (stdout, "\n- restoring initial interface settings ... ");
  switch (Unset_Promisc(flags.E_interface, sock))
  {
      case SCK_IOCTL_SIOCGIFFLAGS_GET_ERR:
        {
          if (flags.verbose == YES)
          { fprintf (stderr, "\nioctl: can not get interface's flags\n"); }
          else
          { fprintf (stderr, "\nError while configuring the interface\n"); }
          exit (1);
        }
        
      case SCK_IOCTL_SIOCGIFFLAGS_SET_ERR:
        {
          if (flags.verbose == YES)
          { fprintf (stderr, "\nioctl: can not set interface's flags\n"); }
          else
          { fprintf (stderr, "\nError while configuring the interface\n"); }
          exit (1);
        }
        
      case SCK_OK:
        { fprintf (stdout, " OK."); }
        break;
        
      default:
        {
          if (flags.verbose == YES)
          { fprintf (stderr, "\nUnknown return value for Set_Promisc()\n"); }
          else
          { fprintf (stderr, "\nInternal error\n"); }
          exit (1);
        }
  }

  fprintf (stdout, "\n- closing the socket.\n\n\n");
  close (sock);
  exit (0);
}


int main (int argc, char **argv)
{
    int                bytes_recieved;
    int                fromlen;
    int                cr;
    char               buffer[PACKET_BUFF_SIZE];
    struct sockaddr_in from;

    #ifdef DEBUG
    struct in_addr     addr;
    #endif


    if (argc == 1)
    {
      usage();
      return 1;
    }


    /***********************************************************************/
    /*                     Command line options flags                      */
    /***********************************************************************/

    cr = check_command_line (argv, argc, &flags);

    switch (cr)
    {
      case COMMAND_LINE_FROM_IP      :
        {
          fprintf (stderr, "\nSyntax error: invalid IP mask (source)\n");
          fprintf (stderr, "Type \"netdump help\" for help\n\n");
          return 1;        
        }; break;
      case COMMAND_LINE_TO_IP        :
        {
          fprintf (stderr, "\nSyntax error: invalid IP mask (destination)\n");
          fprintf (stderr, "Type \"netdump help\" for help\n\n");
          return 1;        
        }; break;
      case COMMAND_LINE_FROM_PORT    :
        {
          fprintf (stderr, "\nSyntax error: invalid source port number\n");
          fprintf (stderr, "Type \"netdump help\" for help\n\n");
          return 1;        
        }; break;
      case COMMAND_LINE_TO_PORT      :
        {
          fprintf (stderr, "\nSyntax error: invalid destination port number\n");
          fprintf (stderr, "Type \"netdump help\" for help\n\n");
          return 1;        
        }; break;
      case COMMAND_LINE_BODY_OUTPUT  :
        {
          fprintf (stderr, "\nSyntax error: invalid body output specification\n");
          fprintf (stderr, "Type \"netdump help\" for help\n\n");
          return 1;        
        }; break;
      case COMMAND_LINE_IP_HD        :
        {
          fprintf (stderr, "\nSyntax error: invalid IP header output flag\n");
          fprintf (stderr, "Type \"netdump help\" for help\n\n");
          return 1;        
        }; break;
      case COMMAND_LINE_UDP_HD       :
        {
          fprintf (stderr, "\nSyntax error: invalid UDP header output flag\n");
          fprintf (stderr, "Type \"netdump help\" for help\n\n");
          return 1;        
        }; break;
      case COMMAND_LINE_TCP_HD       :
        {
          fprintf (stderr, "\nSyntax error: invalid TCP header output flag\n");
          fprintf (stderr, "Type \"netdump help\" for help\n\n");
          return 1;        
        }; break;
      case COMMAND_LINE_ETH_HD       :
        {
          fprintf (stderr, "\nSyntax error: invalid ethernet header output flag\n");
          fprintf (stderr, "Type \"netdump help\" for help\n\n");
          return 1;        
        }; break;
      case COMMAND_LINE_TCP_PROTO    :
        {
          fprintf (stderr, "\nSyntax error: invalid flag for TCP patcket selection\n");
          fprintf (stderr, "Type \"netdump help\" for help\n\n");
          return 1;        
        }; break;
      case COMMAND_LINE_UDP_PROTO    :
        {
          fprintf (stderr, "\nSyntax error: invalid flag for UDP patcket selection\n");
          fprintf (stderr, "Type \"netdump help\" for help\n\n");
          return 1;        
        }; break;
      case COMMAND_LINE_IGMP_PROTO   :
        {
          fprintf (stderr, "\nSyntax error: invalid flag for TCP patcket selection\n");
          fprintf (stderr, "Type \"netdump help\" for help\n\n");
          return 1;        
        }; break;
      case COMMAND_LINE_ARP_PROTO   :
        {
          fprintf (stderr, "\nSyntax error: invalid flag for ARP patcket selection\n");
          fprintf (stderr, "Type \"netdump help\" for help\n\n");
          return 1;        
        }; break;    
      case COMMAND_LINE_IN_FILE_PROTO:
        {
          fprintf (stderr, "\nSyntax error: File name is missing\n");
          fprintf (stderr, "Type \"netdump help\" for help\n\n");
          return 1;        
        }; break;    
      case COMMAND_LINE_OK           :
        {
          if (flags.verbose == YES)
          fprintf (stdout, "\nCommand line checked OK.\n");
        }; break;
      default :
        {
          fprintf (stderr, "\nCammand line checking - internal error");
          return 1;
        }
    }

    if (flags.help == YES)
    {
      usage();
      return 1;
    }

    /***********************************************************************/
    /*                      Creating the PACKET socket                     */
    /***********************************************************************/

    sock = Open_Link_Socket();
    if (sock == SCK_CREATE_ERROR)
    {
      if (flags.verbose == YES)
      { fprintf (stderr, "\nError while creating the PACKET socket\n"); }
      else
      { fprintf (stderr, "\nError while creating the socket\n"); }
      return 1;
    }

    if (flags.verbose == YES)
    {
      fprintf (stdout, "\nSocket successfully created (%d).", sock);
      fflush (stdout);  
    }
      
    /***********************************************************************/
    /*                  Setting socket in Promiscuous mode                 */
    /***********************************************************************/

    fprintf (stdout, "\nLooking at interface: %s", flags.E_interface);

    switch (Set_Promisc(flags.E_interface, sock))
    {
      case SCK_IOCTL_SIOCGIFFLAGS_GET_ERR:
        {
          if (flags.verbose == YES)
          { fprintf (stderr, "\nioctl: can not get interface's flags\n"); }
          else
          { fprintf (stderr, "\nError while configuring the interface\n"); }
          return 1;
        }
        
      case SCK_IOCTL_SIOCGIFFLAGS_SET_ERR:
        {
          if (flags.verbose == YES)
          { fprintf (stderr, "\nioctl: can not set interface's flags\n"); }
          else
          { fprintf (stderr, "\nError while configuring the interface\n"); }
          return 1;
        }
        
      case SCK_OK:
        { 
          if (flags.verbose == YES)
          { fprintf (stdout, "\nInterface in promiscuous mode - OK.\n"); }
        } 
        break;
        
      default:
        {
          if (flags.verbose == YES)
          { fprintf (stderr, "\nUnknown return value for Set_Promisc()\n"); }
          else
          { fprintf (stderr, "\nInternal error\n"); }
          return 1;
        }
    }

    if (flags.verbose == YES) { fflush(stdout); }

    /***********************************************************************/
    /*                  Setting handler for a clean exit                   */
    /***********************************************************************/

    if (signal (SIGINT, clean_stop) == SIG_ERR)
    {
      fprintf (stderr, "\nCan not set the SIGINT signal handler.\n");
      return 1;
    }

    /***********************************************************************/
    /*                           Receiving messages                        */
    /***********************************************************************/

    while(1)
    {
       /********************************************************************/
       /*                         waiting for message                      */
       /********************************************************************/

       fromlen = sizeof from;
       bytes_recieved = recvfrom(sock, buffer, PACKET_BUFF_SIZE,
                          0, (struct sockaddr *)&from, &fromlen);


       if (Handle_Packet (buffer, bytes_recieved) == HANDLER_ERR)
       {
         close (sock);
         return 1;
       }

    } /* end while */

  return 0;
}
