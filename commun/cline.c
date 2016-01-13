#include <stdio.h>
#include <string.h>  /* for strcmp */
#include <stdlib.h>  /* for atoi   */
#include "cline.h"
#include "packet_filter.h"


#define ERR(x) fprintf(stdout, x);

void usage(void)
{
  ERR("  netdump [udp {on|off}] [tcp {on|off}] [igmp {on|off}] [arp {on|off}]\n")
  ERR("          [from_ip IP_mask] [to_ip IP_mask] [from_port port_number]\n")
  ERR("          [to_port port_number] [body_as {none|ascii|hexa|mix}]\n")
  ERR("          [ip_hd {on|off}] [udp_hd {on|off}] [tcp_hd {on|off}]\n") 
  ERR("          [eth_hd {on|off}] [verbose] [{short_desc|long_desc}]\n");
  ERR("          [in_file FileName] [from_file FileName] interface\n");
  ERR("  netdump help\n\n")

  ERR("\n          interface: name of the interface to look at (ex: \"eth0\").")
  ERR("\n                     You can use the \"ifconfig\" command to print ")
  ERR("\n                     the list of all available interface on your ")
  ERR("\n                     system.\n\n\n")
  ERR("Options:\n")

  ERR("\n          udp      : - on    - dump UDP packets")
  ERR("\n                     - off   - ignore UDP packets")

  ERR("\n          tcp      : - on    - dump TCP packets")
  ERR("\n                     - off   - ignore TCP packets")

  ERR("\n          igmp     : - on    - dump IGMP packets")
  ERR("\n                     - off   - ignore IGMP packets")
  
  ERR("\n          arp      : - on    - dump ARP packets")
  ERR("\n                     - off   - ignore ARP packets")

  ERR("\n          from_ip  : dump packets from hosts whose IP addresses")
  ERR("\n                     match the mask.")

  ERR("\n          to_ip    : dump packets to hosts whose IP addresses")
  ERR("\n                     match the mask.")

  ERR("\n          from_port: dump packets from port 'port_number'")

  ERR("\n          to_port  : dump packets to port 'port_number'")

  ERR("\n          body_as  : - ascii - dump packet body in ascii.")
  ERR("\n                     - hexa  - dump packet body in hexa.")
  ERR("\n                     - mix   - dump packet body in hexa and ascii.")
  ERR("\n                     - none  - do not dump packet body.")

  ERR("\n          ip_hd    : - on    - dump IP headers.");
  ERR("\n                     - off   - do not dump IP headers.");

  ERR("\n          udp_hd   : - on    - dump UDP headers.");
  ERR("\n                     - off   - do not dump UDP headers.");

  ERR("\n          tcp_hd   : - on    - dump TCP headers.");
  ERR("\n                     - off   - do not dump TCP headers.");

  ERR("\n          eth_hd   : - on    - dump ethernet headers.");
  ERR("\n                     - off   - do not dump ethernet headers.");

  ERR("\n          in_file  : By default the program dumps data to the console.");
  ERR("\n                     But, if this option is specified, data will be");
  ERR("\n                     dumped into a file. The name of the file is spe-");
  ERR("\n                     -cied after the keyword 'in_file'.");
  ERR("\n                     Notes: (1) this greatly accelerates the program.");
  ERR("\n                            (2) packets are dumped as *binary* data.");

  ERR("\n          from_file : Read packets previously recorded to the file");
  ERR("\n                      'FileName'.");

  ERR("\n          short_desc : short header's description.")
  ERR("\n          long_desc  : long header's description.\n\n")



  ERR("An IP mask is an IP address in doted decimal notation. The special\n")
  ERR("character '@' means \"any number between 0 and 255\".\n")
  ERR("\nex of valid IP masks: 192.45.65.10")
  ERR("\n                      192.45.65.@")
  ERR("\n                      192.45.@.@\n\n")
}


/********************************************************************/
/*                        Search_Command                            */
/*                                                                  */
/* Search for a specific option in the command line.                */
/*                                                                  */
/* If found: return the index of the option in the command line.    */
/* if not found: return -1.                                         */
/********************************************************************/

int Search_Command (char **line, int elem, char *pattern)
{
  int i;
  
  for (i=0; i<elem; i++)
  { if (strcmp(line[i], pattern) == 0) { return i; } }

  return -1;
}

/********************************************************************/
/*                             Is_Number                            */
/*                                                                  */
/* Check if a character string represents a decimal number.         */
/*                                                                  */
/* Return value:                                                    */
/*  YES or NO.                                                      */
/********************************************************************/

int Is_Number (char *field)
{
  int i;
  
  for (i=0; i<strlen(field); i++)
  {
    if (
         (field[i] != '0') &&
         (field[i] != '1') &&
         (field[i] != '2') &&
         (field[i] != '3') &&
         (field[i] != '4') &&
         (field[i] != '5') &&
         (field[i] != '6') &&
         (field[i] != '7') &&
         (field[i] != '8') &&
         (field[i] != '9')                                     
       ) { return NO; }
  }
  
  return YES;
}



int check_command_line (char **line, int argc, S_command *flags)
{
   int    cr;
  
   
   /******************************************************/
   /*               Setting default values               */
   /******************************************************/
  
   flags->help              = NO;
   flags->verbose           = NO;
   flags->proto_udp         = YES;
   flags->proto_tcp         = YES;
   flags->proto_igmp        = NO;
   flags->proto_arp         = NO;
   (flags->from_ip_mask)[0] = -1;
   (flags->from_ip_mask)[1] = -1;
   (flags->from_ip_mask)[2] = -1;
   (flags->from_ip_mask)[3] = -1;
   (flags->to_ip_mask)[0]   = -1;
   (flags->to_ip_mask)[1]   = -1;
   (flags->to_ip_mask)[2]   = -1;
   (flags->to_ip_mask)[3]   = -1;
   flags->from_port_num     = ALL_PORT;
   flags->to_port_num       = ALL_PORT;
   flags->body_level        = BD_MIX;
   flags->ip_hd             = YES;
   flags->udp_hd            = YES;
   flags->tcp_hd            = YES;
   flags->eth_hd            = YES;
   (flags->E_interface)[0]  = 0;
   flags->desc              = LONG_DESC;
   (flags->Dump_File)[0]    = 0;
   flags->dump_from_file    = NO;


   /******************************************************/
   /*                 Printing the help ?                */
   /******************************************************/

   cr = Search_Command (line, argc, "help");
   
   if (cr != -1)
   {
     flags->help = YES;
     return COMMAND_LINE_OK;
   }
   
   /******************************************************/
   /*              Running in verbose mode               */
   /******************************************************/

   cr = Search_Command (line, argc, "verbose");
   
   if (cr != -1)
   { flags->verbose = YES; }
   

   /******************************************************/
   /*               look for UDP packets ?               */
   /******************************************************/

   cr = Search_Command (line, argc, "udp");
   if (cr != -1)
   {
     if (cr+1 > argc-1) { return COMMAND_LINE_UDP_PROTO; }

     flags->proto_udp = NONE;
     if (strcmp(line[cr+1], "on")  == 0) { flags->proto_udp = YES; }
     if (strcmp(line[cr+1], "off") == 0) { flags->proto_udp = NO; }
     if (flags->proto_udp == NONE) { return COMMAND_LINE_UDP_PROTO; }
   }

   /******************************************************/
   /*               look for TCP packets ?               */
   /******************************************************/

   cr = Search_Command (line, argc, "tcp");
   if (cr != -1)
   {
     if (cr+1 > argc-1) { return COMMAND_LINE_TCP_PROTO; }

     flags->proto_tcp = NONE;
     if (strcmp(line[cr+1], "on")  == 0) { flags->proto_tcp = YES; }
     if (strcmp(line[cr+1], "off") == 0) { flags->proto_tcp = NO; }
     if (flags->proto_tcp == NONE) { return COMMAND_LINE_TCP_PROTO; }
   }

   /******************************************************/
   /*               look for IGMP packets ?              */
   /******************************************************/

   cr = Search_Command (line, argc, "igmp");
   if (cr != -1)
   {
     if (cr+1 > argc-1) { return COMMAND_LINE_IGMP_PROTO; }

     flags->proto_igmp = NONE;
     if (strcmp(line[cr+1], "on")  == 0) { flags->proto_igmp = YES; }
     if (strcmp(line[cr+1], "off") == 0) { flags->proto_igmp = NO; }
     if (flags->proto_igmp == NONE) { return COMMAND_LINE_IGMP_PROTO; }
   }

   /******************************************************/
   /*                Set source IP mask ?                */
   /******************************************************/

   cr = Search_Command (line, argc, "from_ip");
   if (cr != -1)
   {
     /* field 'cr+1' must be a valid IP mask */
     if (
          (cr+1 > argc-1)
          ||
          (strlen(line[cr+1]) > 15)
          ||
          (set_mask (line[cr+1], flags->from_ip_mask) == BAD_MASK)
        )
        { return COMMAND_LINE_FROM_IP; }     
   }

   /******************************************************/
   /*             Set destination IP mask ?              */
   /******************************************************/

   cr = Search_Command (line, argc, "to_ip");
   if (cr != -1)
   {
     /* field 'cr+1' must be a valid IP mask */
     if (
          (cr+1 > argc-1)
          ||
          (strlen(line[cr+1]) > 15)
          ||
          (set_mask (line[cr+1], flags->to_ip_mask) == BAD_MASK)
        )
        { return COMMAND_LINE_TO_IP; }     
   }

   /******************************************************/
   /*             Set source port number ?               */
   /******************************************************/

   cr = Search_Command (line, argc, "from_port");

   if (cr != -1)
   {
     /* field 'cr+1' must be a valid port number */
     if (
          (cr+1 > argc-1)
          ||
          (Is_Number (line[cr+1]) == NO)
        )
        { return COMMAND_LINE_FROM_PORT; }     

     /* OK ... set the port number */
     flags->from_port_num     = atoi(line[cr+1]);
   }

   /******************************************************/
   /*          Set destination port number ?             */
   /******************************************************/

   cr = Search_Command (line, argc, "to_port");

   if (cr != -1)
   {
     /* field 'cr+1' must be a valid port number */
     if (
          (cr+1 > argc-1)
          ||
          (Is_Number (line[cr+1]) == NO)
        )
        { return COMMAND_LINE_TO_PORT; }     

     /* OK ... set the port number */
     flags->to_port_num     = atoi(line[cr+1]);
   }

   /******************************************************/
   /*               What kind of output ?                */
   /******************************************************/

   cr = Search_Command (line, argc, "body_as");

   if (cr != -1)
   {
     if (cr+1 > argc-1) { return COMMAND_LINE_BODY_OUTPUT; }

     flags->body_level = NONE;
     if (strcmp(line[cr+1], "mix")   == 0) { flags->body_level = BD_MIX; }
     if (strcmp(line[cr+1], "ascii") == 0) { flags->body_level = BD_ASCII; }
     if (strcmp(line[cr+1], "hexa")  == 0) { flags->body_level = BD_HEXA; }
     if (strcmp(line[cr+1], "none")  == 0) { flags->body_level = BD_NONE; }

     if (flags->body_level == NONE) { return COMMAND_LINE_BODY_OUTPUT; }
   }

   /******************************************************/
   /*               Dumping IP headers ?                 */
   /******************************************************/

   cr = Search_Command (line, argc, "ip_hd");

   if (cr != -1)
   {
     if (cr+1 > argc-1) { return COMMAND_LINE_IP_HD; }

     flags->ip_hd = NONE;
     if (strcmp(line[cr+1], "on")  == 0) { flags->ip_hd = YES; }
     if (strcmp(line[cr+1], "off") == 0) { flags->ip_hd = NO; }
     if (flags->ip_hd == NONE) { return COMMAND_LINE_IP_HD; }
   }

   /******************************************************/
   /*               Dumping UDP headers ?                */
   /******************************************************/

   cr = Search_Command (line, argc, "udp_hd");

   if (cr != -1)
   {
     if (cr+1 > argc-1) { return COMMAND_LINE_UDP_HD; }

     flags->udp_hd = NONE;
     if (strcmp(line[cr+1], "on")  == 0) { flags->udp_hd = YES; }
     if (strcmp(line[cr+1], "off") == 0) { flags->udp_hd = NO; }
     if (flags->udp_hd == NONE) { return COMMAND_LINE_UDP_HD; }
   }

   /******************************************************/
   /*               Dumping TCP headers ?                */
   /******************************************************/

   cr = Search_Command (line, argc, "tcp_hd");

   if (cr != -1)
   {
     if (cr+1 > argc-1) { return COMMAND_LINE_TCP_HD; }

     flags->tcp_hd = NONE;
     if (strcmp(line[cr+1], "on")  == 0) { flags->tcp_hd = YES; }
     if (strcmp(line[cr+1], "off") == 0) { flags->tcp_hd = NO; }
     if (flags->tcp_hd == NONE) { return COMMAND_LINE_TCP_HD; }
   }

   /******************************************************/
   /*           Dumping ethernet headers ?               */
   /******************************************************/

   cr = Search_Command (line, argc, "eth_hd");

   if (cr != -1)
   {
     if (cr+1 > argc-1) { return COMMAND_LINE_ETH_HD; }

     flags->eth_hd = NONE;
     if (strcmp(line[cr+1], "on")  == 0) { flags->eth_hd = YES; }
     if (strcmp(line[cr+1], "off") == 0) { flags->eth_hd = NO; }
     if (flags->eth_hd == NONE) { return COMMAND_LINE_ETH_HD; }
   }

   /******************************************************/
   /*              Getting the interface name            */
   /******************************************************/

   sprintf (flags->E_interface, "%s", line[argc-1]);

   /******************************************************/
   /*        Short or long header description ?          */
   /******************************************************/

   cr = Search_Command (line, argc, "short_desc");
   if (cr != -1)
   { flags->desc = SHORT_DESC; }
   
   cr = Search_Command (line, argc, "long_desc");
   if (cr != -1)
   { flags->desc = LONG_DESC; }

   /******************************************************/
   /*           Dump ARP requests / replies              */
   /******************************************************/

   cr = Search_Command (line, argc, "arp");
   if (cr != -1)
   {
     if (cr+1 > argc-1) { return COMMAND_LINE_ARP_PROTO; }

     flags->proto_arp = NONE;
     if (strcmp(line[cr+1], "on")  == 0) { flags->proto_arp = YES; }
     if (strcmp(line[cr+1], "off") == 0) { flags->proto_arp = NO; }
     if (flags->proto_arp == NONE) { return COMMAND_LINE_ARP_PROTO; }
   }

   /******************************************************/
   /*              Dump data in a file ?                 */
   /******************************************************/

   cr = Search_Command (line, argc, "in_file");
   if (cr != -1)
   {
     if (cr+1 > argc-1) { return COMMAND_LINE_IN_FILE_PROTO; }
     sprintf (flags->Dump_File, "%s", line[cr+1]);
   }

   /******************************************************/
   /*              Read data from a file ?               */
   /******************************************************/

   cr = Search_Command (line, argc, "from_file");
   if (cr != -1)
   {
     if (cr+1 > argc-1) { return COMMAND_LINE_IN_FILE_PROTO; }
     sprintf (flags->Dump_File, "%s", line[cr+1]);
     flags->dump_from_file = YES;  
   }



   return COMMAND_LINE_OK;
}

