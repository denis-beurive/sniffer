#ifndef COMMAND_LINE_HD

  #include "dump_headers.h"

  #define YES   1
  #define NO    0
  #define NONE -1

  #define INTERFACE_NAME_LENGTH 50   /* this is plenty                 */
  #define FILE_NAME_LENGTH      257  /* it's enough for most OSs       */


  struct command_flags
         {
           int     help;             /* YES or NO                      */
           int     verbose;          /* YES or NO                      */
           int     proto_udp;        /* YES or NO                      */
           int     proto_tcp;        /* YES or NO                      */
           int     proto_igmp;       /* YES or NO                      */
           int     proto_arp;        /* YES or NO                      */
           int     from_ip_mask[4];  
           int     to_ip_mask[4];    
           int     from_port_num;    
           int     to_port_num;      
           int     body_level;       /* 0: hide body.      BD_NONE     */
                                     /* 1: hexa only.      BD_HEXA     */
                                     /* 2: ascii only.     BD_ASCII    */
                                     /* 3: hexa and ascii. BD_MIX      */
           int     ip_hd;            /* YES or NO                      */
           int     udp_hd;           /* YES or NO                      */
           int     tcp_hd;           /* YES or NO                      */
           int     eth_hd;           /* YES or NO                      */
           int     desc;             /* LONG_DESC or SHORT_DESC        */
           char    E_interface[INTERFACE_NAME_LENGTH];
                                     /* interface name                 */
           char    Dump_File[FILE_NAME_LENGTH];
                                     /* Name of the file to dump to    */
           int     dump_from_file;   /* YES or NO                      */
         };

   


   

  typedef struct command_flags S_command;

  /* body level */
  #define BD_NONE   0
  #define BD_HEXA   1
  #define BD_ASCII  2
  #define BD_MIX    3
  
  /* port numbers */
  #define ALL_PORT  -1

  /* status codes (OK or ERROR) */
  #define  COMMAND_LINE_OK            0
  #define  COMMAND_LINE_FROM_IP       1
  #define  COMMAND_LINE_TO_IP         2
  #define  COMMAND_LINE_FROM_PORT     3
  #define  COMMAND_LINE_TO_PORT       4
  #define  COMMAND_LINE_BODY_OUTPUT   5
  #define  COMMAND_LINE_IP_HD         6
  #define  COMMAND_LINE_UDP_HD        7
  #define  COMMAND_LINE_TCP_HD        8
  #define  COMMAND_LINE_ETH_HD        9
  #define  COMMAND_LINE_TCP_PROTO     10
  #define  COMMAND_LINE_UDP_PROTO     11
  #define  COMMAND_LINE_IGMP_PROTO    12  
  #define  COMMAND_LINE_ARP_PROTO     13
  #define  COMMAND_LINE_IN_FILE_PROTO 14

  void usage(void);
  int Search_Command (char**, int, char*);
  int Is_Number (char*);
  int check_command_line (char**, int, S_command*);

  #define COMMAND_LINE_HD
#endif
