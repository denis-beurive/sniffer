#include <windows.h>
#include <stdio.h>
#include "dump.h"
#include "buffer.h"
#include "cline.h"
#include "packet_handler.h"
#include "file.h"


/* The following macro is defined to speed up the packet  */
/* initialization process (saved few access to the stack) */
#define PACKETINITPACKET(pack,buff,size) pack->Buffer=buff; pack->Length=size

/* number of receiver threads */
#define NB_OF_RECV   3

int         file_dumper();/* Thread to dump packets into a file */
int         Receiver();   /* Thread for packet reception        */
int         printer();    /* Thread for the packet printer      */
LPADAPTER   lpAdapter;    /* handler on the network adaptator   */
HANDLE      Exit_Ctrl;    /* Mutex used to perform a clean exit */
HANDLE      Thread_Sync;  /* Mutex used to synchronize threads  */
BOOLEAN     Continue;     /* Control the threads execution      */
LPPACKET    lpPacket;     /* Used by receivers to receive       */
                          /* network packets                    */
FILE        *dump_file;   /* File used to dump packets          */
S_command   flags;        /* Command line options               */



main(int argc, char **argv)
{
    TCHAR    buf[256];
    TCHAR    *Name, *c;
    ULONG    NameLength = 256;
    UCHAR    Address[6];
    UINT     i, n;
    DWORD    tid[NB_OF_RECV], ptid;
    HANDLE   hThread[NB_OF_RECV];
    HANDLE   pThread;
    LPDWORD  Terminaison_Status;
    BOOLEAN  cr;
    int      it, err, Thread_Number;
    Case     buff;
    long int file_size, packet_number, remainder;


    err = 0;

    /*******************************************************/
    /*                Command line checking                */
    /*******************************************************/

    if (argc == 1)
    {
      usage();
      return 1;
    }

    /***********************************************************************/
    /*                     Command line options flags                      */
    /***********************************************************************/

    it = check_command_line (argv, argc, &flags);

    switch (it)
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

    /*******************************************************/
    /*               Dump packets from file ?              */
    /*******************************************************/

    if (flags.dump_from_file == YES)
    {
      dump_file = fopen(flags.Dump_File, "rb");
      if (dump_file == NULL)
      {
         fprintf(stderr, "\nCan open file %s\n", flags.Dump_File);
         return 0;
      }

      file_size = File_Length(dump_file);
      packet_number = file_size / sizeof(Case);
      remainder     = file_size - (sizeof(Case) * packet_number);
      
      if (remainder != 0)
      {
         fprintf(stderr, "\nWARNING: It looks like the requested file does not respect the right format\n");
         fprintf(stderr, "\nfile size:     %d", file_size);
         fprintf(stderr, "\npacket_number: %d", packet_number);
         fprintf(stderr, "\nremainder:     %d", remainder);
         fprintf(stderr, "\nbuff size:     %d", sizeof(Case));
         return 1;
      }

      while (packet_number > 0)
      {
         if (fread ((void*)&buff, sizeof(buff), 1, dump_file) != 1)
         {
           fprintf(stderr, "\nError while reading file %s\n", flags.Dump_File);
           fclose (dump_file);
           return 1;
         }
         
         if (Handle_Packet (buff.buffer, buff.size) == HANDLER_ERR)
         {
           fprintf (stderr, "\nInternal error - exit\n");
           return 1;;
         }

         fprintf (stdout, "\n");

         fflush(stdout);

         packet_number--;     
      }

      return 0;
    }

    /*******************************************************/
    /*             Initialize the rolling buffer           */
    /*******************************************************/

    if (Init_Rolling() != PACKET_ROLL_OK)
    {
      fprintf (stderr, "\nError while creating buffers\n");
      return 1;
    }

    /*******************************************************/
    /*                 Adaptator selection                 */
    /*******************************************************/

    Name = buf;

    /* Returns the names of all available network adapters */
    PacketGetAdapterNames(Name, &NameLength);

    /*******************************************************/
    /* 'Name' contains four 0 ended strings in the follo-  */
    /* -wing order:                                        */
    /*     - adapter 0                                     */
    /*     - adapter 1                                     */
    /*     - adapter 2                                     */
    /*     - adapter 3                                     */
    /*                                                     */
    /* If 'adapter N' is undefined, then the associated    */
    /* string (let say 'adapter_N' is null (in other word  */
    /* adapter_N[0]=0.                                     */
    /*                                                     */
    /* Search for the adaptater                            */
    /* o If argv[1]=0 then the adaptator name if the first */
    /*   one in the buffer 'Name'.                         */
    /* o If argv[1]=N then the adaptator we must skip      */
    /*   (N-1) names in the buffer.                        */
    /*******************************************************/

    /*******************************************************/
    /* Printing all available adaptators                   */
    /*******************************************************/

/*

    fprintf(stdout, "\n\nAdaptaror names:\n\n");

    c = Name;
    

    for (i=0; i<4; i++)
    {
      fprintf(stdout, "\nc = %s\n", c);


      switch ((int)i)
      {
        case 3: Name = (char *) &Name[strlen(Name)+1];
                if (strlen(Name) == 0) { break; }

        case 2: Name = (char *) &Name[strlen(Name)+1];
                if (strlen(Name) == 0) { break; }

        case 1: Name = (char *) &Name[strlen(Name)+1];
                if (strlen(Name) == 0) { break; }

        case 0: break;
      }
    
      if (strlen(Name) != 0) { fprintf(stdout, "\nAdapter Name number %d: %s\n", i, Name); }
    
      Name = c;
    }

    fprintf(stdout, "\n\n");
*/

    /*******************************************************/
    /* Open the specific one you choosed                   */
    /*******************************************************/

    switch (atoi(flags.E_interface))
    {
        case 3: Name = (char *) &Name[strlen(Name)+1];
                if (strlen(Name) == 0) { break; }

        case 2: Name = (char *) &Name[strlen(Name)+1];
                if (strlen(Name) == 0) { break; }

        case 1: Name = (char *) &Name[strlen(Name)+1];
                if (strlen(Name) == 0) { break; }

        case 0: break;
    }
    
    if (strlen(Name) != 0) { fprintf(stdout, "Adapter Name: %s\n", Name); }
    else
    {
       /* WARNING: - must close the buffer */

       fprintf(stderr, "Adapter %s not present\n", flags.E_interface);

       if (Close_Rolling() == FALSE)
       { fprintf(stderr, "\nWarning: an error occured while trying to close buffers\n"); }

       return 1;
    }

    /*******************************************************/
    /* Create the mutex used to perform a clean            */
    /* terminaison of the thread.                          */
    /*******************************************************/

    Exit_Ctrl = CreateMutex
    (
      NULL,   /* address of security attributes.  */
              /* NULL => default attributes       */
      FALSE,  /* flag for initial ownership.      */
              /* FALSE => not owned               */
      NULL    /* address of mutex-object name.    */
              /* NULL => no name                  */
    );

    if (Exit_Ctrl == NULL)
    {
       /* WARNING: must close the buffer */

       fprintf(stderr, "\nCan not create 'Exit_Ctrl' mutex\n");

       if (Close_Rolling() == FALSE)
       { fprintf(stderr, "\nWarning: an error occured while trying to close buffers\n"); }

       return 1;
    }

    /*******************************************************/
    /*   Create the mutex used to synchronize receivers    */
    /*******************************************************/

    Thread_Sync = CreateMutex
    (
      NULL,   /* address of security attributes.  */
              /* NULL => default attributes       */
      FALSE,  /* flag for initial ownership.      */
              /* FALSE => not owned               */
      NULL    /* address of mutex-object name.    */
              /* NULL => no name                  */
    );

    if (Thread_Sync == NULL)
    {
       /* WARNING: must close the buffer  */
       /*          must close 'Exit_Ctrl' */

       fprintf(stderr, "\nCan not create 'Thread_Sync' mutex\n");

       if (Close_Rolling() == FALSE)
       { fprintf(stderr, "\nWarning: an error occured while trying to close buffers\n"); }

       if (CloseHandle (Exit_Ctrl) == FALSE)
       { fprintf(stderr, "\nWARNING: Can not close handle for mutex 'Exit_Ctrl'\n"); }

       return 1;
    }

    /*******************************************************/
    /*  Open the adaptator device and return an handler.   */
    /*******************************************************/

    lpAdapter = PacketOpenAdapter(Name);
    if (lpAdapter == NULL)
    {
       /* WARNING: must close the buffer  */
       /*          must close 'Exit_Ctrl' */
       /*          must close 'Exit_Sync' */

       fprintf(stderr, "\nCan not open network adaptator\n");

       if (Close_Rolling() == FALSE)
       { fprintf(stderr, "\nWarning: an error occured while trying to close buffers\n"); }

       if (CloseHandle (Exit_Ctrl) == FALSE)
       { fprintf(stderr, "\nWARNING: Can not close handle for mutex 'Exit_Ctrl'\n"); }

       if (CloseHandle (Thread_Sync) == FALSE)
       { fprintf(stderr, "\nWARNING: Can not close handle for mutex 'Thread_Sync'\n"); }

       return 1;
    }

    /*******************************************************/
    /*         Set adaptator in promiscuous mode           */
    /*******************************************************/

    PacketSetFilter(lpAdapter, NDIS_PACKET_TYPE_PROMISCUOUS);

    /*******************************************************/
    /*   Get the Physical Address of an Ethernet Adapter   */
    /*******************************************************/

    if (PacketGetAddress(lpAdapter, Address) != 6)
    {
       /* WARNING: must close the buffer  */
       /*          must close 'Exit_Ctrl' */
       /*          must close 'Exit_Sync' */

       fprintf(stderr, "\nError while getting adaptator address\n");

       if (Close_Rolling() == FALSE)
       { fprintf(stderr, "\nWarning: an error occured while trying to close buffers\n"); }

       if (CloseHandle (Exit_Ctrl) == FALSE)
       { fprintf(stderr, "\nWARNING: Can not close handle for mutex 'Exit_Ctrl'\n"); }

       if (CloseHandle (Thread_Sync) == FALSE)
       { fprintf(stderr, "\nWARNING: Can not close handle for mutex 'Thread_Sync'\n"); }

       return 1;
    }

    printf("Adapter Addr: [");
    for (i=0; i<5; i++) { printf("%02x:", Address[i]); }
    printf("%02x]\n\n", Address[i]);    

    /*******************************************************/
    /*                  Alocate  the packet                */
    /*******************************************************/

    lpPacket = PacketAllocatePacket();
    
    if (lpPacket == NULL)
    {
      fprintf (stderr, "\n Error while Allocating packet\n");
      
      
      /* WARNING: must close the buffer  */
      /*          must close 'Exit_Ctrl' */
      /*          must close 'Exit_Sync' */
      /*          must close adaptator   */

      fprintf(stderr, "\nCan not allocate packet\n");

      if (Close_Rolling() == FALSE)
      { fprintf(stderr, "\nWarning: an error occured while trying to close buffers\n"); }

      if (CloseHandle (Exit_Ctrl) == FALSE)
      { fprintf(stderr, "\nWARNING: Can not close handle for mutex 'Exit_Ctrl'\n"); }

      if (CloseHandle (Thread_Sync) == FALSE)
      { fprintf(stderr, "\nWARNING: Can not close handle for mutex 'Thread_Sync'\n"); }

      PacketCloseAdapter(lpAdapter);

      return 1;
    }

    /*******************************************************/
    /*             Open dump file is necessary             */
    /*******************************************************/

    dump_file = NULL;
    if ((flags.Dump_File)[0] != 0)
    {
      dump_file = fopen(flags.Dump_File, "wb");
      if (dump_file == NULL)
      {
         fprintf(stderr, "\nCan open file %s\n", flags.Dump_File);

         /* WARNING: must close the buffer  */
         /*          must close 'Exit_Ctrl' */
         /*          must close 'Exit_Sync' */
         /*          must close adaptator   */

         if (Close_Rolling() == FALSE)
         { fprintf(stderr, "\nWarning: an error occured while trying to close buffers\n"); }

         if (CloseHandle (Exit_Ctrl) == FALSE)
         { fprintf(stderr, "\nWARNING: Can not close handle for mutex 'Exit_Ctrl'\n"); }

         if (CloseHandle (Thread_Sync) == FALSE)
         { fprintf(stderr, "\nWARNING: Can not close handle for mutex 'Thread_Sync'\n"); }

         PacketCloseAdapter(lpAdapter);

         return 1;
      }
    }


    /*******************************************************/
    /*                 Launch the printer                  */
    /*                                                     */
    /* If we want to dump packets in a file we launch      */
    /* 'file_dumper'.                                      */
    /*******************************************************/

    Continue      = TRUE;

    if (dump_file == NULL)
    {
       pThread = CreateThread  (
                                 0, 
                                 0,
                                 (LPTHREAD_START_ROUTINE) printer,
                                 0,
                                 0,
                                 &ptid
                               );
    }
    else
    {
       pThread = CreateThread  (
                                 0, 
                                 0,
                                 (LPTHREAD_START_ROUTINE) file_dumper,
                                 0,
                                 0,
                                 &ptid
                               );
    }

    fprintf (stdout, "\nstarting printer");
    fflush(stdout);
                                 
    if (pThread == NULL)
    {
       fprintf (stderr, "\nError while creating printer thread\n");

 
       /* WARNING: must close the buffer  */
       /*          must close 'Exit_Ctrl' */
       /*          must close 'Exit_Sync' */
       /*          must close adaptator   */
       /*          must close dump file   */

       if ((flags.Dump_File)[0] != 0)
       {
          if (fclose (dump_file) != 0)
          { fprintf(stderr, "\nWarning:Can not close file %s\n", flags.Dump_File); }
       }

       if (Close_Rolling() == FALSE)
       { fprintf(stderr, "\nWarning: an error occured while trying to close buffers\n"); }

       if (CloseHandle (Exit_Ctrl) == FALSE)
       { fprintf(stderr, "\nWARNING: Can not close handle for mutex 'Exit_Ctrl'\n"); }

       if (CloseHandle (Thread_Sync) == FALSE)
       { fprintf(stderr, "\nWARNING: Can not close handle for mutex 'Thread_Sync'\n"); }

       PacketCloseAdapter(lpAdapter);



       return 1;
    }

    /*******************************************************/
    /* Launch the 'receiver' threads and wait until the    */
    /* user hits the RETURN key >> if NO error <<          */
    /*                                                     */
    /* Note that we launch the receivers only if the       */
    /* printer has been successfully launched (err value   */
    /* is not 1).                                          */
    /*******************************************************/

    for (it=0; it<NB_OF_RECV; it++)
    {
      fprintf (stdout, "\nstarting receiver %d", it);
      fflush(stdout);

      hThread[it] = CreateThread (
                                   0, 
                                   0,
                                   (LPTHREAD_START_ROUTINE) Receiver,
                                   0,
                                   0,
                                   &(tid[it])
                                 );
                                 
      if (hThread[it] == NULL)
      {
         fprintf (stderr, "\nError while creating receiver %d", it);
         err = 1;
         break;
      }
    }

    Thread_Number = it;

    /*******************************************************/
    /* If an error happened, we don't wait ...             */
    /*******************************************************/

    if (err == 0)
    {                            
      printf("\n\nHit RETURN to terminate...\n\n");
      getchar();
    }

    /*******************************************************/
    /*    Tell the threads that it is time to terminate    */
    /*******************************************************/
    
    if ( 
         WaitForSingleObject
         (
           Exit_Ctrl,           /* handle of object to wait for      */
           INFINITE 	        /* time-out interval in milliseconds */
         ) == WAIT_FAILED
       )
    {
       fprintf(stderr, "\nError while trying to get 'Exit_Ctrl' mutex\n");

       /* WARNING: must close the buffer  */
       /*          must close 'Exit_Ctrl' */
       /*          must close 'Exit_Sync' */
       /*          must free packet       */
       /*          must close adapter     */
       /*          must close dump file   */

       if ((flags.Dump_File)[0] != 0)
       {
          if (fclose (dump_file) != 0)
          { fprintf(stderr, "\nWarning:Can not close file %s\n", flags.Dump_File); }
       }

       if (Close_Rolling() == FALSE)
       { fprintf(stderr, "\nWarning: an error occured while trying to close buffers\n"); }

       if (CloseHandle (Exit_Ctrl) == FALSE)
       { fprintf(stderr, "\nWARNING: Can not close handle for mutex 'Exit_Ctrl'\n"); }

       if (CloseHandle (Thread_Sync) == FALSE)
       { fprintf(stderr, "\nWARNING: Can not close handle for mutex 'Thread_Sync'\n"); }

       PacketFreePacket(lpPacket);

       PacketCloseAdapter(lpAdapter);

       fprintf(stderr, "\nWARNING ! Receiver threads did not terminate properly !\n");
       fprintf(stderr, "\n          Some ressource have not been properly cleared.\n");

       return 1;
    }

    Continue = FALSE;
    
    if (ReleaseMutex (Exit_Ctrl) == FALSE)
    {
       /* WARNING: must close the buffer  */
       /*          must close 'Exit_Ctrl' */
       /*          must close 'Exit_Sync' */
       /*          must free packet       */
       /*          must close adapter     */
       /*          must close dump file   */

       if ((flags.Dump_File)[0] != 0)
       {
          if (fclose (dump_file) != 0)
          { fprintf(stderr, "\nWarning:Can not close file %s\n", flags.Dump_File); }
       }

       fprintf(stderr, "\nError while trying to release 'Exit_Ctrl' mutex\n");

       if (Close_Rolling() == FALSE)
       { fprintf(stderr, "\nWarning: an error occured while trying to close buffers\n"); }

       if (CloseHandle (Exit_Ctrl) == FALSE)
       { fprintf(stderr, "\nWARNING: Can not close handle for mutex 'Exit_Ctrl'\n"); }

       if (CloseHandle (Thread_Sync) == FALSE)
       { fprintf(stderr, "\nWARNING: Can not close handle for mutex 'Thread_Sync'\n"); }

       PacketFreePacket(lpPacket);

       PacketCloseAdapter(lpAdapter);

       fprintf(stderr, "\nWARNING ! Receiver threads did not terminate properly !\n");
       fprintf(stderr, "\n          Some ressource have not been properly cleared.\n");

       return 1;
    }

    /*******************************************************/
    /*        Now we wait for the thread to finish.        */
    /*                                                     */
    /* Note that we loop goes until 'Thread_Number', so we */
    /* only "kill" the threads that have been launched.    */
    /*                                                     */
    /* Note that we wait only for the receivers that have  */
    /* been successfully launched, because we are tested   */
    /* the value of Thread_Number.                         */
    /*******************************************************/

    for (it=0; it<Thread_Number; it++)
    {
      fprintf(stdout, "\nWaiting for receivers %d to perform a CLEAN terminaison ...\n\n", it);

      (*Terminaison_Status) = STILL_ACTIVE;

      while ((*Terminaison_Status) == STILL_ACTIVE)
      {
         cr = GetExitCodeThread
         (
            hThread[it],	     // handle to the thread 
            Terminaison_Status   // address to receive termination status 
         );

         if (cr == FALSE)
         {
           fprintf(stderr, "\nWARNING:  Error while waiting for thread termination");
           fprintf(stderr, "\n          Performing a very dirty exit ...");
           TerminateThread(hThread[it], 0);
           (*Terminaison_Status) = PACKET_RECV_END_ERR;
           break;
         }
      }

      switch (*Terminaison_Status)
      {
        case PACKET_RECV_END_OK:
             { fprintf(stdout, "\nReceiver %d: Successfull exit\n", it); };
             break;
           
        case PACKET_RECV_END_ERR:
             { 
               fprintf(stderr, "\nReceiver %d: Error while performing exit", it);
               fprintf(stderr, "\n             Some resources have not been freed correctly.");
               fprintf(stderr, "\n             You may need to reboot your system.");
             };
             break;

        case PACKET_GET_PACKET_ERR:
             { fprintf(stderr, "\nReceiver %d: Error while trying to receive packet\n", it); };
             break;
             
        case PACKET_ROLL_OVERFLOW:
             { fprintf(stderr, "\nReceiver %d: buffer out of space\n", it); };
             break;
             
        case PACKET_ROLL_GET_MUTEX_ERROR:
             { fprintf(stderr, "\nError while trying to get status' mutex\n", it); };
             break;
             
        case PACKET_ROLL_RELEASE_MUTEX_ERROR:
             { fprintf(stderr, "\nError while trying to release status' mutex\n", it); };
             break;
      
        default:
             { fprintf(stderr, "\nReceiver %d: Unexpected error (could be a serious problem)\n", it); };
      }
    }

    /*******************************************************/
    /*           Waiting for printer to terminate          */
    /*******************************************************/

    (*Terminaison_Status) = STILL_ACTIVE;

    while ((*Terminaison_Status) == STILL_ACTIVE)
    {
       cr = GetExitCodeThread
       (
          pThread,             // handle to the thread 
          Terminaison_Status   // address to receive termination status 
       );

       if (cr == FALSE)
       {
         fprintf(stderr, "\nWARNING:  Error while waiting for thread termination");
         fprintf(stderr, "\n          Performing a very dirty exit ...");
         TerminateThread(pThread, 0);
         (*Terminaison_Status) = PACKET_RECV_END_ERR;
         break;
       }
    }

    switch (*Terminaison_Status)
    {
        case PACKET_PRINT_OK:
             { fprintf(stdout, "\nPrinter: Successfull exit\n"); };
             break;
           
        case PACKET_PRINT_END_ERR:
             { 
               fprintf(stderr, "\nprinter: Error while performing exit");
               fprintf(stderr, "\n         Some resources have not been freed correctly.");
               fprintf(stderr, "\n         You may need to reboot your system.");
             };
             break;
             
        case PACKET_ROLL_GET_MUTEX_ERROR:
             { fprintf(stderr, "\nError while trying to get status' mutex\n"); };
             break;
             
        case PACKET_ROLL_RELEASE_MUTEX_ERROR:
             { fprintf(stderr, "\nError while trying to release status' mutex\n"); };
             break;

        case HANDLER_ERR:
             { fprintf(stderr, "\nError while printing packets\n"); };
             break;

        case PACKET_PRINT_FILE_ERR:
             { fprintf(stderr, "\nError while writing data into file %s\n", flags.Dump_File); };
             break;
      
        default:
             { fprintf(stderr, "\nPrinter : Unexpected error (could be a serious problem)\n"); };
    }

    /*******************************************************/
    /*         Closing the dump file if necessary          */
    /*******************************************************/

    if ((flags.Dump_File)[0] != 0)
    {
       if (fclose (dump_file) != 0)
       { fprintf(stderr, "\nWarning:Can not close file %s\n", flags.Dump_File); }
    }

    /*******************************************************/
    /*               Closing the rolling buffer            */
    /*                                                     */
    /* In case of an error we don't exit because other     */
    /* cleaning nead to be done.                           */
    /*******************************************************/

    if (Close_Rolling() == FALSE)
    {
      fprintf(stderr, "\nWarning: an error occured while trying to close buffers\n");
      err = 1;  
    }

    /*******************************************************/
    /*                Freeing the packet                   */
    /*******************************************************/

    PacketFreePacket(lpPacket);

    /*******************************************************/
    /*        Close the network adatator properly.         */
    /*******************************************************/

    PacketCloseAdapter(lpAdapter);
    
    /*******************************************************/
    /*                Closing mutex handles                */
    /*******************************************************/
    
    if (CloseHandle (Exit_Ctrl) == FALSE)
    {
      fprintf(stderr, "\nWARNING: Can not close handle for mutex 'Exit_Ctrl'\n");
      err = 1;  
    }
    
    if (CloseHandle (Thread_Sync) == FALSE)
    {
      fprintf(stderr, "\nWARNING: Can not close handle for mutex 'Thread_Sync'\n");
      err = 1;  
    }

    /*******************************************************/
    /*                Closing threads handles              */
    /*******************************************************/

    for (it=0; it<Thread_Number; it++)
    {
      if (CloseHandle (hThread[it]) == FALSE)
      {
         fprintf(stderr, "\nWARNING: Can not close handle for receiver %d\n", it);
         err = 1;
      }
    }

    if (CloseHandle (pThread) == FALSE)
    {
       fprintf(stderr, "\nWARNING: Can not close handle for printer thread \n");
       err = 1;
    }

   
    return err;
}







/*******************************************************/
/* receiver -- a trivial packet monitor (promiscuous)  */
/*******************************************************/

int Receiver()
{
    int         i, err, status;
    ULONG       Length;
    BOOLEAN     c;
    Case        *buff;


    /* Rules                                             */
    /* o Only one packet initialization per adaptator.   */
    /* o It is not necessary to allocate/initialise/     */
    /*   free the packet for each packet capture.        */
    /* o it seems that we can open only one adaptator    */
    /*   handler per adaptator (defined by its handler). */
    /* o lpPacket does not need to be "global".          */
 
                 
    /*******************************************************/
    /*                Enter reception loop                 */
    /*******************************************************/

    c   = TRUE;    
    err = 0;

    while (c)
    {
        /****************************************************/
        /*             Is it time to terminate ?            */
        /****************************************************/
        
        if ( 
             WaitForSingleObject
             (
               Exit_Ctrl,           /* handle of object to wait for      */
               INFINITE 	        /* time-out interval in milliseconds */
             ) == WAIT_FAILED
           )
        { return PACKET_RECV_END_ERR; }

        c = Continue;
    
        if (ReleaseMutex (Exit_Ctrl) == FALSE)
        { return PACKET_RECV_END_ERR; }
    
        if (c == FALSE) { /* terminate the thread */ break; }
    
        /****************************************************/
        /*                   Get the packet                 */
        /*                                                  */
        /* The 'PacketReceivePacket' procedure must be cal- */
        /* -led only one time at the time.                  */
        /*                                                  */
        /* 'lpPacket' is a shared ressource ! Must be in    */
        /* The critical section.                            */
        /****************************************************/

        if ( 
             WaitForSingleObject
             (
               Thread_Sync,   /* handle of object to wait for      */
               INFINITE 	  /* time-out interval in milliseconds */
             ) == WAIT_FAILED
           )
        { return PACKET_SYNC_ERROR; }

        /****************************************************/
        /* (1) Make sure the available buffer is not FULL   */
        /****************************************************/
        
        switch (status = Get_Wr_Status())
        {
          case EMPTY:
               break;
          
          case FULL:
               { 
                 err = PACKET_ROLL_OVERFLOW;
                 goto RECV_END;
               }
               
          default: err = status; goto RECV_END;
                   /* PACKET_ROLL_GET_MUTEX_ERROR / PACKET_ROLL_RELEASE_MUTEX_ERROR */
        }

        /****************************************************/
        /* (2) Initialize packet structure.                 */
        /****************************************************/

        buff = Get_Wr_Buffer();        
        PACKETINITPACKET(lpPacket,buff->buffer,MAX_BUFF_SIZE);

        /****************************************************/
        /* (3) Get the packet.                              */
        /****************************************************/
    
        if (PacketReceivePacket(lpAdapter, lpPacket, TRUE, &Length) == FALSE)
        {
          err = PACKET_GET_PACKET_ERR;
          goto RECV_END;
        }

        /****************************************************/
        /* (4) give extra data to current buffer.           */
        /****************************************************/

        buff->size = Length;

        /****************************************************/
        /* (5) Set buffer status to FULL                    */
        /****************************************************/

        switch (status = Set_Wr_Status(FULL))
        {
          case PACKET_ROLL_OK:
               break;
               
          default: err = status; goto RECV_END;
                   /* PACKET_ROLL_GET_MUTEX_ERROR / PACKET_ROLL_RELEASE_MUTEX_ERROR */
        }

        /****************************************************/
        /* (6) Set index to the next write buffer           */
        /****************************************************/

        Next_Write();

        RECV_END:

        if (ReleaseMutex (Thread_Sync) == FALSE)
        { return PACKET_SYNC_ERROR; }

        if (err != 0) { return err; }
    }

    /* end of receiver thread */

    return PACKET_RECV_END_OK;
}


/*******************************************************/
/*                     printer thread                  */
/*******************************************************/

int printer()
{
  int         i, status;
  BOOLEAN     c;
  Case        *buff;


  c   = TRUE;    

  while (c)
  {
      PRINT_BEGIN:

      /****************************************************/
      /*             Is it time to terminate ?            */
      /****************************************************/
        
      if ( 
           WaitForSingleObject
           (
             Exit_Ctrl,           /* handle of object to wait for      */
             INFINITE 	          /* time-out interval in milliseconds */
           ) == WAIT_FAILED
         )
      { return PACKET_PRINT_END_ERR; }

      c = Continue;
  
      if (ReleaseMutex (Exit_Ctrl) == FALSE)
      { return PACKET_PRINT_END_ERR; }
    
      if (c == FALSE) { /* terminate the thread */ break; }

      /****************************************************/
      /*                 Print the packet                 */
      /*                                                  */
      /* (1) Make sure the available buffer is not FULL   */
      /****************************************************/

      /****************************************************/
      /* (1) Make sure the available buffer is FULL       */
      /****************************************************/
        
      switch (status = Get_Rd_Status())
      {
        case FULL:
             break;
          
        case EMPTY:
             goto PRINT_BEGIN; /* nothing to print */
               
        default: 
             return status;    /* this is an error */
             /* PACKET_ROLL_GET_MUTEX_ERROR / PACKET_ROLL_RELEASE_MUTEX_ERROR */
      }

      /****************************************************/
      /* (2) read the buffer                              */
      /****************************************************/
      
      buff = Get_Rd_Buffer();

      if (Handle_Packet (buff->buffer, buff->size) == HANDLER_ERR)
      {
        fprintf (stderr, "\nprinter: internal error - exit\n");
        return HANDLER_ERR;
      }

      fprintf (stdout, "\n");

      fflush(stdout);
      
      /****************************************************/
      /* (3) Set buffer status to EMPTY                   */
      /****************************************************/

      switch (status = Set_Rd_Status(EMPTY))
      {
        case PACKET_ROLL_OK:
             break;
             
        default:
             return status;
             /* PACKET_ROLL_GET_MUTEX_ERROR / PACKET_ROLL_RELEASE_MUTEX_ERROR */
      }

      /****************************************************/
      /* (4) Set index to the next available buffer       */
      /****************************************************/

      Next_Read();
  }

  return PACKET_PRINT_OK;
}



/*******************************************************/
/*              File dumpder - pretty basic            */
/*******************************************************/

int file_dumper()
{
  int         i, status;
  BOOLEAN     c;
  Case        *buff;


  c   = TRUE;    

  while (c)
  {
      PRINT_BEGIN:

      /****************************************************/
      /*             Is it time to terminate ?            */
      /****************************************************/
        
      if ( 
           WaitForSingleObject
           (
             Exit_Ctrl,           /* handle of object to wait for      */
             INFINITE 	          /* time-out interval in milliseconds */
           ) == WAIT_FAILED
         )
      { return PACKET_PRINT_END_ERR; }

      c = Continue;
  
      if (ReleaseMutex (Exit_Ctrl) == FALSE)
      { return PACKET_PRINT_END_ERR; }
    
      if (c == FALSE) { /* terminate the thread */ break; }

      /****************************************************/
      /*                 Print the packet                 */
      /*                                                  */
      /* (1) Make sure the available buffer is not FULL   */
      /****************************************************/

      /****************************************************/
      /* (1) Make sure the available buffer is FULL       */
      /****************************************************/
        
      switch (status = Get_Rd_Status())
      {
        case FULL:
             break;
          
        case EMPTY:
             goto PRINT_BEGIN; /* nothing to print */
               
        default: 
             return status;    /* this is an error */
             /* PACKET_ROLL_GET_MUTEX_ERROR / PACKET_ROLL_RELEASE_MUTEX_ERROR */
      }

      /****************************************************/
      /* (2) read the buffer                              */
      /****************************************************/
      
      buff = Get_Rd_Buffer();

      if (fwrite ((const void*)buff, sizeof(Case), 1, dump_file) != 1)
      { return PACKET_PRINT_FILE_ERR; }
      
      /****************************************************/
      /* (3) Set buffer status to EMPTY                   */
      /****************************************************/

      switch (status = Set_Rd_Status(EMPTY))
      {
        case PACKET_ROLL_OK:
             break;
             
        default:
             return status;
             /* PACKET_ROLL_GET_MUTEX_ERROR / PACKET_ROLL_RELEASE_MUTEX_ERROR */
      }

      /****************************************************/
      /* (4) Set index to the next available buffer       */
      /****************************************************/

      Next_Read();
  }

  return PACKET_PRINT_OK;
}







