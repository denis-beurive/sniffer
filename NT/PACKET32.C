/*************************************************************************/
/* packet32.c - PacketInit PacketOpenAdapter PacketCloseAdapter          */
/*              PacketAllocatePacket PacketFreePacket PacketInitPacket   */
/*              PacketSendPacket PacketReceivePacket PacketWaitPacket    */
/*              PacketResetAdapter PacketRequest PacketSetFilter         */
/*              PacketGetAddr StartPacketDriver PacketGetAdapterNames    */
/*              PacketGetName                                            */
/*************************************************************************/

#include <windows.h>
#include <windowsx.h>
#include "packet32.h"


TCHAR   szWindowTitle[] = TEXT("PACKET32.DLL");


#if DBG
  #define ODS(_x) OutputDebugString(TEXT(_x))
#else
  #define ODS(_x)
#endif

BOOLEAN StartPacketDriver(LPTSTR ServiceName);

/*************************************************************************/
/*  PacketInit - Start the Packet Driver                                 */ 
/*                                                                       */
/*      Args:   DllHandle   - not used                                   */
/*              Option      - attach or detach                           */
/*              Context     - not used                                   */
/*                                                                       */
/*  Remark:                                                              */
/*      (1) the argument 'DllHandle' is not used. The                    */
/*          warning:                                                     */
/*          "Parameter 'DllHandle' is never used in function PacketInit" */
/*          is normal.                                                   */
/*      (2) the argument 'Context' is not used. The                      */
/*          warning:                                                     */
/*          "Parameter 'Context' is never used in function PacketInit"   */
/*          is normal.                                                   */
/*************************************************************************/

BOOLEAN PacketInit (
                      IN PVOID DllHandle,
                      IN ULONG Option,
                      IN PCONTEXT Context OPTIONAL
                   )
{
    BOOLEAN     Status;

    ODS("Packet32: DllEntry\n");

    switch (Option)
    {
    	case DLL_PROCESS_ATTACH:
             Status = StartPacketDriver(TEXT("PACKET")); break;
        case DLL_PROCESS_DETACH:
             break;
        default:
             break;
    }
    
    return Status;

   /*************************************************************************/
   /*  Remark:                                                              */
   /*      (1) the argument 'DllHandle' is not used. The                    */
   /*          warning:                                                     */
   /*          "Parameter 'DllHandle' is never used in function PacketInit" */
   /*          is normal.                                                   */
   /*      (2) the argument 'Context' is not used. The                      */
   /*          warning:                                                     */
   /*          "Parameter 'Context' is never used in function PacketInit"   */
   /*          is normal.                                                   */
   /*************************************************************************/
}





/*************************************************************************/
/*                                                                       */
/*  PacketOpenAdapter - Open the named adapter                           */
/*                                                                       */
/*      Args:   AdapterName - the UNICODE registry name of the adapter   */
/*                                                                       */
/*   Returns:   pointer to an Adapter or NULL                            */
/*                                                                       */
/*************************************************************************/

PVOID PacketOpenAdapter(LPTSTR AdapterName)
{
    LPADAPTER  lpAdapter;
    BOOLEAN    Result;

    ODS("Packet32: PacketOpenAdapter\n");

    lpAdapter = (LPADAPTER)GlobalAlloc
                (
                  GMEM_MOVEABLE | GMEM_ZEROINIT,
                  sizeof(ADAPTER)
                );

    if (lpAdapter == NULL) {

        ODS("Packet32: PacketOpenAdapter GlobalAlloc Failed\n");
        return NULL;
    }

    wsprintf (
                lpAdapter->SymbolicLink,
                TEXT("\\\\.\\%s%s"),
                DOSNAMEPREFIX,
                &AdapterName[8]
             );

    Result = DefineDosDevice
             (
                DDD_RAW_TARGET_PATH,
                &lpAdapter->SymbolicLink[4],
                AdapterName
             );

    if (Result)
    {
       lpAdapter->hFile = CreateFile
                          (
                             lpAdapter->SymbolicLink,
                             GENERIC_WRITE | GENERIC_READ,
                             0,
                             NULL,
                             CREATE_ALWAYS,
                             FILE_FLAG_OVERLAPPED,
                             0
                          );

       if (lpAdapter->hFile != INVALID_HANDLE_VALUE)
       { return lpAdapter; }
    }

    ODS("Packet32: PacketOpenAdapter Could not open adapter\n");

    GlobalFree(lpAdapter);

    return NULL;
}

/*************************************************************************/
/*                                                                       */
/*  PacketCloseAdapter - Close the specified adapter                     */
/*                                                                       */
/*      Args:   lpAdapter - pointer to an adapter object                 */
/*                                                                       */
/*   Returns:                                                            */
/*                                                                       */
/*************************************************************************/

VOID PacketCloseAdapter(LPADAPTER lpAdapter)

{
    ODS("Packet32: PacketCloseAdapter\n");
    CloseHandle(lpAdapter->hFile);
    GlobalFree(lpAdapter);
}

/*************************************************************************/
/*                                                                       */
/*  PacketAllocatePacket - allocate a Packet for send and receive        */
/*                                                                       */
/*      Args:   none                                                     */
/*                                                                       */
/*   Returns:   pointer to a Packet or NULL                              */
/*                                                                       */
/*************************************************************************/

PVOID PacketAllocatePacket()
{
    LPPACKET    lpPacket;

    lpPacket = (LPPACKET)GlobalAlloc
               (
                  GMEM_MOVEABLE | GMEM_ZEROINIT,
                  sizeof(PACKET)
               );

    if (lpPacket == NULL)
    {
       ODS("Packet32: PacketAllocateSendPacket: GlobalAlloc Failed\n");
       return NULL;
    }

    lpPacket->OverLapped.hEvent=CreateEvent(NULL, FALSE, FALSE, NULL);

    if (lpPacket->OverLapped.hEvent == NULL)
    {
        ODS("Packet32: PacketAllocateSendPacket: CreateEvent Failed\n");
        GlobalFree(lpPacket);
        return NULL;
    }
    return lpPacket;
}

/*************************************************************************/
/*                                                                       */
/*  PacketFreePacket - release a Packet                                  */
/*                                                                       */
/*      Args:   lpPacket - pointer to a Packet                           */
/*                                                                       */
/*   Returns:                                                            */
/*                                                                       */
/*************************************************************************/

VOID PacketFreePacket(LPPACKET lpPacket)
{
    CloseHandle(lpPacket->OverLapped.hEvent);
    GlobalFree(lpPacket);
}

/*************************************************************************/
/*                                                                       */
/*  PacketInitPacket - initialize an allocated Packet                    */
/*                                                                       */
/*      Args:   lpPacket - pointer to a Packet                           */
/*              Buffer   - buffer pointer                                */
/*              Length   - length of buffer                              */
/*                                                                       */
/*   Returns:                                                            */
/*                                                                       */
/*************************************************************************/

VOID PacketInitPacket(LPPACKET lpPacket, PVOID Buffer, UINT Length)
{
    lpPacket->Buffer = Buffer;
    lpPacket->Length = Length;
}

/*************************************************************************/
/*                                                                       */
/*  PacketSendPacket - send a Packet                                     */
/*                                                                       */
/*      Args:   lpAdapter - pointer to an Adapter                        */
/*              lpPacket  - pointer to a Packet                          */
/*              Sync      - synchronous or asynchronous I/O              */
/*                                                                       */
/*   Returns:   TRUE - synchronous operation completed or                */
/*                     asynchronous operation is pending                 */
/*                                                                       */
/*************************************************************************/

BOOLEAN PacketSendPacket (
                            LPADAPTER lpAdapter,
                            LPPACKET lpPacket,
                            BOOLEAN Sync
                         )
{
    BOOLEAN Result;
    DWORD   BytesTransfered;

    lpPacket->OverLapped.Offset = 0;
    lpPacket->OverLapped.OffsetHigh = 0;

    if (ResetEvent(lpPacket->OverLapped.hEvent) == FALSE)
    { return FALSE; }

    /* WriteFile return value (boolean) not tested  */
    /* This is done later by 'GetOverlappedResult'. */

    WriteFile (
                 lpAdapter->hFile,
                 lpPacket->Buffer,
                 lpPacket->Length,
                 &BytesTransfered,
                 &lpPacket->OverLapped
              );

    if (Sync)
    {
      Result = GetOverlappedResult (
                                      lpAdapter->hFile,
                                      &lpPacket->OverLapped,
                                      &BytesTransfered,
                                      TRUE
                                   );
    }
    else { Result = TRUE; }

    return Result;
}

/*************************************************************************/
/*                                                                       */
/*  PacketReceivePacket - receive a Packet                               */
/*                                                                       */
/*      Args:   lpAdapter   - pointer to an Adapter                      */
/*              lpPacket    - pointer to a Packet                        */
/*              Sync        - synchronous or asynchronous I/O            */
/*              BytesReveived   - pointer to number of bytes received    */
/*                                                                       */
/*   Returns:   TRUE  - synchronous operation completed or               */
/*                      asynchronous operation is pending                */
/*                                                                       */
/*************************************************************************/

BOOLEAN PacketReceivePacket (
                               LPADAPTER lpAdapter,
                               LPPACKET  lpPacket,
                               BOOLEAN   Sync,
                               PULONG    BytesReceived
                            )
{
    BOOLEAN Result;

    lpPacket->OverLapped.Offset = 0;
    lpPacket->OverLapped.OffsetHigh = 0;

    if (ResetEvent(lpPacket->OverLapped.hEvent) == FALSE)
    { return FALSE; }

    /* ReadFile return value (boolean) not tested   */
    /* This is done later by 'GetOverlappedResult'. */

    ReadFile
        (
           lpAdapter->hFile,
           lpPacket->Buffer,
           lpPacket->Length,
           BytesReceived,
           &lpPacket->OverLapped
        );

    if (Sync)
    {
      Result = GetOverlappedResult (
                                      lpAdapter->hFile,
                                      &lpPacket->OverLapped,
                                      BytesReceived,
                                      TRUE
                                   );
    }
    else { Result = TRUE; }

    return Result;
}

/*************************************************************************/
/*                                                                       */
/*  PacketWaitPacket - wait for an asynchronous operation to complete    */
/*                                                                       */
/*      Args:   lpAdapter     - pointer to an Adapter object             */
/*              lpPacket      - pointer to a Packet                      */
/*              BytesReceived - pointer to a bytes received ULONG        */
/*                                                                       */
/*   Returns:   result of asynchronous operation                         */
/*                                                                       */
/*************************************************************************/

BOOLEAN PacketWaitPacket (
                            LPADAPTER lpAdapter,
                            LPPACKET  lpPacket,
                            PULONG    BytesReceived
                         )
{
   return GetOverlappedResult (
                                lpAdapter->hFile,
                                &lpPacket->OverLapped,
                                BytesReceived,
                                TRUE
                              );
}

/*************************************************************************/
/*                                                                       */
/* PacketResetAdapter - reset adapter, completing all pending operations */
/*                                                                       */
/*      Args:   lpAdapter - pointer to an Adapter                        */
/*                                                                       */
/*   Returns:   TRUE                                                     */
/*                                                                       */
/*************************************************************************/

BOOLEAN PacketResetAdapter(LPADAPTER lpAdapter)
{
    UINT    BytesReturned;

    /* DeviceIoControl return value (boolean) not tested. */

    DeviceIoControl (
                       lpAdapter,
                       (DWORD)IOCTL_PROTOCOL_RESET,
                       NULL,
                       0,
                       NULL,
                       0,
                       (LPDWORD)&BytesReturned,
                       (LPOVERLAPPED)NULL
                    );

    return TRUE;
}

/*************************************************************************/
/*                                                                       */
/*  PacketRequest - issue a request to an adapter                        */
/*                                                                       */
/*      Args:   lpAdapter - pointer to an Adapter                        */
/*              Set       - set OID if TRUE else get OID                 */
/*              OidData - pointer to OID data                            */
/*                                                                       */
/*   Returns:   Number of bytes returned                                 */
/*                                                                       */
/*************************************************************************/

ULONG PacketRequest (
                       LPADAPTER lpAdapter,
                       BOOLEAN   Set,
                       PPACKET_OID_DATA OidData
                    )
{
    UINT       BytesReturned = 0;

    /* DeviceIoControl return value not tested */

    DeviceIoControl
         (
            lpAdapter->hFile,
            (DWORD) Set ? IOCTL_PROTOCOL_SET_OID : IOCTL_PROTOCOL_QUERY_OID, OidData,
            sizeof(PACKET_OID_DATA)-1+OidData->Length,
            OidData,
            sizeof(PACKET_OID_DATA)-1+OidData->Length,
            (LPDWORD)&BytesReturned,
            NULL
         );
             
    return BytesReturned;
}

/*************************************************************************/
/*                                                                       */
/*  PacketSetFilter - issue a set filter request to an adapter           */
/*                                                                       */
/*      Args:   lpAdapter  - pointer to an Adapter                       */
/*              Filter     - filter to set                               */
/*                                                                       */
/*   Returns:                                                            */
/*                                                                       */
/*************************************************************************/

BOOLEAN PacketSetFilter(LPADAPTER lpAdapter, ULONG Filter)
{

    BOOLEAN           Status;
    ULONG             IoCtlBufferLength = (sizeof(PACKET_OID_DATA)+sizeof(ULONG)-1);
    PPACKET_OID_DATA  OidData;

    OidData = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, IoCtlBufferLength);

    if (OidData == NULL) { return FALSE; }

    OidData->Oid             = OID_GEN_CURRENT_PACKET_FILTER;
    OidData->Length          = sizeof(ULONG);
    *((PULONG)OidData->Data) = Filter;

    Status = PacketRequest(lpAdapter, TRUE, OidData);
    GlobalFree(OidData);

    return Status;
}

/*************************************************************************/
/*                                                                       */
/*  PacketGetAddress - issue a get address request to an adapter         */
/*                                                                       */
/*      Args:   lpAdapter     - pointer to an Adapter                    */
/*              AddressBuffer - buffer to hold the address               */
/*                                                                       */
/*   Returns:   number of bytes copied to address buffer                 */
/*                                                                       */
/*************************************************************************/

ULONG PacketGetAddress (
                          LPADAPTER lpAdapter,
                          PUCHAR AddressBuffer
                       )
{
    ULONG   Result;
    
    BYTE iBuf[sizeof(PACKET_OID_DATA) + 128];

    PPACKET_OID_DATA pOidData = (PPACKET_OID_DATA)iBuf;

    pOidData->Oid     = OID_802_3_CURRENT_ADDRESS;
    pOidData->Length  = 6;
    pOidData->Data[0] = 0;

    Result = PacketRequest(lpAdapter, 0, pOidData);

    if (Result > 0)
    {
      memcpy(AddressBuffer, &iBuf[8], 6);
      Result = 6;
    }
    else { Result = 0; }
        
    return Result;
}

/*************************************************************************/
/*                                                                       */
/*  StartPacketDriver - starts the kernel mode packet driver             */
/*                                                                       */
/*      Args:   ServiceName - name of service to start                   */
/*                                                                       */
/*   Returns:                                                            */
/*                                                                       */
/*************************************************************************/

BOOLEAN StartPacketDriver(LPTSTR ServiceName)
{
    BOOLEAN    Status;
    SC_HANDLE  SCManagerHandle;
    SC_HANDLE  SCServiceHandle;

    // Open a handle to the SC Manager database.
    SCManagerHandle = OpenSCManager
                      (
                         NULL,       // local machine
                         NULL,       // ServicesActive database
                         SC_MANAGER_ALL_ACCESS
                      );

    if (SCManagerHandle==NULL)
    {
       MessageBox(NULL,TEXT("Could not open SC"), szWindowTitle, MB_OK);
       return FALSE;
    }
    else
    {
        SCServiceHandle = OpenService
                          (
                             SCManagerHandle,
                             ServiceName,
                             SERVICE_START
                          );
 
        if (SCServiceHandle == NULL)
        { MessageBox(NULL,TEXT("Could not open service"),szWindowTitle,MB_OK); }

        Status = StartService(SCServiceHandle, 0, NULL);

        if (Status == FALSE)
        {
           if (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING)
           {
              ODS("Packet32: Packet service already started\n");
              return TRUE;
           }
        }
        return Status;
    }
}

/*************************************************************************/
/*                                                                       */
/*  PacketGetAdapterNames - returns the names of all available adapters  */
/*                                                                       */
/*      Args:   pStr   - pointer to buffer for UNICODE names             */
/*              pSize  - address of ulong containing string length       */
/*                                                                       */
/*   Returns:                                                            */
/*                                                                       */
/*************************************************************************/

ULONG PacketGetAdapterNames (
                               PTSTR pStr,
                               PULONG pSize
                            )
{

    HKEY    SystemKey;
    HKEY    ControlSetKey;
    HKEY    ServicesKey;
    HKEY    NdisPerfKey;
    HKEY    LinkageKey;
    LONG    Status;
    DWORD   RegType;

    Status = RegOpenKeyEx (
                             HKEY_LOCAL_MACHINE,
                             TEXT("SYSTEM"),
                             0,
                             KEY_READ,
                             &SystemKey
                          );

    if (Status == ERROR_SUCCESS)
    {
        Status = RegOpenKeyEx (
                                SystemKey,
                                TEXT("CurrentControlSet"),
                                0,
                                KEY_READ,
                                &ControlSetKey
                              );

        if (Status == ERROR_SUCCESS)
        {
            Status = RegOpenKeyEx (
                                    ControlSetKey,
                                    TEXT("Services"),
                                    0,
                                    KEY_READ,
                                    &ServicesKey
                                  );

            if (Status == ERROR_SUCCESS)
            {
                Status = RegOpenKeyEx (
                                         ServicesKey,
                                         TEXT("Packet"),
                                         0,
                                         KEY_READ,
                                         &NdisPerfKey
                                      );

                if (Status == ERROR_SUCCESS)
                {
                    Status = RegOpenKeyEx (
                                            NdisPerfKey,
                                            TEXT("Linkage"),
                                            0,
                                            KEY_READ,
                                            &LinkageKey
                                          );

                    if (Status == ERROR_SUCCESS)
                    {
                        Status = RegQueryValueEx (
                                                   LinkageKey,
                                                   TEXT("Export"),
                                                   NULL,
                                                   &RegType,
                                                   (LPBYTE)pStr,
                                                   pSize
                                                 );
                                                 
                        /* WARNING                             */
                        /* RegCloseKey return value not tested */
                                                 
                        RegCloseKey(LinkageKey);
                    }
 
                    /* WARNING                             */
                    /* RegCloseKey return value not tested */
                    
                    RegCloseKey(NdisPerfKey);
                }
                
                /* WARNING                             */
                /* RegCloseKey return value not tested */

                RegCloseKey(ServicesKey);
            }

            /* WARNING                             */
            /* RegCloseKey return value not tested */

            RegCloseKey(ControlSetKey);
        }

        /* WARNING                             */
        /* RegCloseKey return value not tested */

        RegCloseKey(SystemKey);
    }

    return Status;
}

/*************************************************************************/
/*                                                                       */
/*  PacketGetName - returns the name of a specified adapter              */
/*                                                                       */
/*      Args:   pStr - pointer to buffer for a UNICODE name              */
/*              n    - which name to return                              */
/*                                                                       */
/*   Returns:   TRUE  if the n'th name was found                         */
/*              FALSE if the n'th name does not exist                    */
/*                                                                       */
/*************************************************************************/

ULONG PacketGetName (
                       PTSTR pStr,
                       ULONG n
                    )
{
    TCHAR   buf[256];
    TCHAR   *Name;
    ULONG   NameLength = 256;

    Name = buf;
        
    PacketGetAdapterNames(Name, &NameLength);

    switch (n)
    {
        case 3: Name = &Name[strlen(Name)+1];
                if (!strlen(Name))
                    break;
        case 2: Name = (char *) &Name[strlen(Name)+1];
                if (!strlen(Name))
                    break;
        case 1: Name = (char *) &Name[strlen(Name)+1];
                if (!strlen(Name))
                    break;
        case 0: break;
    }
    
    if (strlen(Name) != 0)
    {
        strcpy(pStr, Name);
        return TRUE;
    }
    else { return FALSE; }
}
