#include "ntddpack.h"
#ifndef __PACKET32
#define __PACKET32
#define EXPORT __declspec(dllexport)

#define        DOSNAMEPREFIX   TEXT("Packet_")

#define        MAX_LINK_NAME_LENGTH   64


typedef struct _ADAPTER {

    HANDLE     hFile;

    TCHAR      SymbolicLink[MAX_LINK_NAME_LENGTH];

    } ADAPTER, *LPADAPTER;


typedef struct _PACKET {
    HANDLE       hEvent;
    OVERLAPPED   OverLapped;
    PVOID        Buffer;
    UINT         Length;
    } PACKET, *LPPACKET;

/* Receiver Block definition */

    struct rcvblk {
        int       active;
        int       intf;
        struct ep *pep;
        int       len;
        DWORD     cbRet;
        LPPACKET  lpPacket;
    };

#define RTAB_SIZE 8                 /* 8 is an empirical value */


PVOID PacketOpenAdapter(LPTSTR AdapterName);


BOOLEAN PacketSendPacket(LPADAPTER lpAdapter,
                         LPPACKET  lpPacket,
                         BOOLEAN   Sync);


PVOID PacketAllocatePacket();             


VOID PacketInitPacket(LPPACKET lpPacket,    
                      PVOID    Buffer,
                      UINT     Length);


VOID PacketFreePacket(LPPACKET lpPacket);


BOOLEAN PacketResetAdapter(LPADAPTER lpAdapter);


ULONG PacketGetAddress(LPADAPTER lpAdapter,
                       PUCHAR    AddressBuffer);


BOOLEAN PacketWaitPacket(LPADAPTER  lpAdapter,
                         LPPACKET   lpPacket,
                         PULONG     BytesReceived);


BOOLEAN PacketReceivePacket(LPADAPTER lpAdapter,
                            LPPACKET  lpPacket,
                            BOOLEAN   Sync,
                            PULONG    BytesReceived);


VOID PacketCloseAdapter(LPADAPTER lpAdapter);


BOOLEAN PacketSetFilter(LPADAPTER lpAdapter,
                        ULONG     Filter);


ULONG PacketGetAdapterNames(PTSTR   pStr,
                            PULONG  BufferSize);


ULONG PacketRequest(LPADAPTER lpAdapter,
                    BOOLEAN   Set,
                    PPACKET_OID_DATA OidData);


ULONG PacketGetName(PTSTR pStr, 
                    ULONG n);

#endif
