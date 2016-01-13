// test.h - include file for the test application

#ifndef __PACKET32

#define __PACKET32
#define EXPORT                 __declspec(dllexport)
#define DOSNAMEPREFIX          TEXT("Packet_")
#define MAX_LINK_NAME_LENGTH   64

#include "packon.h"

typedef struct _PACKET_OID_DATA
{
    ULONG           Oid;
    ULONG           Length;
    UCHAR           Data[1];
}   PACKET_OID_DATA, *PPACKET_OID_DATA;

#include "packoff.h"

typedef struct _ADAPTER
{
    HANDLE     hFile;
    TCHAR      SymbolicLink[MAX_LINK_NAME_LENGTH];
} ADAPTER, *LPADAPTER;

typedef struct _PACKET
{
    HANDLE       hEvent;
    OVERLAPPED   OverLapped;
    PVOID        Buffer;
    UINT         Length;
} PACKET, *LPPACKET;


PVOID PacketOpenAdapter(LPTSTR AdapterName);

BOOLEAN PacketSendPacket(LPADAPTER lpAdapter,
                         LPPACKET  lpPacket,
                         BOOLEAN   Sync);

PVOID PacketAllocatePacket(VOID);

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

/* Ndis Packet Filter Bits (OID_GEN_CURRENT_PACKET_FILTER). */

#define NDIS_PACKET_TYPE_DIRECTED           0x0001
#define NDIS_PACKET_TYPE_MULTICAST          0x0002
#define NDIS_PACKET_TYPE_ALL_MULTICAST      0x0004
#define NDIS_PACKET_TYPE_BROADCAST          0x0008
#define NDIS_PACKET_TYPE_SOURCE_ROUTING     0x0010
#define NDIS_PACKET_TYPE_PROMISCUOUS        0x0020
#define NDIS_PACKET_TYPE_SMT                0x0040
#define NDIS_PACKET_TYPE_ALL_LOCAL          0x0080
#define NDIS_PACKET_TYPE_MAC_FRAME          0x8000
#define NDIS_PACKET_TYPE_FUNCTIONAL         0x4000
#define NDIS_PACKET_TYPE_ALL_FUNCTIONAL     0x2000
#define NDIS_PACKET_TYPE_GROUP              0x1000

/* buffer status */
#define   EMPTY                           0
#define   FULL                            1

#define PACKET_RECV_END_OK                2
#define PACKET_RECV_END_ERR               3

#define PACKET_GET_PACKET_ERR             4
#define PACKET_SYNC_ERROR                 5

#define PACKET_ROLL_MUTEX_ERROR           6
#define PACKET_ROLL_GET_MUTEX_ERROR       7
#define PACKET_ROLL_RELEASE_MUTEX_ERROR   8
#define PACKET_ROLL_OVERFLOW              9
#define PACKET_ROLL_OK                    10

#define PACKET_PRINT_OK                   11
#define PACKET_PRINT_END_ERR              12
#define PACKET_PRINT_FILE_ERR             13

#endif
