#ifndef _WRMEM_H
#define _WRMEM_H

#include <ntddk.h>
#include "pt.h"
#include "intel.h"

PCHAR CheckPool;
SINGLE_LIST_ENTRY lstMapInfo;	//mapped memory information

typedef struct _PHYMEM_MEM {
	PVOID addr;	//physical addr when mapping, virtual addr when unmapping
	ULONG size;	//memory size to map or unmap
} PHYMEM_MEM, *PPHYMEM_MEM;

//Mapped memory information list
typedef struct _MAPINFO {
	SINGLE_LIST_ENTRY	link;
	PMDL				pMdl;	//allocated mdl
	PVOID				pvk;	//kernel mode virtual address
	PVOID				pvu;	//user mode virtual address
	ULONG				memSize;//memory size in bytes
} MAPINFO, * PMAPINFO;

CHAR sharedBuffer[0x2000];

VOID InitWRMem();
VOID FreeWRMem();

PCHAR FindMemoryPAELocal(PCHAR buffer, ULONG bytes);
PCHAR FindMemoryPAE(ULONG bytes, PCHAR address);
PMAPINFO MapPhyMem(PPHYMEM_MEM pMem, PVOID buffer, MODE mode, MEMORY_CACHING_TYPE cachType);
VOID WritePhyMem(PVOID address, PUCHAR buffer, ULONG size);
VOID MapPhyMemFree(PPHYMEM_MEM pMem);
PCHAR FindStrInMap(PVOID map, ULONG size, PCHAR str);

VOID PrintMapDWORD(PVOID map, ULONG size, ULONG offset);
VOID PrintMapBYTE(PVOID map, ULONG size, ULONG offset);

//BOOLEAN READ_W_PAE_HANDLER(char* buf, const ULONG addr, const ULONG len);
//BOOLEAN READ_W_PAE_HANDLER2(char* buf, const ULONG addr, const ULONG len);
//BOOLEAN READ_WO_PAE_HANDLER(char* buf, const ULONG addr, const ULONG len);


#endif // !_WRMEM_H
