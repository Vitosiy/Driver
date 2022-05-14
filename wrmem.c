#include "wrmem.h"

VOID InitWRMem() {
	ULONG i;
	ULONG size = 0x50;

	lstMapInfo.Next = NULL;

	CheckPool = (PCHAR)ExAllocatePoolWithTag(NonPagedPool, size, 'oneN');

	for (i = 0; i < size; ++i) {
		CheckPool[i] = '0' + (i & 0x7);
	}
	//DbgPrint("STR:%s\n", CheckPool);

	return;
}
VOID FreeWRMem() {

	PMAPINFO pMapInfo;
	PSINGLE_LIST_ENTRY pLink;


	if (CheckPool) {
		ExFreePool(CheckPool);
	}

	//free resources
	pLink = PopEntryList(&lstMapInfo);
	while (pLink)
	{
		pMapInfo = CONTAINING_RECORD(pLink, MAPINFO, link);

		MmUnmapLockedPages(pMapInfo->pvu, pMapInfo->pMdl);
		IoFreeMdl(pMapInfo->pMdl);
		MmUnmapIoSpace(pMapInfo->pvk, pMapInfo->memSize);

		ExFreePool(pMapInfo);

		pLink = PopEntryList(&lstMapInfo);
	}

	return;
}

PCHAR FindMemoryPAELocal(PCHAR buffer, ULONG bytes) {
	
	ULONG i;
	PCHAR address;
	ULONG pdeIndex;
	ULONG pteIndex;
	PPAEPDE pde;
	PPAEPTE pte;

	ULONG k;

	for (pdeIndex = 0; pdeIndex < MAX_PAE_PDE_INDEX; ++pdeIndex) {
		pde = (PPAEPDE)GET_PAE_PDE_ADDRESS_FROM_PDE_INDEX(pdeIndex);

		if (pde->P) {
			if (!pde->PS) {
				for (pteIndex = 0; pteIndex < MAX_PAE_PTE_INDEX; ++pteIndex) {
					i = 0;
					pte = (PPAEPTE)GET_PAE_PTE_ADDRESS_FROM_PDE_INDEX_PTE_INDEX(pdeIndex, pteIndex);
					if (pte->P) {
						for (address = (PCHAR)GET_PAE_VA_FROM_PTE_ADDRESS(pte);
							address != (PCHAR)GET_PAE_LAST_VA_FROM_PTE_ADDRESS(pte);
							++address) {
							if (*address == buffer[i]) ++i;
							else if (i) i = 0;

							if (i + 1 == bytes) {
								ULONG a, b;
								DbgPrint("------------------------\n");
								a = pde->R_W;
								b = pte->R_W;
								//DbgPrint("%d %d pde pte\n", a, b);
								//for (k = 0; k < bytes; ++k) {
								//	DbgPrint("%c", (address - i + 1)[k]);
								//	(address - i + 1)[k] = 'Z';
								//}
								//for (k = 0; k < bytes; ++k) {
								//	DbgPrint("%c", (address - i + 1)[k]);
								//}
								DbgPrint("\npte:%d pde:%d address:%X\n", pteIndex, pdeIndex, address - i + 1);
								if (pdeIndex != 0) {
									//for (k = 0; k < bytes; ++k) {
									//	DbgPrint("%c", (address - i + 1)[k]);
									//	(address - i + 1)[k] = 'Z';
									//}
									return address - i + 1;
								}
							}
						}
					}
				}
			}
		}
	}

	return NULL;
}


PCHAR FindMemoryPAE(ULONG bytes, PCHAR address) {
ULONG oldPhysAddress;
PPAEPTE pte1;
PPAEPTE pte2;
ULONG i;

	sharedBuffer[0] = 'a';
	DbgPrint("\nDDDDDDDDDDDDDD %s\n", address);
	DbgPrint("POINT : %X %X\n", sharedBuffer, &sharedBuffer);
	DbgPrint("POINT : %X %X\n", address, &address);
	pte1 = (PPAEPTE)GET_PAE_PTE_ADDRESS_FROM_VA(&sharedBuffer);
	pte2 = (PPAEPTE)GET_PAE_PTE_ADDRESS_FROM_VA(address);
	oldPhysAddress = pte2->Address;
	pte2->Address = pte1->Address;

	for (i = 0; i < bytes; ++i) {
		sharedBuffer[i] = 'D';
	}

	pte2->Address = oldPhysAddress;
	DbgPrint("\nDDDDDDDDDDDDDD %s\n", address);

	

	return NULL;
}


PMAPINFO MapPhyMem(PPHYMEM_MEM pMem, PVOID pVirAddr, MODE mode, MEMORY_CACHING_TYPE cachType) {
	PHYSICAL_ADDRESS phyAddress;
	PVOID pvk, pvu;
	PMAPINFO pMapInfo = NULL;

	phyAddress.QuadPart = (ULONGLONG)pMem->addr;

	//get mapped kernel address
	pvk = MmMapIoSpace(phyAddress, pMem->size, cachType);

	if (pvk) {
		//allocate mdl for the mapped kernel address
		PMDL pMdl = IoAllocateMdl(pvk, pMem->size, FALSE, FALSE, NULL);
		if (pMdl) {
			
			//build mdl and map to user space
			MmBuildMdlForNonPagedPool(pMdl);
			//DbgPrint("%c", (PCHAR)NULL);
			__try {
				// Old method
				// pvu = MmMapLockedPages(pMdl, mode);
				
				// As per Microsoft documentation, this function can throw an exception
				pvu = MmMapLockedPagesSpecifyCache(pMdl, mode, cachType, NULL, FALSE, NormalPagePriority);
			} __except(EXCEPTION_CONTINUE_EXECUTION) {
				IoFreeMdl(pMdl);
				MmUnmapIoSpace(pvk, pMem->size);
				DbgPrint("EXCEPTION_CONTINUE_EXECUTION\n");
				return NULL;
			}
			//insert mapped infomation to list
			pMapInfo = (PMAPINFO)ExAllocatePoolWithTag(NonPagedPool, sizeof(MAPINFO), 'oneN');
			if (pMapInfo) {
				pMapInfo->pMdl = pMdl;
				pMapInfo->pvk = pvk;
				pMapInfo->pvu = pvu;
				pMapInfo->memSize = pMem->size;
				PushEntryList(&lstMapInfo, &pMapInfo->link);

				//DbgPrint("Map physical:0x%x to virtual user:0x%x kernel:0x%X size:%u\n", pMem->addr, pvu, pvk, pMem->size);

				RtlCopyMemory(pVirAddr, &pvu, sizeof(PVOID));
			} else {
				MmUnmapLockedPages(pvu, pMdl);
				IoFreeMdl(pMdl);
				MmUnmapIoSpace(pvk, pMem->size);
				DbgPrint("Error allocate for MAPINFO\n");
			}
		} else {
			//allocate mdl error, unmap the mapped physical memory
			MmUnmapIoSpace(pvk, pMem->size);
			DbgPrint("\nError allocate MDL\n");
		}
	} else {
		MmUnmapIoSpace(pvk, pMem->size);
		DbgPrint("\nError mapped kernel address\n");
	}
	return pMapInfo;
}

VOID WritePhyMem(PVOID address, PUCHAR buffer, ULONG size) {
	PMAPINFO pMapInfo;
	PHYMEM_MEM mem;
	PVOID map = NULL;
	mem.addr = address;
	mem.size = size;

	MapPhyMem(&mem, &map, KernelMode, MmNonCached);
	if (map) {
		pMapInfo = RtlCopyMemory(map, buffer, size);

		// ???
		// do I need to use this when MEMORY_CACHING_TYPE == MmNonCached
		KeFlushIoBuffers(pMapInfo->pMdl, FALSE, TRUE);
		// ???

		MapPhyMemFree(&mem);
	}
	else {
		DbgPrint("Error write physical memmory");
	}
	return;
}

VOID MapPhyMemFree(PPHYMEM_MEM pMem) {
	PMAPINFO pMapInfo;
	PSINGLE_LIST_ENTRY pLink, pPrevLink;

	//initialize to head
	pPrevLink = pLink = lstMapInfo.Next;
	while (pLink) {
		pMapInfo = CONTAINING_RECORD(pLink, MAPINFO, link);

		if (pMapInfo->pvu == pMem->addr) {
			if (pMapInfo->memSize == pMem->size) {
				//DbgPrint("%c", (PCHAR)NULL);
				//free mdl, unmap mapped memory
				MmUnmapLockedPages(pMapInfo->pvu, pMapInfo->pMdl);
				IoFreeMdl(pMapInfo->pMdl);
				MmUnmapIoSpace(pMapInfo->pvk, pMapInfo->memSize);

				//DbgPrint("Unmap virtual address:0x%x size:%u\n", pMapInfo->pvu, pMapInfo->memSize);

				//delete matched element from the list
				if (pLink == lstMapInfo.Next)
					lstMapInfo.Next = pLink->Next;	//delete head elememt
				else
					pPrevLink->Next = pLink->Next;

				ExFreePool(pMapInfo);
			}
			else
				DbgPrint("Error param");

			break;
		}

		pPrevLink = pLink;
		pLink = pLink->Next;
	}

	return;
}

PCHAR FindStrInMap(PVOID map, ULONG size, PCHAR str) {
	ULONG i;
	ULONG bytes = 0;
	ULONG lenStr = strlen(str);
	PCHAR bytePtr = (PCHAR)map;

	for (i = 0; i < size; ++i) {

		if (bytePtr[i] == str[bytes]) ++bytes;
		else if (bytes) bytes = 0;

		if (bytes == lenStr) {
			//printf("BYTEPTR : 0x%X %d\n", (DWORD)bytePtr, bytes);
			return (bytePtr + i - bytes + 1);
		}
	}

	return NULL;
}

VOID PrintMapDWORD(PVOID map, ULONG size, ULONG offset) {

	PCHAR dbgStr = "%08X";
	ULONG i;
	DbgPrint("\n\nMAP ADDRESS : %X\n", map);
	DbgPrint("0: ");
	for (i = offset; i < size / 4; ++i) {
		
		if (i) {
			if (i == 0x1000 / 4) {
				DbgPrint("\n-------------\n");
			}
			if (i % 8 == 0) {
				DbgPrint("\n%d: ", (i / 8));
			}
			else {
				DbgPrint(" ");
			}
			
		}
		__asm {
			mov ebx, i
			mov eax, 4
			mul ebx
			mov ebx, map
			add ebx, eax
			mov ebx, dword ptr[ebx]
			push ebx
			push dbgStr
			call DbgPrint
		}

	}
	DbgPrint("\n");

	return;
}

VOID PrintMapBYTE(PVOID map, ULONG size, ULONG offset) {

	PCHAR dbgStr = "%02X";
	ULONG i;
	DbgPrint("\n\nMAP ADDRESS : %X\n", map);
	DbgPrint("0: ");
	for (i = offset; i < size; ++i) {

		if (i) {
			if (i % 32 == 0) {
				DbgPrint("\n%d: ", (i / 32));
			}
			else {
				DbgPrint(" ");
			}
		}
		__asm {
			mov eax, map
			add eax, i
			xor ebx, ebx
			mov bl, byte ptr[eax]
			push ebx
			push dbgStr
			call DbgPrint
		}

	}
	DbgPrint("\n");

	return;
}