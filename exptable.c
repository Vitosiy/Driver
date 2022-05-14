#include "exptable.h"

NTSTATUS MyEnumKernelModule(IN CHAR* str, OUT PVOID* moduleadd)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG n = 0;
    ULONG i = 0;
    PSYSTEM_MODULE_INFORMATION_ENTRY module = NULL;
    PVOID pbuftmp = NULL;
    ANSI_STRING ModuleName1, ModuleName2;

    status = ZwQuerySystemInformation(SystemModuleInformation, &n, 0, &n);

    pbuftmp = ExAllocatePool(NonPagedPool, n);

    status = ZwQuerySystemInformation(SystemModuleInformation, pbuftmp, n, NULL);
    module = (PSYSTEM_MODULE_INFORMATION_ENTRY)((PULONG)pbuftmp + 1);

    RtlInitAnsiString(&ModuleName1, str);

    n = *((PULONG)pbuftmp);
    for (i = 0; i < n; i++)
    {
        RtlInitAnsiString(&ModuleName2, module[i].ImageName);
        DbgPrint("%d 0x%08X 0x%08X %s \n", module[i].Index, module[i].Base, module[i].Size, module[i].ImageName);
        if (RtlCompareString(&ModuleName1, &ModuleName2, TRUE) == 0)
        {
            DbgPrint("\n Found!\n Path: %s \n BaseAddr: 0x%08X \n\n", ModuleName2.Buffer, module[i].Base);
            *moduleadd = module[i].Base;
            break;
        }
    }
    ExFreePool(pbuftmp);

    return status;
}

VOID ImgBase(IN PVOID lpBase, OUT PULONG pImageBase) {

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBase;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        DbgPrint("Image has no DOS header!\n");
        return;
    }
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((char*)lpBase + pDosHeader->e_lfanew);
    if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        DbgPrint("Image has no NT header!\n");
        return;
    }
    if (pImageBase)
        *pImageBase = pNtHeader->OptionalHeader.ImageBase;
}