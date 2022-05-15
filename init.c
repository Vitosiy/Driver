#include <ntddk.h>
#include <stdio.h>
#include "intel.h"
#include "ioctl.h"
#include "hookidt.h"
#include "dump.h"
#include "hooksysenter.h"
#include "wrmem.h"
#include "pt.h"
//#include "exptable.h"

#define	SYM_LINK_NAME   L"\\Global??\\Driver"
#define DEVICE_NAME     L"\\Device\\DDriver"

#define HOOK_STRING     L"\\hook"
#define INFO_STRING     L"\\info"

UNICODE_STRING  DevName;
UNICODE_STRING	SymLinkName;

//*************************************************************
// ��������������� ���������� �������


DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;


NTSTATUS DispatchCreate(IN PDEVICE_OBJECT DeviceObject, IN PIRP pIrp);
NTSTATUS DispatchClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP pIrp);
NTSTATUS DispatchControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP pIrp);
NTSTATUS DispatchRead(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);
NTSTATUS DispatchWrite(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);
NTSTATUS CompleteIrp(PIRP Irp, NTSTATUS status, ULONG Info);

VOID InsertCallGate(ULONG index, PVOID handler);
void CallGateHook();
void CallGateInfo();
VOID InsertTrapGate(ULONG index, PVOID handler);
void TrapGateHandler();

void FreeMapHandler();
void WriteMemHandler();
void ReadMemHandler();

BOOLEAN DUMP_IDT_HANDLER(unsigned char* outbuffer, int* exact_bytes_wrote);
BOOLEAN DUMP_GDT_HANDLER(unsigned char* outbuffer, int* exact_bytes_wrote);
BOOLEAN HookSyscall(PKSERVICE_TABLE_DESCRIPTOR table, PVOID addressHooker, ULONG index, UCHAR param, PKSERVICE_TABLE_DESCRIPTOR backup);
BOOLEAN ChangeSyscallTable(PKSERVICE_TABLE_DESCRIPTOR table, ULONG extra);
void InPortSyscall(USHORT port, PCHAR buffer, ULONG sz);
void OutPortSyscall(USHORT port, PCHAR buffer, ULONG sz);
void DumpGdtSysCall(PCHAR buffer, ULONG size);
void DumpIdtSysCall(PCHAR buffer, ULONG size);
void RollbackChangeSyscallTable(PKSERVICE_TABLE_DESCRIPTOR table, PULONG_PTR old_base, PUCHAR old_param, ULONG limit);
void CreateOverIndexGDT(ULONG index);
void PrintSSDT(PKSERVICE_TABLE_DESCRIPTOR table, PCHAR str);
ULONG ClearWP(void);
void WriteCR0(ULONG reg);
void test();

typedef ULONG_PTR (*NT_USER_SET_INFORMATION_PROCESS)(
    ULONG_PTR	arg_01,
    ULONG_PTR	arg_02,
    ULONG_PTR	arg_03,
    ULONG_PTR	arg_04
);

NT_USER_SET_INFORMATION_PROCESS glRealNtUserSetInformationProcess;

ULONG_PTR __stdcall HookNtUserSetInformationProcess(
    ULONG_PTR	arg_01,
    ULONG_PTR	arg_02,
    ULONG_PTR	arg_03,
    ULONG_PTR	arg_04
);

//*************************************************************
// ���������� ����������

KSERVICE_TABLE_DESCRIPTOR backupTable[4];
KSERVICE_TABLE_DESCRIPTOR backupTableShadow[4];

// ������� ������������� ��������
NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath) {

NTSTATUS status = STATUS_SUCCESS;
PDEVICE_OBJECT  DeviceObject;
//PVOID ModuleAddress;
//ULONG uImageBase;
ULONG reg;
ULONG i;

    DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
    DriverObject->MajorFunction[IRP_MJ_READ] = DispatchRead;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = DispatchWrite;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchControl;

    DriverObject->DriverUnload = DriverUnload;
#if DBG
    DbgPrint("Load driver %wZ\n", &DriverObject->DriverName);
    DbgPrint("Registry path %wZ\n\n", RegistryPath);
#endif

    RtlInitUnicodeString(&DevName, DEVICE_NAME);
    RtlInitUnicodeString(&SymLinkName, SYM_LINK_NAME);

    // �������� ����������
    status = IoCreateDevice(DriverObject,	// ��������� �� ������ ��������
                            0,				// ������ ������� �������������� ������ ����������
                            &DevName,		// ��� ����������
                    FILE_DEVICE_UNKNOWN,	// ������������� ���� ����������
                            0,				// �������������� ���������� �� ����������
                            FALSE,			// ��� ������������� �������
                            &DeviceObject); // ����� ��� ���������� ��������� �� ������ ����������
    if (!NT_SUCCESS(status))
        return status;

#if DBG
    DbgPrint("Create device %ws\n", DEVICE_NAME);
#endif

    // �������� ���������� ������
    status = IoCreateSymbolicLink(&SymLinkName, &DevName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(DeviceObject);
        return status;
    }
    KeServiceDescriptorTableShadow = (PKSERVICE_TABLE_DESCRIPTOR)((ULONG)KeServiceDescriptorTable - 0x40);
    //****************************dump gdt, idt
    PrintSSDT(KeServiceDescriptorTable, "KeServiceDescriptorTable");
    PrintSSDT(KeServiceDescriptorTableShadow, "KeServiceDescriptorTableShadow");

    // for syscall 0x2006
    HookSyscall(&KeServiceDescriptorTable[2], DumpGdtSysCall, 0x6, sizeof(PCHAR) + sizeof(ULONG), &backupTable[2]);
    HookSyscall(&KeServiceDescriptorTableShadow[2], DumpGdtSysCall, 0x6, sizeof(PCHAR) + sizeof(ULONG), &backupTableShadow[2]);
    
    // for syscall 0x3013
    HookSyscall(&KeServiceDescriptorTable[3], DumpIdtSysCall, 0x13, sizeof(PCHAR) + sizeof(ULONG), &backupTable[3]);
    HookSyscall(&KeServiceDescriptorTableShadow[3], DumpIdtSysCall, 0x13, sizeof(PCHAR) + sizeof(ULONG), &backupTableShadow[3]);
    
    //****************************init hook ints
    InitializateContextList();
    InsertCallGate(126, CallGateHook); //hook
    InsertCallGate(127, CallGateInfo); //info

    //****************************init hook sysenter
    InitHookSysenter();

    //****************************init w/r mem
    InitWRMem();
    InsertTrapGate(0x75, FreeMapHandler);
    InsertTrapGate(0x76, ReadMemHandler);
    InsertTrapGate(0x77, WriteMemHandler);

    //****************************init syscalls for i/o
    // for syscall 0x1fa
    HookSyscall(KeServiceDescriptorTable, InPortSyscall, 0x1fa, sizeof(PCHAR) + sizeof(ULONG) + sizeof(USHORT), backupTable);
    HookSyscall(KeServiceDescriptorTableShadow, InPortSyscall, 0x1fa, sizeof(PCHAR) + sizeof(ULONG) + sizeof(USHORT), backupTableShadow);
    KeServiceDescriptorTable->Base[0x1f9] = (ULONG_PTR)OutPortSyscall;
    KeServiceDescriptorTableShadow->Base[0x1f9] = (ULONG_PTR)OutPortSyscall;
    KeServiceDescriptorTable->Number[0x1f9] = sizeof(PCHAR) + sizeof(ULONG) + sizeof(USHORT);
    KeServiceDescriptorTableShadow->Number[0x1f9] = sizeof(PCHAR) + sizeof(ULONG) + sizeof(USHORT);

    // for syscall 0x1207
    //HookSyscall(&KeServiceDescriptorTable[1], OutPortSyscall, 0x207, sizeof(PCHAR) + sizeof(ULONG), &backupTable[1]);
    //DbgPrint("HEX %X\n", KeServiceDescriptorTableShadow[1].Base);
    //glRealNtUserSetInformationProcess = (NT_USER_SET_INFORMATION_PROCESS)KeServiceDescriptorTableShadow[1].Base[0x207];
    //reg = ClearWP();
    //KeServiceDescriptorTableShadow[1].Base[0x207] = (ULONG)HookNtUserSetInformationProcess;
    //WriteCR0(reg);

    PrintSSDT(KeServiceDescriptorTable, "KeServiceDescriptorTable");
    PrintSSDT(KeServiceDescriptorTableShadow, "KeServiceDescriptorTableShadow");
    
    //MyEnumKernelModule("\\systemroot\\system32\\win32k.sys", &ModuleAddress);
    //DbgPrint("ModuleAddress: 0x%08X \n", ModuleAddress);
    //ImgBase(ModuleAddress, &uImageBase);
    //DbgPrint("ImageBase: 0x%08X", uImageBase);

    //test();

    

#if DBG
    DbgPrint("Create symbolic link %ws\n", SYM_LINK_NAME);
#endif

    PlaceFunction();

    return status;
}

void test() {
    UNICODE_STRING routineName;
    PKSERVICE_TABLE_DESCRIPTOR pServiceDescriptorTable;
    PKSERVICE_TABLE_DESCRIPTOR pServiceDescriptorTableShadow;
    RtlInitUnicodeString(&routineName, L"KeServiceDescriptorTable");
    pServiceDescriptorTable = (PKSERVICE_TABLE_DESCRIPTOR)MmGetSystemRoutineAddress(&routineName);
    pServiceDescriptorTableShadow = (PKSERVICE_TABLE_DESCRIPTOR)((ULONG_PTR)pServiceDescriptorTable - 0x40);
    DbgPrint("SSDT: 0x%08X 0x%08X\n", pServiceDescriptorTable, KeServiceDescriptorTable);
    DbgPrint("SSDT: 0x%08X 0x%08X\n", pServiceDescriptorTableShadow, (ULONG_PTR)KeServiceDescriptorTable - 0x40);

    return;
}

//----------------------------------------
NTSTATUS CompleteIrp(PIRP Irp, NTSTATUS status, ULONG Info) {

    Irp->IoStatus.Status = status;		// ������ ���������� ��������
    Irp->IoStatus.Information = Info;	// ���������� ����������� ����������
    IoCompleteRequest(Irp, IO_NO_INCREMENT);	// ���������� �������� �����-������
    return status;
}
NTSTATUS DispatchClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP pIrp) {

    return CompleteIrp(pIrp, STATUS_SUCCESS, 0);
}
NTSTATUS DispatchCreate(IN PDEVICE_OBJECT DeviceObject, IN PIRP pIrp) {

    return CompleteIrp(pIrp, STATUS_SUCCESS, 0); // ���������� IRP
}
VOID DriverUnload(IN PDRIVER_OBJECT DriverObject) {

ULONG reg;

    RollbackChangeSyscallTable(KeServiceDescriptorTable, backupTable->Base, backupTable->Number, backupTable->Limit);
    //RollbackChangeSyscallTable(&KeServiceDescriptorTable[1], backupTable[1].Base, backupTable[1].Number, backupTable[1].Limit);
    RollbackChangeSyscallTable(&KeServiceDescriptorTable[2], backupTable[2].Base, backupTable[2].Number, backupTable[2].Limit);
    RollbackChangeSyscallTable(&KeServiceDescriptorTable[3], backupTable[3].Base, backupTable[3].Number, backupTable[3].Limit);

    RollbackChangeSyscallTable(KeServiceDescriptorTableShadow, backupTableShadow->Base, backupTableShadow->Number, backupTableShadow->Limit);
    //RollbackChangeSyscallTable(&KeServiceDescriptorTableShadow[1], backupTableShadow[1].Base, backupTableShadow[1].Number, backupTableShadow[1].Limit);
    RollbackChangeSyscallTable(&KeServiceDescriptorTableShadow[2], backupTableShadow[2].Base, backupTableShadow[2].Number, backupTableShadow[2].Limit);
    RollbackChangeSyscallTable(&KeServiceDescriptorTableShadow[3], backupTableShadow[3].Base, backupTableShadow[3].Number, backupTableShadow[3].Limit);

    //reg = ClearWP();
    //KeServiceDescriptorTableShadow[1].Base[0x207] = (ULONG)glRealNtUserSetInformationProcess;
    //WriteCR0(reg);

    FreeContextList();
    FreeHookSysenterEaxs();
    FreeWRMem();

    // �������� ���������� ������ � ������� ����������
    IoDeleteSymbolicLink(&SymLinkName);
    IoDeleteDevice(DriverObject->DeviceObject);

#if DBG
    DbgPrint("Driver unload");
#endif

    return;
}
//----------------------------------------

void CallHookInt(PCHAR codeChar) {
    ULONG i;
    ULONG code;
    NTSTATUS status = RtlCharToInteger(codeChar, (ULONG)NULL, &code);
    DbgPrint("HOOK\n");
    if (NT_SUCCESS(status)) {
        if (code < 0x100) { // codes interrupts
            HookInterrupt(code);
            return;
        }
    }
    DbgPrint("ERROR HOOK");
}

void CallInfoInt(PCHAR buffer) {
    ULONG i;
    ULONG info = 0;
    if (buffer) {
        //INT32 size = *(PINT32)buffer;
        //DbgPrint("\n0x%X 0x%X\n", buffer, size);

        for (i = 0; i < 0x100; ++i) {
            if (context[i].found) {
                PLIST_ENTRY link = &context[i].link;
                info += sprintf(buffer + info, "Index: 0x%X\tCount: %d\n", i, context[i].count);
                do {
                    PIDT_CONTEXT entry = CONTAINING_RECORD(&context[i].link, IDT_CONTEXT, link);
                    info += sprintf(buffer + info, "Eax:0x%X Ebx:0x%X Ecx:0x%X Edx:0x%X\n",
                        entry->regs.Eax, entry->regs.Ebx, entry->regs.Ecx, entry->regs.Edx);
                    link = link->Flink;
                } while (link != &context[i].link);
            }
        }
    }
    else {
        DbgPrint("\nBuffer is NULL\n");
    }
    return;
}

//********************************************************************** HANDLERS
//i/o port syscall
void InPortSyscall(USHORT port, PCHAR buffer, ULONG sz) {
    int max_address = 0;
    int i = 0;

    DbgPrint("InPortSyscall addr:0x%X buffer:0x%X sz:0x%X\n", port, buffer, sz);
    //RtlCopyMemory(&address, in, 4);
    //max_address = address + 64000;
    //for (i = address; i < max_address; i++) {
    //    __asm {
    //        push eax
    //        push ebx
    //        push edx

    //        xor ecx, ecx
    //        mov eax, i
    //        mov ebx, buffer
    //        add ebx, eax
    //        mov eax, address
    //        in al, dx
    //        mov byte ptr[ebx], al

    //        pop edx
    //        pop ebx
    //        pop eax
    //    }
    //}

    return;
}
void OutPortSyscall(USHORT port, PCHAR buffer, ULONG sz) {

int address = 0;
int max_address = 0;
int i = 0;

    DbgPrint("OutPortSyscall port:0x%X buffer:0x%X sz:0x%X\n", port, buffer, sz);
    
    
    DbgPrint("OUTPUT_PORT\n");
    //RtlCopyMemory(&address, in, 4);
    address = port;
    max_address = address + 64000;
    for (i = address; i < max_address; i++) {
        __asm {
            push eax
            push ebx
            push edx

            xor ecx, ecx
            mov eax, i
            mov ebx, buffer
            add ebx, eax
            mov eax, address
            out dx, al
            mov byte ptr[ebx], al

            pop edx
            pop ebx
            pop eax
        }
    }

    // reload
    //__asm {
    //    mov al, 0xFE
    //    out 0x64, al
    //}


    return;
}
//dump gdt and idt
void DumpGdtSysCall(PCHAR buffer, ULONG size) {
    PCHAR buf;
    ULONG write;

    DbgPrint("0x%X 0x%X\n", buffer, size);

    buf = (PCHAR)ExAllocatePoolWithTag(PagedPool, size, 'oneN');
    if (buf) {
        write = ShowGDT(buf, 0);
        RtlCopyMemory(buffer, buf, write);
        ExFreePool(buf);
    }
    return;
}
void DumpIdtSysCall(PCHAR buffer, ULONG size) {
    PCHAR buf;
    ULONG write;

    DbgPrint("0x%X 0x%X\n", buffer, size);

    buf = (PCHAR)ExAllocatePoolWithTag(PagedPool, size, 'oneN');
    if (buf) {
        write = ShowIDT(buf, 0);
        RtlCopyMemory(buffer, buf, write);
        ExFreePool(buf);
    }
    return;
}
//free mem map
void CallFunctionFreeMap() {
    PHYMEM_MEM mem;
    __asm {
        push eax
        mov eax, [edx + 4]
        mov mem.size, eax
        mov eax, [edx]
        mov mem.addr, eax
        pop eax
    }
    DbgPrint("F");
    //DbgPrint("INFO CALL 0x76 : SIZE:%X PHYS:%X\n", mem.size, mem.addr);
    MapPhyMemFree(&mem);
    return;
}

__declspec(naked) void FreeMapHandler() { //0x75
    __asm {
        pushad
        pushfd

        //sti
        call CallFunctionFreeMap
        //cli
    }
    //DbgPrint("Free map handler execute\n");
    __asm {
        popfd
        popad
        iretd
    }
}
//read mem map
void CallFunctionRead() {
    PHYMEM_MEM mem;
    PVOID map = NULL;
    PVOID outMap;
    //PPHYSICAL_MEMORY_RANGE range;
    __asm {
        push eax
        mov eax, [edx + 8]
        mov mem.size, eax
        mov eax, [edx + 4]
        mov mem.addr, eax
        mov eax, [edx]
        mov outMap, eax
        pop eax
    }
    DbgPrint("R");
    //range = MmGetPhysicalMemoryRanges();
    //DbgPrint("INFO CALL 0x76 : PVOID:%X SIZE:%X PHYS:%X\n", map, mem.size, mem.addr);
    //DbgPrint("RANGE:%X~%X\n", range->BaseAddress.QuadPart, range->NumberOfBytes.QuadPart);
    MapPhyMem(&mem, &map, UserMode, MmNonCached);
    RtlCopyMemory(outMap, &map, sizeof(PVOID));

    return;
}

__declspec(naked) void ReadMemHandler() { //0x76
    __asm {
        pushad
        pushfd
        
        //sti
        call CallFunctionRead
        //cli
    }
    //DbgPrint("Read memory handler execute\n");
    __asm {
        popfd
        popad
        iretd
    }
}
//write mem
void CallFunctionWrite() {
    PUCHAR buffer;
    ULONG sz;
    PVOID address;
    __asm {
        push eax
        mov eax, [edx + 8]
        mov sz, eax
        mov eax, [edx + 4]
        mov buffer, eax
        mov eax, [edx]
        mov address, eax
        pop eax
    }
    DbgPrint("W");
    //DbgPrint("INFO CALL 0x77 : BUFFER:%X SIZE:%X PHYS:%X\n", buffer, sz, address);
    WritePhyMem(address, buffer, sz);
    return;
}

__declspec(naked) void WriteMemHandler() { //0x77
    __asm {
        pushad
        pushfd

        call CallFunctionWrite
    }
    //DbgPrint("Write memory handler execute\n");
    __asm {
        popfd
        popad
        iretd
    }
}
//test int
__declspec(naked) void TrapGateHandler() { // ioctl 0x65

    __asm {
        //int 3
        pushad
        pushfd
    }
    DbgPrint("TrapGateHandler execute\n");
    __asm {
        popfd
        popad
        iretd
    }
}
//hook int
__declspec(naked) void CallGateHook() {

    //__asm {int 3}

    __asm {
        pushad
        push eax // code
        call CallHookInt
    }

    DbgPrint("CallGateHook execute\n");
    __asm {
        popad
        retf
    }

}

__declspec(naked) void CallGateInfo() {

    //__asm {int 3}

    __asm {
        pushad
        push eax // buffer
        call CallInfoInt
    }

    DbgPrint("CallGateInfo execute\n");
    __asm {
        popad
        retf
    }

}
//********************************************************************** HANDLERS

// �������� ������� ��������� ���� ioctl-��������
NTSTATUS DispatchControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP pIrp) {

NTSTATUS status = STATUS_SUCCESS;
PIO_STACK_LOCATION IrpStack;
ULONG	Info = 0;
ULONG   inlen;          // ������ �������� ������
ULONG   outlen;         // ������ ��������� ������
ULONG   len;
unsigned char* in;      // ������� �����
unsigned char* out;     // �������� �����
ULONG   ioctl;          // ioctl-���
PCHAR buf;              // ��������������� �����
ULONG   i, j, count;    // ������� �����
UNICODE_STRING bufferUnicode;
ULONG indexIdt = 0;
ULONG value = 0x100;
PLIST_ENTRY pLink;

    IrpStack = IoGetCurrentIrpStackLocation(pIrp);

    DbgPrint("DeviceIOCTL:\n");
    DbgPrint("ioctl - %X\n", IrpStack->Parameters.DeviceIoControl.IoControlCode);
    DbgPrint("Input length - %d\n", IrpStack->Parameters.DeviceIoControl.InputBufferLength);
    DbgPrint("Output length - %d\n", IrpStack->Parameters.DeviceIoControl.OutputBufferLength);
    DbgPrint("System buffer - %p\n", pIrp->AssociatedIrp.SystemBuffer);
    DbgPrint("Type3InputBuffer - %p\n", IrpStack->Parameters.DeviceIoControl.Type3InputBuffer);
    DbgPrint("User buffer - %p\n\n", pIrp->UserBuffer);

    // �������� ioctl-���
    ioctl = IrpStack->Parameters.DeviceIoControl.IoControlCode;

    // ������ �������� ������
    inlen = IrpStack->Parameters.DeviceIoControl.InputBufferLength;

    // ������ ��������� ������
    outlen = IrpStack->Parameters.DeviceIoControl.OutputBufferLength;

    // ��������� ��� �����/������, ��������������� � ioctl-�����
    if ((ioctl & 0x00000003) == METHOD_BUFFERED) {
        // ���� ��������������
        // �� ��������� ����� �������� � ������� � ��������
        out = in = pIrp->AssociatedIrp.SystemBuffer;
    }
    else {
        // ����� �������� ��������� �� ��������������� ����� IPR
        in = IrpStack->Parameters.DeviceIoControl.Type3InputBuffer;
        out = pIrp->UserBuffer;
    }

    switch (ioctl) {
        case START_HOOKING_SYSENTER:
            DbgPrint("STARTING HOOKING SYSENTER\n");
            HookSysenter((ULONG)HandlerSysenter, &glRealAddressSysenter);
            DbgPrint("Handler sysenter\told=%p  new=%p\n", glRealAddressSysenter, HandlerSysenter);
            RtlCopyMemory(out, "OK", strlen("OK"));
            break;

        case STOP_HOOKING_SYSENTER:
            DbgPrint("STOPING HOOKING SYSENTER\n");
            HookSysenter(glRealAddressSysenter, &i);
            RtlCopyMemory(out, "OK", strlen("OK"));
            break;

        default:
            status = STATUS_INVALID_PARAMETER;
            break;
    }

    return CompleteIrp(pIrp, status, Info);
}


NTSTATUS DispatchRead(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp) {

NTSTATUS status = STATUS_SUCCESS;
ULONG info = 0;
PIO_STACK_LOCATION pIrpStack;
PULONG pReadLength;
PUNICODE_STRING pFileName;
UNICODE_STRING fileNameInfo;
PWCHAR pStr;
PCHAR outputBuffer;
ULONG value;
ULONG i;
PLIST_ENTRY link;
//PULONG pReadLength;
//PLARGE_INTEGER pByteOffset;
    
    DbgPrint("\nCallRead\n");
    pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
    pReadLength = &pIrpStack->Parameters.Read.Length;
    //pByteOffset = (int*)&pIrpStack->Parameters.Read.ByteOffset;
    pFileName = &pIrpStack->FileObject->FileName;

    if (pDeviceObject->Flags & DO_BUFFERED_IO) {
        outputBuffer = (PCHAR)pIrp->AssociatedIrp.SystemBuffer;
    }
    else {
        outputBuffer = (PCHAR)pIrp->UserBuffer;
    }

    fileNameInfo.Length = sizeof(INFO_STRING) + 2;
    fileNameInfo.MaximumLength = fileNameInfo.Length;
    pStr = (PWCH)ExAllocatePoolWithTag(PagedPool, fileNameInfo.Length, 'oneN');
    if (!pStr) {
        return CompleteIrp(pIrp, STATUS_MEMORY_NOT_ALLOCATED, 0);
    }
    fileNameInfo.Buffer = pStr;


    RtlInitUnicodeString(&fileNameInfo, INFO_STRING);
    if (!RtlCompareUnicodeString(pFileName, &fileNameInfo, TRUE)) { //INFO_STRING == L"\\info"
        DbgPrint("%wZ\n", pFileName);
        for (i = 0; i < 0x100; ++i) {
            if (context[i].found) {
                info += sprintf(outputBuffer + info, "Count: %d\n", context[i].count);
                link = &context[i].link;
                do {
                    PIDT_CONTEXT entry = CONTAINING_RECORD(&context[i].link, IDT_CONTEXT, link);
                    info += sprintf(outputBuffer + info, "Eax:0x%X Ebx:0x%X Ecx:0x%X Edx:0x%X\n",
                        entry->regs.Eax, entry->regs.Ebx, entry->regs.Ecx, entry->regs.Edx);
                    link = link->Flink;
                } while (link != &context[i].link);
            }
        }
    }
    else {
        status = STATUS_FILE_INVALID;
    }
    
    ExFreePool(pStr);

    return CompleteIrp(pIrp, status, info);
}

NTSTATUS DispatchWrite(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp) {

NTSTATUS status = STATUS_SUCCESS;
ULONG info = 0;
PIO_STACK_LOCATION pIrpStack;
PUNICODE_STRING pFileName;
UNICODE_STRING fileNameHook;
PWCHAR pStr;
PCHAR inputBuffer;
ULONG value;

    DbgPrint("\nCallWrite\n");
    pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
    pFileName = &pIrpStack->FileObject->FileName;

    if (pDeviceObject->Flags & DO_BUFFERED_IO) {
        inputBuffer = (PCHAR)pIrp->AssociatedIrp.SystemBuffer;
    }
    else {
        inputBuffer = (PCHAR)pIrp->UserBuffer;
    }
    
    fileNameHook.Length = sizeof(HOOK_STRING) + 2;
    fileNameHook.MaximumLength = fileNameHook.Length;
    pStr = (PWCH)ExAllocatePoolWithTag(PagedPool, fileNameHook.Length, 'oneN');
    if (!pStr) {
        return CompleteIrp(pIrp, STATUS_MEMORY_NOT_ALLOCATED, 0);
    }
    fileNameHook.Buffer = pStr;
    
    
    RtlInitUnicodeString(&fileNameHook, HOOK_STRING);
    if (!RtlCompareUnicodeString(pFileName, &fileNameHook, TRUE)) { //HOOK_STRING == L"\\hook"
        
        //DbgPrint("%s\n", inputBuffer);
        //DbgPrint("%wZ\n", pFileName);
        status = RtlCharToInteger(inputBuffer, (ULONG)NULL, &value);
        if (!NT_SUCCESS(status) && value != 0) {
            status = STATUS_INVALID_PARAMETER;
        }
        else {
            DbgPrint("Code Interrupt: 0x%X\n", value);
            HookInterrupt(value);
            info = 2;
        }
    }
    else {
        status = STATUS_FILE_INVALID;
    }

    ExFreePool(pStr);

    return CompleteIrp(pIrp, status, info);
}

VOID InsertCallGate(ULONG index, PVOID handler) {

    GDTR gdtr;
    DescriptorGate* gdt;
    ULONG gateCount;
    DescriptorGate* newGate;

    //DbgBreakPoint();
    __asm {sgdt gdtr}

    gdt = (DescriptorGate*)gdtr.Base;
    gateCount = (gdtr.Limit + 1) / sizeof(DescriptorGate);

    newGate = gdt + index;
    newGate->DestinationSelector = 8;
    newGate->DestinationOffsetLow = (ULONG)handler & 0xFFFF;
    newGate->DestinationOffsetHigh = (ULONG)handler >> 16;
    newGate->Type = TYPE_CALLGATE_386;
    newGate->WordCount = 0;
    newGate->SystemOrUser = 0;
    newGate->DPL = 3;
    newGate->P = 1;

    DbgPrint("GDT (%08X) contains %d gates\n", gdt, gateCount);

    return;
}

//������� ���������� ����� ������� � ������� IDT
VOID InsertTrapGate(ULONG index, PVOID handler) {

    IDTR idtr;
    DescriptorGate* idt;
    ULONG gateCount;
    DescriptorGate* newGate;

    __asm {sidt idtr}

    idt = (DescriptorGate*)idtr.Base;
    gateCount = idtr.Limit / sizeof(DescriptorGate);

    newGate = idt + index;
    newGate->DestinationSelector = 8; //0000000000001000 = 0000000000001 0 00
    newGate->DestinationOffsetLow = (ULONG)handler & 0xFFFF;
    newGate->DestinationOffsetHigh = (ULONG)handler >> 16;
    newGate->Type = TYPE_TRAPGATE_386;
    newGate->SystemOrUser = 0;
    newGate->DPL = 3;
    newGate->P = 1;

    DbgPrint("IDT (%08X) �������� %d ������\n", idt, gateCount);

    return;
}
//--------------------


//
// ��������� ������� ��������� ������� ��� ���������� ����� ��������� �������.
// ��� ����� ���������� ������ ������� ������� ��� ������� ������� ��������� �������
// � ������� ���������� ���������� ��������� �������.
//
// ���������:
// table                ������� ��������� �������
// extra                ���������� ������� ��� ������� ������������� ����� �������� ������
//
BOOLEAN ChangeSyscallTable(
    PKSERVICE_TABLE_DESCRIPTOR table,
    ULONG extra) {

    ULONG new_size_base;            // ������ ������ ������� ������� �������
    ULONG old_size_base;            // ������ ������� ������� ������� �������
    ULONG new_size_param;           // ������ ������ ������� ���������� ����������
    ULONG old_size_param;           // ������ ������� ������� ���������� ����������
    PULONG_PTR new_base_syscall;    // ��������� �� ����� ������ ������� �������
    PUCHAR new_param_syscall;       // ��������� �� ����� ������ ���������� ����������


        // ���������� �������� ��������
    old_size_base = table->Limit * sizeof(ULONG_PTR);

    new_size_base = (table->Limit + extra) * sizeof(ULONG_PTR);

    old_size_param = table->Limit * sizeof(UCHAR);

    new_size_param = (table->Limit + extra) * sizeof(UCHAR);


    // ��������� ������ ��� ����� �������� � ������������ ������
    new_base_syscall = (PULONG_PTR)ExAllocatePoolWithTag(NonPagedPool, new_size_base, 'oneN');
    if (!new_base_syscall)
        return FALSE;

    new_param_syscall = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, new_size_param, 'oneN');
    if (!new_param_syscall) {
        ExFreePool(new_base_syscall);
        return FALSE;
    }

    // �������� ������ ������� � �����
    RtlCopyMemory(new_base_syscall, table->Base, old_size_base);

    RtlCopyMemory(new_param_syscall, table->Number, old_size_param);

    // ��������� ����� ������� ��������� �������
    table->Base = new_base_syscall;

    table->Number = new_param_syscall;

    table->Limit += extra;

    return TRUE;
}


//--------------------


//
// �������� ��������� � ������� ��������� �������.
// ��������� ������ �������� � ������� ��������� �������
// � ����������� ������, ���������� ��� ����� �������.
//
// ���������:
// table        ������� ��������� �������
// old_base     ��������� �� ������ ������ �������
// old_param    ��������� �� ������ ������ ����������
// limit        ������ ���������� ��������� �������
//
void RollbackChangeSyscallTable(
    PKSERVICE_TABLE_DESCRIPTOR table,
    PULONG_PTR old_base,
    PUCHAR old_param,
    ULONG limit) {

    PULONG_PTR tmp_base;
    PUCHAR	tmp_param;

    tmp_base = table->Base;

    tmp_param = table->Number;

    // �������������� ������ ��������
    table->Base = old_base;

    table->Number = old_param;

    table->Limit = limit;

    // ������������ ������, ���������� ��� ����� �������
    ExFreePool(tmp_base);

    ExFreePool(tmp_param);

    return;
}

void CreateOverIndexGDT(ULONG index) {

    GDTR gdtr;
    DescriptorGate* gdt;
    ULONG gateCount;
    DescriptorGate* newGate;

    //DbgBreakPoint();
    __asm {sgdt gdtr}

    gdt = (DescriptorGate*)gdtr.Base;
    gateCount = (gdtr.Limit + 1) / sizeof(DescriptorGate);



    return;
}

ULONG ClearWP(void) {

    ULONG reg;

    __asm {
        mov eax, cr0
        mov[reg], eax
        and eax, 0xFFFEFFFF
        mov cr0, eax
    }

    return reg;
}


void WriteCR0(ULONG reg) {

    __asm {
        mov eax, [reg]
        mov cr0, eax
    }

}


BOOLEAN HookSyscall(
    PKSERVICE_TABLE_DESCRIPTOR table,
    PVOID addressHooker,
    ULONG index,
    UCHAR param,
    PKSERVICE_TABLE_DESCRIPTOR backup) {


    backup->Limit = table->Limit;
    backup->Base = table->Base;
    backup->Number = table->Number;
    if (index > backup->Limit + 1) {
        if (!ChangeSyscallTable(table, index - backup->Limit + 1)) {
            DbgPrint("Error change table syscall");
            return STATUS_UNSUCCESSFUL;
        }
    }
    table->Base[index] = (ULONG_PTR)addressHooker;
    table->Number[index] = param;


    return STATUS_SUCCESS;
}

void PrintSSDT(PKSERVICE_TABLE_DESCRIPTOR table, PCHAR str) {

ULONG i;

    for (i = 0; i < 4; ++i) {
        DbgPrint("%s[%d]\t\tBase:0x%X\tLimit:0x%X\tNumber:0x%X\n",
            str, i, table[i].Base, table[i].Limit, table[i].Number);
    }

    return;
}

ULONG_PTR __stdcall HookNtUserSetInformationProcess(
    ULONG_PTR	arg_01,
    ULONG_PTR	arg_02,
    ULONG_PTR	arg_03,
    ULONG_PTR	arg_04
) {
ULONG_PTR ret;

    DbgPrint("OOOOOOOOOOOOOONIME\n");
    ret = glRealNtUserSetInformationProcess(arg_01, arg_02, arg_03, arg_04);


    return ret;
}