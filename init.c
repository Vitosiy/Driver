#include "init.h"

// функция инициализации драйвера
NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath) {

NTSTATUS status = STATUS_SUCCESS;
PDEVICE_OBJECT  DeviceObject;
//PVOID ModuleAddress;
//ULONG uImageBase;
ULONG reg;
ULONG i;
    
    //Interface: 1
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

    // создание устройства
    status = IoCreateDevice(DriverObject,	// указатель на объект драйвера
                            0,				// размер области дополнительной памяти устройства
                            &DevName,		// имя устройства
                    FILE_DEVICE_UNKNOWN,	// идентификатор типа устройства
                            0,				// дополнительная информация об устройстве
                            FALSE,			// без эксклюзивного доступа
                            &DeviceObject); // адрес для сохранения указателя на объект устройства
    if (!NT_SUCCESS(status))
        return status;

#if DBG
    DbgPrint("Create device %ws\n", DEVICE_NAME);
#endif

    // создание символьной ссылки
    status = IoCreateSymbolicLink(&SymLinkName, &DevName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(DeviceObject);
        return status;
    }
    KeServiceDescriptorTableShadow = (PKSERVICE_TABLE_DESCRIPTOR)((ULONG)KeServiceDescriptorTable - 0x40);
    //****************************dump gdt, idt     Interface: 3

    PrintSSDT(KeServiceDescriptorTable, "KeServiceDescriptorTable");
    PrintSSDT(KeServiceDescriptorTableShadow, "KeServiceDescriptorTableShadow");

    __asm int 3;

    InsertTrapGate(0x75, DumpInitHandler);

    //****************************hook idt counter      Interface: 4
  
    // for syscall 0x2021
    HookSyscall(&KeServiceDescriptorTable[2], CallHookInt, 0x21, sizeof(PCHAR) + sizeof(ULONG), &backupTable[2]);
    HookSyscall(&KeServiceDescriptorTableShadow[2], CallHookInt, 0x21, sizeof(PCHAR) + sizeof(ULONG), &backupTableShadow[2]);
    
    // for syscall 0x3009
    HookSyscall(&KeServiceDescriptorTable[3], CallInfoInt, 0x9, sizeof(PCHAR) + sizeof(ULONG), &backupTable[3]);
    HookSyscall(&KeServiceDescriptorTableShadow[3], CallInfoInt, 0x9, sizeof(PCHAR) + sizeof(ULONG), &backupTableShadow[3]);
    
    //****************************hook idt registry context     Interface: 5

    InitializateContextList();
    InsertCallGate(126, CallGateHook); //hook
    InsertCallGate(127, CallGateInfo); //info

    //****************************init hook sysenter        Interface: 0

    InitHookSysenter();

    //****************************init w/r mem      Interface: 1

    InitWRMem();

    //****************************init syscalls for i/o     Interface: 2
     
    // for syscall 0x3f
    InsertTrapGate(0x3f, ReadMemHandler);

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

    Irp->IoStatus.Status = status;		// статус завершении операции
    Irp->IoStatus.Information = Info;	// количество возращаемой информации
    IoCompleteRequest(Irp, IO_NO_INCREMENT);	// завершение операции ввода-вывода
    return status;
}

NTSTATUS DispatchClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP pIrp) {

    return CompleteIrp(pIrp, STATUS_SUCCESS, 0);
}

NTSTATUS DispatchCreate(IN PDEVICE_OBJECT DeviceObject, IN PIRP pIrp) {

    return CompleteIrp(pIrp, STATUS_SUCCESS, 0); // Завершение IRP
}

VOID DriverUnload(IN PDRIVER_OBJECT DriverObject) {

ULONG reg;

    RollbackChangeSyscallTable(KeServiceDescriptorTable, backupTable->Base, backupTable->Number, backupTable->Limit);
    if (dump_initialized) {
        RollbackChangeSyscallTable(&KeServiceDescriptorTable[0], backupTable[0].Base, backupTable[0].Number, backupTable[0].Limit);
        //RollbackChangeSyscallTable(&KeServiceDescriptorTable[1], backupTable[1].Base, backupTable[1].Number, backupTable[1].Limit);
    }
    RollbackChangeSyscallTable(&KeServiceDescriptorTable[2], backupTable[2].Base, backupTable[2].Number, backupTable[2].Limit);
    RollbackChangeSyscallTable(&KeServiceDescriptorTable[3], backupTable[3].Base, backupTable[3].Number, backupTable[3].Limit);

    RollbackChangeSyscallTable(KeServiceDescriptorTableShadow, backupTableShadow->Base, backupTableShadow->Number, backupTableShadow->Limit);
    if (dump_initialized) {
        RollbackChangeSyscallTable(&KeServiceDescriptorTableShadow[0], backupTableShadow[0].Base, backupTableShadow[0].Number, backupTableShadow[0].Limit);
        //RollbackChangeSyscallTable(&KeServiceDescriptorTableShadow[1], backupTableShadow[1].Base, backupTableShadow[1].Number, backupTableShadow[1].Limit);
        KeServiceDescriptorTableShadow[1].Base[0x11df] = (ULONG)glRealNtUserQueryInformationThread;
    }
    RollbackChangeSyscallTable(&KeServiceDescriptorTableShadow[2], backupTableShadow[2].Base, backupTableShadow[2].Number, backupTableShadow[2].Limit);
    RollbackChangeSyscallTable(&KeServiceDescriptorTableShadow[3], backupTableShadow[3].Base, backupTableShadow[3].Number, backupTableShadow[3].Limit);

    dump_initialized = FALSE;
    //reg = ClearWP();
    //KeServiceDescriptorTableShadow[1].Base[0x207] = (ULONG)glRealNtUserSetInformationProcess;
    //WriteCR0(reg);

    FreeContextList();
    FreeHookSysenterEaxs();
    FreeWRMem();

    // удаление символьной ссылки и объекта устройства
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
//Вызов инициализации dump gdt и idt
void CallFunctionDumpInit() {
    // for syscall 0x0215
    HookSyscall(&KeServiceDescriptorTable[0], DumpGdtSysCall, 0x215, sizeof(PCHAR) + sizeof(ULONG), &backupTable[0]);
    HookSyscall(&KeServiceDescriptorTableShadow[0], DumpGdtSysCall, 0x215, sizeof(PCHAR) + sizeof(ULONG), &backupTableShadow[0]);

    // for syscall 0x11df
    glRealNtUserQueryInformationThread = (NT_USER_QUERY_INFORMATION_THREAD)KeServiceDescriptorTableShadow[1].Base[0x1df];
    KeServiceDescriptorTableShadow[1].Base[0x1df] = (ULONG)HookNtQuerySystemInformation;
    //HookSyscall(&KeServiceDescriptorTableShadow[1], DumpIdtSysCall, 0x29B, sizeof(PCHAR) + sizeof(ULONG), &backupTableShadow[1]);
    dump_initialized = TRUE;
    return;
}

__declspec(naked) void DumpInitHandler() { //0x75
    __asm {
        pushad
        pushfd

        //sti
        call CallFunctionDumpInit
        //cli
    }
    //DbgPrint("Free map handler execute\n");
    __asm {
        popfd
        popad
        iretd
    }
}


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

//read mem map
void CallFunctionRead() {
    PUCHAR buffer;
    ULONG sz;
    PULONG address;
    int max_address = 0;
    int i = 0;
    __asm {
        push eax
        mov eax, [edx + 8]
        mov sz, eax
        mov eax, [edx + 4]
        mov buffer, eax
        mov eax, [edx]
        mov address, eax
        pop eax
    };
    DbgPrint("R");
    //range = MmGetPhysicalMemoryRanges();
    //DbgPrint("INFO CALL 0x76 : PVOID:%X SIZE:%X PHYS:%X\n", map, mem.size, mem.addr);
    //DbgPrint("RANGE:%X~%X\n", range->BaseAddress.QuadPart, range->NumberOfBytes.QuadPart);
    max_address = address + sz;
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
            in al, dx
            mov byte ptr[ebx], al

            pop edx
            pop ebx
            pop eax
        }
    }

    return;
}

__declspec(naked) void ReadMemHandler() { //0x3f
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

// основная функция обработки всех ioctl-запросов
NTSTATUS DispatchControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP pIrp) {

NTSTATUS status = STATUS_SUCCESS;
PIO_STACK_LOCATION IrpStack;
ULONG	Info = 0;
ULONG   inlen;          // размер входного буфера
ULONG   outlen;         // размер выходного буфера
ULONG   len;
unsigned char* in;      // входной буфер
unsigned char* out;     // выходной буфер
ULONG   ioctl;          // ioctl-код
PCHAR buf;              // вспомогательный буфер
ULONG   i, j, count;    // счётчик цикла
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

    // получаем ioctl-код
    ioctl = IrpStack->Parameters.DeviceIoControl.IoControlCode;

    // размер входного буфера
    inlen = IrpStack->Parameters.DeviceIoControl.InputBufferLength;

    // размер выходного буфера
    outlen = IrpStack->Parameters.DeviceIoControl.OutputBufferLength;

    // проверяем тип ввода/вывода, ассоциированный с ioctl-кодом
    if ((ioctl & 0x00000003) == METHOD_BUFFERED) {
        // если буферизованный
        // то системный буфер является и входным и выходным
        out = in = pIrp->AssociatedIrp.SystemBuffer;
    }
    else {
        // иначе получаем указатели из соответствующих полей IPR
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

        case SYSCALL_CNT_INFO_IOCTL:
            Info += sprintf(out + Info, "Current coutner value: %d\n", glNumberSysServices);
            //DbgPrint("Current coutner value: %d\n", glNumberSysServices);
            Info += sprintf(out + Info, "Last: %d\n", glLastSC);
            //DbgPrint("Last: %d\n", glLastSC);
            for (i = 0; i < glNumberSysServices; ++i) {
                Info += sprintf(out + Info, "%d: %u\n", i, glSyscallEaxs[i]);
                //DbgPrint("%d: %u\n", i, glSyscallEaxs[i]);
            }
            break;

        case SYSCALL_ALL_INFO_IOCTL:
            DbgPrint("SYSCALL_ALL_INFO_IOCTL\n");
            DbgPrint("%s\n", in);
            status = RtlCharToInteger(in, (ULONG)NULL, &value);
            if (!NT_SUCCESS(status)) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
            else if (value) {
                for (i = 0; i < glNumberSysServices; ++i) {
                    count = 0;
                    if (pContextSyscalls[i].b) {
                        for (pLink = pContextSyscalls[i].link.Flink; pLink != &pContextSyscalls[i].link && count < value; pLink = pLink->Flink) {
                            PCONTEXT_SYSCALL entry = CONTAINING_RECORD(pLink, CONTEXT_SYSCALL, link);
                            Info += sprintf(out + Info, "Index:%d", entry->index);
                            if (pContextSyscalls[i].argBuffer.size) {
                                Info += sprintf(out + Info, " Args:\t");
                                for (j = 0; j < entry->argBuffer.size / sizeof(ULONG); ++j) {
                                    Info += sprintf(out + Info, "[%d]:0x%X ", j, entry->argBuffer.buffer[j]);
                                }
                            }
                            Info += sprintf(out + Info, "\tStack:0x%X\n", (ULONG)entry->userStack);
                            pLink = pLink->Flink;
                            count++;
                        }
                    }
                }
            }
            break;

        case SYSCALL_IND_INFO_IOCTL:
            DbgPrint("SYSCALL_IND_INFO_IOCTL\n");
            status = RtlCharToInteger(in, (ULONG)NULL, &value);

            DbgPrint("%s %d\n", in, value);
            if (!NT_SUCCESS(status) || value > glNumberSysServices) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
            else if (pContextSyscalls[value].b) {
                PCONTEXT_SYSCALL entry = CONTAINING_RECORD(&pContextSyscalls[value].link, CONTEXT_SYSCALL, link);
                Info += sprintf(out + Info, "Index:%d~0x%X\t", entry->index, entry->index);
                DbgPrint("Index:%d~0x%X", entry->index, entry->index);
                if (entry->argBuffer.size) {
                    Info += sprintf(out + Info, "\tArgs: ");
                    DbgPrint("\tArgs: ");
                    for (j = 0; j < entry->argBuffer.size / sizeof(ULONG); ++j) {
                        Info += sprintf(out + Info, "[%d]:0x%X ", j, entry->argBuffer.buffer[j]);
                        DbgPrint("[%d]:0x%X ", j, entry->argBuffer.buffer[j]);
                    }
                }
                Info += sprintf(out + Info, "\tStack:0x%X\n", (ULONG)entry->userStack);
            }
            else {
                Info = sprintf(out, "Empty syscall context\n");
            }
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
        PVOID pvk;
        ULONG i = 0;

        pvk = MmMapIoSpace(save_cmd.address, save_cmd.size, MmNonCached);

        if (pvk && (*pReadLength >= save_cmd.size)) {
            for (; i < save_cmd.size; i++) {
                info += sprintf(outputBuffer + info, "%02X", (UCHAR)*((PUCHAR)pvk+i));
            }
            //RtlCopyMemory(outputBuffer, pvk, save_cmd.size);
        }
        MmUnmapIoSpace(pvk, save_cmd.size);
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
UNICODE_STRING fileNameHook1;
UNICODE_STRING fileNameHook2;
PWCHAR pStr;
PCHAR inputBuffer;
ULONG value;

    DbgPrint("\nCallRead&Write\n");
    pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
    pFileName = &pIrpStack->FileObject->FileName;

    if (pDeviceObject->Flags & DO_BUFFERED_IO) {
        inputBuffer = (PCHAR)pIrp->AssociatedIrp.SystemBuffer;
    }
    else {
        inputBuffer = (PCHAR)pIrp->UserBuffer;
    }
    
    fileNameHook1.Length = sizeof(WRITE_STRING) + 2;
    fileNameHook1.MaximumLength = fileNameHook1.Length;
    pStr = (PWCH)ExAllocatePoolWithTag(PagedPool, fileNameHook1.Length, 'oneN');
    if (!pStr) {
        return CompleteIrp(pIrp, STATUS_MEMORY_NOT_ALLOCATED, 0);
    }
    fileNameHook1.Buffer = pStr;

    fileNameHook2.Length = sizeof(READ_STRING) + 2;
    fileNameHook2.MaximumLength = fileNameHook2.Length;
    pStr = (PWCH)ExAllocatePoolWithTag(PagedPool, fileNameHook2.Length, 'oneN');
    if (!pStr) {
        return CompleteIrp(pIrp, STATUS_MEMORY_NOT_ALLOCATED, 0);
    }
    fileNameHook2.Buffer = pStr;
    
    
    RtlInitUnicodeString(&fileNameHook1, WRITE_STRING);
    RtlInitUnicodeString(&fileNameHook2, READ_STRING);

    if (!RtlCompareUnicodeString(pFileName, &fileNameHook1, TRUE)) { //HOOK_STRING == L"\\write"
        ULONG address;
        PUCHAR buffer;
        ULONG sz = 0;
        unsigned int i = 0;

        DbgPrint("%s\n", inputBuffer);

        for (; inputBuffer[i] != '\0'; i++) {
            if (inputBuffer[i] == ' ') {
                inputBuffer[i] = "\0";
                buffer = inputBuffer + i + 1;
                break;
            }
        }

        RtlCharToInteger(inputBuffer, (ULONG)NULL, &address);

        i = 0;
        for (; buffer[i] != '\0'; i++) {
            sz++;
        }

        DbgPrint("W");
        WritePhyMem((PVOID)address, buffer, sz);
        info = sz;
    }
    else if (!RtlCompareUnicodeString(pFileName, &fileNameHook2, TRUE)) { //HOOK_STRING == L"\\read"
        ULONG address;
        PUCHAR adr_sz;
        ULONG sz;
        unsigned int i = 0;

        DbgPrint("%s\n", inputBuffer);

        for (; inputBuffer[i] != '\0'; i++) {
            if (inputBuffer[i] == ' ') {
                inputBuffer[i] = "\0";
                adr_sz = inputBuffer + i + 1;
                break;
            }
        }

        RtlCharToInteger(inputBuffer, (ULONG)NULL, &address);
        RtlCharToInteger(adr_sz, (ULONG)NULL, &sz);
        
        save_cmd.address.QuadPart = (ULONGLONG)address;
        save_cmd.size = sz;

        info = sz;
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

//Функция добавления шлюза ловушки в таблицу IDT
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

    DbgPrint("IDT (%08X) содержит %d шлюзов\n", idt, gateCount);

    return;
}
//--------------------


//
// Изменение таблицы системных вызовов для добавления новых системных вызовов.
// Для этого выделяются буферы нужного размера для массива адресов системных вызовов
// и массива количества параметров системных вызовов.
//
// Аргументы:
// table                таблица системных вызовов
// extra                количество вызовов для которых дополнительно нужно выделить память
//
BOOLEAN ChangeSyscallTable(
    PKSERVICE_TABLE_DESCRIPTOR table,
    ULONG extra) {

    ULONG new_size_base;            // размер нового массива адресов вызовов
    ULONG old_size_base;            // размер старого массива адресов вызовов
    ULONG new_size_param;           // размер нового массива количества параметров
    ULONG old_size_param;           // размер старого массива каличества параметров
    PULONG_PTR new_base_syscall;    // указатель на новый массив адресов вызовов
    PUCHAR new_param_syscall;       // указатель на новый массив количества параметров


        // вычисление размеров массивов
    old_size_base = table->Limit * sizeof(ULONG_PTR);

    new_size_base = (table->Limit + extra) * sizeof(ULONG_PTR);

    old_size_param = table->Limit * sizeof(UCHAR);

    new_size_param = (table->Limit + extra) * sizeof(UCHAR);


    // выделение памяти для новых массивов в нестраничной памяти
    new_base_syscall = (PULONG_PTR)ExAllocatePoolWithTag(NonPagedPool, new_size_base, 'oneN');
    if (!new_base_syscall)
        return FALSE;

    new_param_syscall = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, new_size_param, 'oneN');
    if (!new_param_syscall) {
        ExFreePool(new_base_syscall);
        return FALSE;
    }

    // копируем старые массивы в новые
    RtlCopyMemory(new_base_syscall, table->Base, old_size_base);

    RtlCopyMemory(new_param_syscall, table->Number, old_size_param);

    // изменение полей таблицы системных вызовов
    table->Base = new_base_syscall;

    table->Number = new_param_syscall;

    table->Limit += extra;

    return TRUE;
}


//--------------------


//
// Отменяет изменения в таблице системных вызовов.
// Сохраняет старые значения в таблице системных вызовов
// и освобождает память, выделенную для новых буферов.
//
// Аргументы:
// table        таблица системных вызовов
// old_base     указатель на старый массив адресов
// old_param    указатель на старый массив параметров
// limit        старое количество системных вызовов
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

    // восстановление старых значений
    table->Base = old_base;

    table->Number = old_param;

    table->Limit = limit;

    // освобождение памяти, выделенной для новых буферов
    if (tmp_base)
        ExFreePool(tmp_base);
    if(tmp_param)
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

NTSTATUS HookNtQuerySystemInformation(
    IN            HANDLE          ThreadHandle,
    IN            THREADINFOCLASS ThreadInformationClass,
    IN OUT        PVOID           ThreadInformation,
    IN            ULONG           ThreadInformationLength,
    OUT OPTIONAL  PULONG          ReturnLength)
{
    NTSTATUS retStatus = STATUS_SUCCESS;

    if ((ULONG)ThreadHandle == (ULONG)SYSCALL_SIGNATURE) {
        DumpIdtSysCall((PCHAR)ThreadInformationClass, (ULONG)ThreadInformation);
    }
    else {
        retStatus = glRealNtUserQueryInformationThread(
            ThreadHandle,
            ThreadInformationClass,
            ThreadInformation,
            ThreadInformationLength,
            ReturnLength
        );
    }

    return retStatus;
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