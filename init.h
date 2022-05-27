#pragma once
#include <ntddk.h>
#include <stdio.h>
#include "intel.h"
#include "ioctl.h"
#include "hookidt.h"
#include "dump.h"
#include "hooksysenter.h"
#include "wrmem.h"
#include "command.h"
#include "pt.h"

#define	SYM_LINK_NAME   L"\\Global??\\Driver"
#define DEVICE_NAME     L"\\Device\\DDriver"

#define WRITE_STRING     L"\\write"
#define READ_STRING     L"\\read"

#define INFO_STRING     L"\\info"

#define SYSCALL_SIGNATURE 0x00ABBA00


UNICODE_STRING  DevName;
UNICODE_STRING	SymLinkName;

//*************************************************************
// предварительное объ€вление функций


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

void DumpInitHandler();
void ReadMemHandler();

BOOLEAN HookSyscall(PKSERVICE_TABLE_DESCRIPTOR table, PVOID addressHooker, ULONG index, UCHAR param, PKSERVICE_TABLE_DESCRIPTOR backup);
BOOLEAN ChangeSyscallTable(PKSERVICE_TABLE_DESCRIPTOR table, ULONG extra);
void InPortSyscall(USHORT port, PCHAR buffer, ULONG sz);
void OutPortSyscall(USHORT port, PCHAR buffer, ULONG sz);
void DumpGdtSysCall(PCHAR buffer, ULONG size);
void DumpIdtSysCall(PCHAR buffer, ULONG size);
void CallHookInt(PCHAR codeChar);
void CallInfoInt(PCHAR buffer);
void RollbackChangeSyscallTable(PKSERVICE_TABLE_DESCRIPTOR table, PULONG_PTR old_base, PUCHAR old_param, ULONG limit);
void CreateOverIndexGDT(ULONG index);
void PrintSSDT(PKSERVICE_TABLE_DESCRIPTOR table, PCHAR str);
ULONG ClearWP(void);
void WriteCR0(ULONG reg);
void test();

typedef NTSTATUS(*NT_USER_QUERY_INFORMATION_THREAD)(
    IN            HANDLE          ThreadHandle,
    IN            THREADINFOCLASS ThreadInformationClass,
    IN OUT        PVOID           ThreadInformation,
    IN            ULONG           ThreadInformationLength,
    OUT OPTIONAL  PULONG          ReturnLength
    );

NTSTATUS HookNtQuerySystemInformation(
    IN            HANDLE          ThreadHandle,
    IN            THREADINFOCLASS ThreadInformationClass,
    IN OUT        PVOID           ThreadInformation,
    IN            ULONG           ThreadInformationLength,
    OUT OPTIONAL  PULONG          ReturnLength
);

NT_USER_QUERY_INFORMATION_THREAD glRealNtUserQueryInformationThread;

typedef ULONG_PTR(*NT_USER_SET_INFORMATION_PROCESS)(
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
// глобальные переменные

KSERVICE_TABLE_DESCRIPTOR backupTable[4];
KSERVICE_TABLE_DESCRIPTOR backupTableShadow[4];
BOOLEAN dump_initialized = FALSE;

typedef struct _READ_COMMAND {
    PHYSICAL_ADDRESS address;
    ULONG size;
} READ_COMMAND, * PREAD_COMMAND;

READ_COMMAND save_cmd;
