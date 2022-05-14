#ifndef _HOOKSYSENTER_H
#define _HOOKSYSENTER_H

#include "intel.h"
#include <ntddk.h>

typedef struct _ARG_BUFFER {
	PULONG buffer;
	ULONG size;
} ARG_BUFFER, *PARG_BUFFER;

typedef struct _CONTEXT_SYSCALL {
	BOOLEAN b;
	struct _ARG_BUFFER argBuffer;
	PULONG userStack;
	ULONG index;
	LIST_ENTRY link;
} CONTEXT_SYSCALL, *PCONTEXT_SYSCALL;

PCONTEXT_SYSCALL pContextSyscalls;
PAGED_LOOKASIDE_LIST pagedContextSyscall;

typedef struct _KSERVICE_TABLE_DESCRIPTOR {
	PULONG_PTR Base;        // ������ ������� ��������� �������(��������)
	PULONG Count;           // ������ ��������� ������� ��������
	ULONG Limit;            // ���������� ������� � �������
	PUCHAR Number;          // ������ ���������� ���������� �������(� ������)
} KSERVICE_TABLE_DESCRIPTOR, * PKSERVICE_TABLE_DESCRIPTOR;

volatile ULONG glNumberOfSysenters;
volatile ULONG* glSyscallEaxs;
volatile ULONG glLastSC;

PTSS	glTss;
ULONG   glCurrentNumberService;     // ����� ���������� �������, ���������� ����� ������� eax
ULONG   glRealAddressSysenter;      // �������� ����� ����������� SYSENTER
ULONG   glThreadStackPointer;       // ���� ���� �������� ������
PULONG  glCurrentUserStack;         // ��������� �� ���������������� ���� ������
ULONG   glOldStackPointer;          // ���� ���� ����� �������� � ����� ����(����� ��� ���� �������)
ULONG   glNumberSysServices;

extern PKSERVICE_TABLE_DESCRIPTOR KeServiceDescriptorTable;
PKSERVICE_TABLE_DESCRIPTOR KeServiceDescriptorTableShadow;

void InitHookSysenter();
void HandlerSysenter();
void HookSysenter(ULONG NewAddress, PULONG OldAddress);
PTSS GetTSS();


void PrintContextSyscalls(); // ? 
void FreeHookSysenterEaxs(); // ?

#endif // !_HOOKSYSENTER_H
