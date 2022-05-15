#include "hookidt.h"

/* ---------PUSHAD-OPERATION
  push eax
  push ecx
  push edx
  push ebx
  push esp
  push ebp
  push esi
  push edi
   ---------PUSHAD-OPERATION */


//В начале лежит индекс, а за ним eax оригинальный, а после оригинальный стэк

__declspec(naked) void InterruptHook() {
	PIDT_CONTEXT currentContext;
	ULONG realAddr;
	ULONG ind;
	__asm {
		cli
		pop eax
		mov ind, eax
		pushad
	}
	//-----CODE-HOOK-----
	realAddr = addrInt[ind];
	__asm sti
	//DbgPrint("Hook execute\n");
	if (!context[ind].found) {
		InitializeListHead(&context[ind].link);
		currentContext = &context[ind];
		currentContext->found++;
	}
	else {
		currentContext = (PIDT_CONTEXT)ExAllocateFromPagedLookasideList(&pagedContext);
		InsertTailList(&context[ind].link, &currentContext->link);

	}
	DbgPrint("HOOOOOK");
	__asm cli
	context[ind].count++;

	__asm {
		popad
		pop eax
		push ebx
		mov ebx, currentContext
		mov [ebx]currentContext.regs.Eax, eax
		mov [ebx]currentContext.regs.Ecx, ecx
		mov [ebx]currentContext.regs.Edx, edx
		pop ebx
		push eax
		mov eax, currentContext
		mov [eax]currentContext.regs.Ebx, ebx
		pop eax
		pushad
	}

	//-----CODE-HOOK-----
	__asm {
		popad
		//popfd
		//pop eax //uncomment if code-hook is empty
		sti
		jmp realAddr
	}
}

//-----------HOOK-----------
void HookInterrupt(DWORD32 ind) {

	IDTR idtr;
	ULONG count;
	PIDT_ENTRY idt;
	PIDT_ENTRY ent;
	ULONG i;
	PVOID fun;

	__asm sidt idtr

	count = (idtr.Limit + 1) / sizeof(IDT_ENTRY);
	idt = (PIDT_ENTRY)(idtr.Base);

	ind &= 0xFF;
	DbgPrint("Modification interrupt 0x%X\n", ind);
	ent = &(idt[ind]);
	if (ent->P) {
		if (!addrInt[ind]) {
			addrInt[ind] = (ent->offsetLow) + (ent->offsetHigh << 16);
			
			//ent->offsetLow = (ULONG)addrFun[ind] & 0xFFFF;
			//ent->offsetHigh = (ULONG)addrFun[ind] >> 16;
			DbgPrint("\tHandler Hook\n");
			DbgPrint("\tOFFSET BEFORE:0x%08X\t", (ent->offsetLow) + (ent->offsetHigh << 16));
			SetOffsetInt(ent, addrFun[ind]);
			DbgPrint("AFTER:0x%08X\n", (ent->offsetLow) + (ent->offsetHigh << 16));
		}
		else {
			
			DbgPrint("\tHandler Return\n");
			DbgPrint("\tOFFSET BEFORE:0x%08X\t", (ent->offsetLow) + (ent->offsetHigh << 16));
			SetOffsetInt(ent, (PVOID)addrInt[ind]);
			DbgPrint("AFTER:0x%08X\n", (ent->offsetLow) + (ent->offsetHigh << 16));
			
			addrInt[ind] = 0;
			//context[ind].count = 0;
		}
	}
	else {
		DbgPrint("_IDT_ENTRY->P == 0");
	}

	return;
}
void SetOffsetInt(PIDT_ENTRY inter, PVOID fun) {
	__asm {
		cli
		//pushad
		mov eax, fun
		mov ebx, inter
		mov[ebx], ax
		shr eax, 16
		mov[ebx + 6], ax
		//popad
		sti
	}
	return;
}
//-----------HOOK-----------

//-----------LIST-----------
void InitializateContextList() {
	ULONG i;
	ExInitializePagedLookasideList(&pagedContext, NULL, NULL, 0, sizeof(IDT_CONTEXT), ' LFO', 0);
	for (i = 0; i < 0x100; ++i) {
		context[i].found = 0;
	}
	return;
}
void FreeContextList() {
	ULONG i;
	for (i = 0; i < 0x100; ++i) {
		if (context[i].found) {
			while (!IsListEmpty(&context[i].link)) {
				PLIST_ENTRY pLink = RemoveHeadList(&context[i].link);
				IDT_CONTEXT* entry = CONTAINING_RECORD(pLink, IDT_CONTEXT, link);
				ExFreeToPagedLookasideList(&pagedContext, entry);
			}
		}
	}
	ExDeletePagedLookasideList(&pagedContext);
	return;
}
void PrintListContext() {
	ULONG i;
	PLIST_ENTRY link;
	for (i = 0; i < 0x100; ++i) {
		if (context[i].found) {
			link = &context[i].link;
			do {
				PIDT_CONTEXT entry = CONTAINING_RECORD(link, IDT_CONTEXT, link);
				DbgPrint("Eax:0x%X Ebx:0x%X Ecx:0x%X Edx:0x%X\n",
					entry->regs.Eax, entry->regs.Ebx, entry->regs.Ecx, entry->regs.Edx);
				link = link->Flink;
			} while (link != &context[i].link);
		}
	}
	return;
}
//-----------LIST-----------

//--------INTERRUPTS--------
__declspec(naked) void Interrupt0x0() {
	__asm {
		push eax
		push 0x0
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x1() {
	__asm {
		push eax
		push 0x1
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x2() {
	__asm {
		push eax
		push 0x2
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x3() {
	__asm {
		push eax
		push 0x3
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x4() {
	__asm {
		push eax
		push 0x4
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x5() {
	__asm {
		push eax
		push 0x5
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x6() {
	__asm {
		push eax
		push 0x6
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x7() {
	__asm {
		push eax
		push 0x7
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x8() {
	__asm {
		push eax
		push 0x8
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x9() {
	__asm {
		push eax
		push 0x9
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xa() {
	__asm {
		push eax
		push 0xa
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xb() {
	__asm {
		push eax
		push 0xb
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xc() {
	__asm {
		push eax
		push 0xc
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xd() {
	__asm {
		push eax
		push 0xd
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xe() {
	__asm {
		push eax
		push 0xe
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xf() {
	__asm {
		push eax
		push 0xf
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x10() {
	__asm {
		push eax
		push 0x10
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x11() {
	__asm {
		push eax
		push 0x11
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x12() {
	__asm {
		push eax
		push 0x12
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x13() {
	__asm {
		push eax
		push 0x13
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x14() {
	__asm {
		push eax
		push 0x14
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x15() {
	__asm {
		push eax
		push 0x15
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x16() {
	__asm {
		push eax
		push 0x16
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x17() {
	__asm {
		push eax
		push 0x17
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x18() {
	__asm {
		push eax
		push 0x18
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x19() {
	__asm {
		push eax
		push 0x19
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x1a() {
	__asm {
		push eax
		push 0x1a
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x1b() {
	__asm {
		push eax
		push 0x1b
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x1c() {
	__asm {
		push eax
		push 0x1c
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x1d() {
	__asm {
		push eax
		push 0x1d
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x1e() {
	__asm {
		push eax
		push 0x1e
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x1f() {
	__asm {
		push eax
		push 0x1f
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x20() {
	__asm {
		push eax
		push 0x20
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x21() {
	__asm {
		push eax
		push 0x21
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x22() {
	__asm {
		push eax
		push 0x22
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x23() {
	__asm {
		push eax
		push 0x23
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x24() {
	__asm {
		push eax
		push 0x24
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x25() {
	__asm {
		push eax
		push 0x25
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x26() {
	__asm {
		push eax
		push 0x26
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x27() {
	__asm {
		push eax
		push 0x27
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x28() {
	__asm {
		push eax
		push 0x28
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x29() {
	__asm {
		push eax
		push 0x29
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x2a() {
	__asm {
		push eax
		push 0x2a
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x2b() {
	__asm {
		push eax
		push 0x2b
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x2c() {
	__asm {
		push eax
		push 0x2c
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x2d() {
	__asm {
		push eax
		push 0x2d
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x2e() {
	__asm {
		push eax
		push 0x2e
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x2f() {
	__asm {
		push eax
		push 0x2f
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x30() {
	__asm {
		push eax
		push 0x30
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x31() {
	__asm {
		push eax
		push 0x31
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x32() {
	__asm {
		push eax
		push 0x32
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x33() {
	__asm {
		push eax
		push 0x33
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x34() {
	__asm {
		push eax
		push 0x34
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x35() {
	__asm {
		push eax
		push 0x35
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x36() {
	__asm {
		push eax
		push 0x36
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x37() {
	__asm {
		push eax
		push 0x37
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x38() {
	__asm {
		push eax
		push 0x38
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x39() {
	__asm {
		push eax
		push 0x39
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x3a() {
	__asm {
		push eax
		push 0x3a
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x3b() {
	__asm {
		push eax
		push 0x3b
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x3c() {
	__asm {
		push eax
		push 0x3c
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x3d() {
	__asm {
		push eax
		push 0x3d
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x3e() {
	__asm {
		push eax
		push 0x3e
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x3f() {
	__asm {
		push eax
		push 0x3f
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x40() {
	__asm {
		push eax
		push 0x40
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x41() {
	__asm {
		push eax
		push 0x41
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x42() {
	__asm {
		push eax
		push 0x42
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x43() {
	__asm {
		push eax
		push 0x43
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x44() {
	__asm {
		push eax
		push 0x44
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x45() {
	__asm {
		push eax
		push 0x45
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x46() {
	__asm {
		push eax
		push 0x46
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x47() {
	__asm {
		push eax
		push 0x47
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x48() {
	__asm {
		push eax
		push 0x48
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x49() {
	__asm {
		push eax
		push 0x49
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x4a() {
	__asm {
		push eax
		push 0x4a
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x4b() {
	__asm {
		push eax
		push 0x4b
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x4c() {
	__asm {
		push eax
		push 0x4c
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x4d() {
	__asm {
		push eax
		push 0x4d
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x4e() {
	__asm {
		push eax
		push 0x4e
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x4f() {
	__asm {
		push eax
		push 0x4f
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x50() {
	__asm {
		push eax
		push 0x50
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x51() {
	__asm {
		push eax
		push 0x51
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x52() {
	__asm {
		push eax
		push 0x52
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x53() {
	__asm {
		push eax
		push 0x53
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x54() {
	__asm {
		push eax
		push 0x54
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x55() {
	__asm {
		push eax
		push 0x55
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x56() {
	__asm {
		push eax
		push 0x56
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x57() {
	__asm {
		push eax
		push 0x57
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x58() {
	__asm {
		push eax
		push 0x58
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x59() {
	__asm {
		push eax
		push 0x59
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x5a() {
	__asm {
		push eax
		push 0x5a
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x5b() {
	__asm {
		push eax
		push 0x5b
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x5c() {
	__asm {
		push eax
		push 0x5c
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x5d() {
	__asm {
		push eax
		push 0x5d
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x5e() {
	__asm {
		push eax
		push 0x5e
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x5f() {
	__asm {
		push eax
		push 0x5f
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x60() {
	__asm {
		push eax
		push 0x60
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x61() {
	__asm {
		push eax
		push 0x61
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x62() {
	__asm {
		push eax
		push 0x62
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x63() {
	__asm {
		push eax
		push 0x63
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x64() {
	__asm {
		push eax
		push 0x64
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x65() {
	__asm {
		push eax
		push 0x65
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x66() {
	__asm {
		push eax
		push 0x66
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x67() {
	__asm {
		push eax
		push 0x67
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x68() {
	__asm {
		push eax
		push 0x68
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x69() {
	__asm {
		push eax
		push 0x69
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x6a() {
	__asm {
		push eax
		push 0x6a
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x6b() {
	__asm {
		push eax
		push 0x6b
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x6c() {
	__asm {
		push eax
		push 0x6c
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x6d() {
	__asm {
		push eax
		push 0x6d
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x6e() {
	__asm {
		push eax
		push 0x6e
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x6f() {
	__asm {
		push eax
		push 0x6f
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x70() {
	__asm {
		push eax
		push 0x70
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x71() {
	__asm {
		push eax
		push 0x71
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x72() {
	__asm {
		push eax
		push 0x72
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x73() {
	__asm {
		push eax
		push 0x73
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x74() {
	__asm {
		push eax
		push 0x74
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x75() {
	__asm {
		push eax
		push 0x75
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x76() {
	__asm {
		push eax
		push 0x76
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x77() {
	__asm {
		push eax
		push 0x77
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x78() {
	__asm {
		push eax
		push 0x78
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x79() {
	__asm {
		push eax
		push 0x79
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x7a() {
	__asm {
		push eax
		push 0x7a
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x7b() {
	__asm {
		push eax
		push 0x7b
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x7c() {
	__asm {
		push eax
		push 0x7c
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x7d() {
	__asm {
		push eax
		push 0x7d
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x7e() {
	__asm {
		push eax
		push 0x7e
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x7f() {
	__asm {
		push eax
		push 0x7f
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x80() {
	__asm {
		push eax
		push 0x80
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x81() {
	__asm {
		push eax
		push 0x81
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x82() {
	__asm {
		push eax
		push 0x82
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x83() {
	__asm {
		push eax
		push 0x83
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x84() {
	__asm {
		push eax
		push 0x84
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x85() {
	__asm {
		push eax
		push 0x85
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x86() {
	__asm {
		push eax
		push 0x86
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x87() {
	__asm {
		push eax
		push 0x87
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x88() {
	__asm {
		push eax
		push 0x88
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x89() {
	__asm {
		push eax
		push 0x89
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x8a() {
	__asm {
		push eax
		push 0x8a
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x8b() {
	__asm {
		push eax
		push 0x8b
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x8c() {
	__asm {
		push eax
		push 0x8c
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x8d() {
	__asm {
		push eax
		push 0x8d
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x8e() {
	__asm {
		push eax
		push 0x8e
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x8f() {
	__asm {
		push eax
		push 0x8f
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x90() {
	__asm {
		push eax
		push 0x90
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x91() {
	__asm {
		push eax
		push 0x91
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x92() {
	__asm {
		push eax
		push 0x92
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x93() {
	__asm {
		push eax
		push 0x93
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x94() {
	__asm {
		push eax
		push 0x94
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x95() {
	__asm {
		push eax
		push 0x95
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x96() {
	__asm {
		push eax
		push 0x96
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x97() {
	__asm {
		push eax
		push 0x97
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x98() {
	__asm {
		push eax
		push 0x98
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x99() {
	__asm {
		push eax
		push 0x99
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x9a() {
	__asm {
		push eax
		push 0x9a
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x9b() {
	__asm {
		push eax
		push 0x9b
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x9c() {
	__asm {
		push eax
		push 0x9c
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x9d() {
	__asm {
		push eax
		push 0x9d
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x9e() {
	__asm {
		push eax
		push 0x9e
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0x9f() {
	__asm {
		push eax
		push 0x9f
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xa0() {
	__asm {
		push eax
		push 0xa0
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xa1() {
	__asm {
		push eax
		push 0xa1
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xa2() {
	__asm {
		push eax
		push 0xa2
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xa3() {
	__asm {
		push eax
		push 0xa3
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xa4() {
	__asm {
		push eax
		push 0xa4
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xa5() {
	__asm {
		push eax
		push 0xa5
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xa6() {
	__asm {
		push eax
		push 0xa6
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xa7() {
	__asm {
		push eax
		push 0xa7
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xa8() {
	__asm {
		push eax
		push 0xa8
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xa9() {
	__asm {
		push eax
		push 0xa9
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xaa() {
	__asm {
		push eax
		push 0xaa
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xab() {
	__asm {
		push eax
		push 0xab
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xac() {
	__asm {
		push eax
		push 0xac
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xad() {
	__asm {
		push eax
		push 0xad
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xae() {
	__asm {
		push eax
		push 0xae
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xaf() {
	__asm {
		push eax
		push 0xaf
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xb0() {
	__asm {
		push eax
		push 0xb0
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xb1() {
	__asm {
		push eax
		push 0xb1
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xb2() {
	__asm {
		push eax
		push 0xb2
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xb3() {
	__asm {
		push eax
		push 0xb3
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xb4() {
	__asm {
		push eax
		push 0xb4
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xb5() {
	__asm {
		push eax
		push 0xb5
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xb6() {
	__asm {
		push eax
		push 0xb6
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xb7() {
	__asm {
		push eax
		push 0xb7
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xb8() {
	__asm {
		push eax
		push 0xb8
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xb9() {
	__asm {
		push eax
		push 0xb9
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xba() {
	__asm {
		push eax
		push 0xba
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xbb() {
	__asm {
		push eax
		push 0xbb
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xbc() {
	__asm {
		push eax
		push 0xbc
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xbd() {
	__asm {
		push eax
		push 0xbd
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xbe() {
	__asm {
		push eax
		push 0xbe
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xbf() {
	__asm {
		push eax
		push 0xbf
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xc0() {
	__asm {
		push eax
		push 0xc0
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xc1() {
	__asm {
		push eax
		push 0xc1
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xc2() {
	__asm {
		push eax
		push 0xc2
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xc3() {
	__asm {
		push eax
		push 0xc3
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xc4() {
	__asm {
		push eax
		push 0xc4
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xc5() {
	__asm {
		push eax
		push 0xc5
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xc6() {
	__asm {
		push eax
		push 0xc6
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xc7() {
	__asm {
		push eax
		push 0xc7
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xc8() {
	__asm {
		push eax
		push 0xc8
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xc9() {
	__asm {
		push eax
		push 0xc9
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xca() {
	__asm {
		push eax
		push 0xca
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xcb() {
	__asm {
		push eax
		push 0xcb
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xcc() {
	__asm {
		push eax
		push 0xcc
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xcd() {
	__asm {
		push eax
		push 0xcd
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xce() {
	__asm {
		push eax
		push 0xce
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xcf() {
	__asm {
		push eax
		push 0xcf
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xd0() {
	__asm {
		push eax
		push 0xd0
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xd1() {
	__asm {
		push eax
		push 0xd1
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xd2() {
	__asm {
		push eax
		push 0xd2
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xd3() {
	__asm {
		push eax
		push 0xd3
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xd4() {
	__asm {
		push eax
		push 0xd4
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xd5() {
	__asm {
		push eax
		push 0xd5
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xd6() {
	__asm {
		push eax
		push 0xd6
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xd7() {
	__asm {
		push eax
		push 0xd7
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xd8() {
	__asm {
		push eax
		push 0xd8
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xd9() {
	__asm {
		push eax
		push 0xd9
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xda() {
	__asm {
		push eax
		push 0xda
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xdb() {
	__asm {
		push eax
		push 0xdb
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xdc() {
	__asm {
		push eax
		push 0xdc
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xdd() {
	__asm {
		push eax
		push 0xdd
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xde() {
	__asm {
		push eax
		push 0xde
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xdf() {
	__asm {
		push eax
		push 0xdf
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xe0() {
	__asm {
		push eax
		push 0xe0
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xe1() {
	__asm {
		push eax
		push 0xe1
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xe2() {
	__asm {
		push eax
		push 0xe2
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xe3() {
	__asm {
		push eax
		push 0xe3
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xe4() {
	__asm {
		push eax
		push 0xe4
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xe5() {
	__asm {
		push eax
		push 0xe5
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xe6() {
	__asm {
		push eax
		push 0xe6
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xe7() {
	__asm {
		push eax
		push 0xe7
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xe8() {
	__asm {
		push eax
		push 0xe8
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xe9() {
	__asm {
		push eax
		push 0xe9
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xea() {
	__asm {
		push eax
		push 0xea
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xeb() {
	__asm {
		push eax
		push 0xeb
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xec() {
	__asm {
		push eax
		push 0xec
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xed() {
	__asm {
		push eax
		push 0xed
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xee() {
	__asm {
		push eax
		push 0xee
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xef() {
	__asm {
		push eax
		push 0xef
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xf0() {
	__asm {
		push eax
		push 0xf0
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xf1() {
	__asm {
		push eax
		push 0xf1
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xf2() {
	__asm {
		push eax
		push 0xf2
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xf3() {
	__asm {
		push eax
		push 0xf3
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xf4() {
	__asm {
		push eax
		push 0xf4
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xf5() {
	__asm {
		push eax
		push 0xf5
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xf6() {
	__asm {
		push eax
		push 0xf6
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xf7() {
	__asm {
		push eax
		push 0xf7
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xf8() {
	__asm {
		push eax
		push 0xf8
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xf9() {
	__asm {
		push eax
		push 0xf9
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xfa() {
	__asm {
		push eax
		push 0xfa
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xfb() {
	__asm {
		push eax
		push 0xfb
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xfc() {
	__asm {
		push eax
		push 0xfc
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xfd() {
	__asm {
		push eax
		push 0xfd
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xfe() {
	__asm {
		push eax
		push 0xfe
		jmp InterruptHook
	}
}
__declspec(naked) void Interrupt0xff() {
	__asm {
		push eax
		push 0xff
		jmp InterruptHook
	}
}


void PlaceFunction() {
	addrFun[0] = &Interrupt0x0;
	addrFun[1] = &Interrupt0x1;
	addrFun[2] = &Interrupt0x2;
	addrFun[3] = &Interrupt0x3;
	addrFun[4] = &Interrupt0x4;
	addrFun[5] = &Interrupt0x5;
	addrFun[6] = &Interrupt0x6;
	addrFun[7] = &Interrupt0x7;
	addrFun[8] = &Interrupt0x8;
	addrFun[9] = &Interrupt0x9;
	addrFun[10] = &Interrupt0xa;
	addrFun[11] = &Interrupt0xb;
	addrFun[12] = &Interrupt0xc;
	addrFun[13] = &Interrupt0xd;
	addrFun[14] = &Interrupt0xe;
	addrFun[15] = &Interrupt0xf;
	addrFun[16] = &Interrupt0x10;
	addrFun[17] = &Interrupt0x11;
	addrFun[18] = &Interrupt0x12;
	addrFun[19] = &Interrupt0x13;
	addrFun[20] = &Interrupt0x14;
	addrFun[21] = &Interrupt0x15;
	addrFun[22] = &Interrupt0x16;
	addrFun[23] = &Interrupt0x17;
	addrFun[24] = &Interrupt0x18;
	addrFun[25] = &Interrupt0x19;
	addrFun[26] = &Interrupt0x1a;
	addrFun[27] = &Interrupt0x1b;
	addrFun[28] = &Interrupt0x1c;
	addrFun[29] = &Interrupt0x1d;
	addrFun[30] = &Interrupt0x1e;
	addrFun[31] = &Interrupt0x1f;
	addrFun[32] = &Interrupt0x20;
	addrFun[33] = &Interrupt0x21;
	addrFun[34] = &Interrupt0x22;
	addrFun[35] = &Interrupt0x23;
	addrFun[36] = &Interrupt0x24;
	addrFun[37] = &Interrupt0x25;
	addrFun[38] = &Interrupt0x26;
	addrFun[39] = &Interrupt0x27;
	addrFun[40] = &Interrupt0x28;
	addrFun[41] = &Interrupt0x29;
	addrFun[42] = &Interrupt0x2a;
	addrFun[43] = &Interrupt0x2b;
	addrFun[44] = &Interrupt0x2c;
	addrFun[45] = &Interrupt0x2d;
	addrFun[46] = &Interrupt0x2e;
	addrFun[47] = &Interrupt0x2f;
	addrFun[48] = &Interrupt0x30;
	addrFun[49] = &Interrupt0x31;
	addrFun[50] = &Interrupt0x32;
	addrFun[51] = &Interrupt0x33;
	addrFun[52] = &Interrupt0x34;
	addrFun[53] = &Interrupt0x35;
	addrFun[54] = &Interrupt0x36;
	addrFun[55] = &Interrupt0x37;
	addrFun[56] = &Interrupt0x38;
	addrFun[57] = &Interrupt0x39;
	addrFun[58] = &Interrupt0x3a;
	addrFun[59] = &Interrupt0x3b;
	addrFun[60] = &Interrupt0x3c;
	addrFun[61] = &Interrupt0x3d;
	addrFun[62] = &Interrupt0x3e;
	addrFun[63] = &Interrupt0x3f;
	addrFun[64] = &Interrupt0x40;
	addrFun[65] = &Interrupt0x41;
	addrFun[66] = &Interrupt0x42;
	addrFun[67] = &Interrupt0x43;
	addrFun[68] = &Interrupt0x44;
	addrFun[69] = &Interrupt0x45;
	addrFun[70] = &Interrupt0x46;
	addrFun[71] = &Interrupt0x47;
	addrFun[72] = &Interrupt0x48;
	addrFun[73] = &Interrupt0x49;
	addrFun[74] = &Interrupt0x4a;
	addrFun[75] = &Interrupt0x4b;
	addrFun[76] = &Interrupt0x4c;
	addrFun[77] = &Interrupt0x4d;
	addrFun[78] = &Interrupt0x4e;
	addrFun[79] = &Interrupt0x4f;
	addrFun[80] = &Interrupt0x50;
	addrFun[81] = &Interrupt0x51;
	addrFun[82] = &Interrupt0x52;
	addrFun[83] = &Interrupt0x53;
	addrFun[84] = &Interrupt0x54;
	addrFun[85] = &Interrupt0x55;
	addrFun[86] = &Interrupt0x56;
	addrFun[87] = &Interrupt0x57;
	addrFun[88] = &Interrupt0x58;
	addrFun[89] = &Interrupt0x59;
	addrFun[90] = &Interrupt0x5a;
	addrFun[91] = &Interrupt0x5b;
	addrFun[92] = &Interrupt0x5c;
	addrFun[93] = &Interrupt0x5d;
	addrFun[94] = &Interrupt0x5e;
	addrFun[95] = &Interrupt0x5f;
	addrFun[96] = &Interrupt0x60;
	addrFun[97] = &Interrupt0x61;
	addrFun[98] = &Interrupt0x62;
	addrFun[99] = &Interrupt0x63;
	addrFun[100] = &Interrupt0x64;
	addrFun[101] = &Interrupt0x65;
	addrFun[102] = &Interrupt0x66;
	addrFun[103] = &Interrupt0x67;
	addrFun[104] = &Interrupt0x68;
	addrFun[105] = &Interrupt0x69;
	addrFun[106] = &Interrupt0x6a;
	addrFun[107] = &Interrupt0x6b;
	addrFun[108] = &Interrupt0x6c;
	addrFun[109] = &Interrupt0x6d;
	addrFun[110] = &Interrupt0x6e;
	addrFun[111] = &Interrupt0x6f;
	addrFun[112] = &Interrupt0x70;
	addrFun[113] = &Interrupt0x71;
	addrFun[114] = &Interrupt0x72;
	addrFun[115] = &Interrupt0x73;
	addrFun[116] = &Interrupt0x74;
	addrFun[117] = &Interrupt0x75;
	addrFun[118] = &Interrupt0x76;
	addrFun[119] = &Interrupt0x77;
	addrFun[120] = &Interrupt0x78;
	addrFun[121] = &Interrupt0x79;
	addrFun[122] = &Interrupt0x7a;
	addrFun[123] = &Interrupt0x7b;
	addrFun[124] = &Interrupt0x7c;
	addrFun[125] = &Interrupt0x7d;
	addrFun[126] = &Interrupt0x7e;
	addrFun[127] = &Interrupt0x7f;
	addrFun[128] = &Interrupt0x80;
	addrFun[129] = &Interrupt0x81;
	addrFun[130] = &Interrupt0x82;
	addrFun[131] = &Interrupt0x83;
	addrFun[132] = &Interrupt0x84;
	addrFun[133] = &Interrupt0x85;
	addrFun[134] = &Interrupt0x86;
	addrFun[135] = &Interrupt0x87;
	addrFun[136] = &Interrupt0x88;
	addrFun[137] = &Interrupt0x89;
	addrFun[138] = &Interrupt0x8a;
	addrFun[139] = &Interrupt0x8b;
	addrFun[140] = &Interrupt0x8c;
	addrFun[141] = &Interrupt0x8d;
	addrFun[142] = &Interrupt0x8e;
	addrFun[143] = &Interrupt0x8f;
	addrFun[144] = &Interrupt0x90;
	addrFun[145] = &Interrupt0x91;
	addrFun[146] = &Interrupt0x92;
	addrFun[147] = &Interrupt0x93;
	addrFun[148] = &Interrupt0x94;
	addrFun[149] = &Interrupt0x95;
	addrFun[150] = &Interrupt0x96;
	addrFun[151] = &Interrupt0x97;
	addrFun[152] = &Interrupt0x98;
	addrFun[153] = &Interrupt0x99;
	addrFun[154] = &Interrupt0x9a;
	addrFun[155] = &Interrupt0x9b;
	addrFun[156] = &Interrupt0x9c;
	addrFun[157] = &Interrupt0x9d;
	addrFun[158] = &Interrupt0x9e;
	addrFun[159] = &Interrupt0x9f;
	addrFun[160] = &Interrupt0xa0;
	addrFun[161] = &Interrupt0xa1;
	addrFun[162] = &Interrupt0xa2;
	addrFun[163] = &Interrupt0xa3;
	addrFun[164] = &Interrupt0xa4;
	addrFun[165] = &Interrupt0xa5;
	addrFun[166] = &Interrupt0xa6;
	addrFun[167] = &Interrupt0xa7;
	addrFun[168] = &Interrupt0xa8;
	addrFun[169] = &Interrupt0xa9;
	addrFun[170] = &Interrupt0xaa;
	addrFun[171] = &Interrupt0xab;
	addrFun[172] = &Interrupt0xac;
	addrFun[173] = &Interrupt0xad;
	addrFun[174] = &Interrupt0xae;
	addrFun[175] = &Interrupt0xaf;
	addrFun[176] = &Interrupt0xb0;
	addrFun[177] = &Interrupt0xb1;
	addrFun[178] = &Interrupt0xb2;
	addrFun[179] = &Interrupt0xb3;
	addrFun[180] = &Interrupt0xb4;
	addrFun[181] = &Interrupt0xb5;
	addrFun[182] = &Interrupt0xb6;
	addrFun[183] = &Interrupt0xb7;
	addrFun[184] = &Interrupt0xb8;
	addrFun[185] = &Interrupt0xb9;
	addrFun[186] = &Interrupt0xba;
	addrFun[187] = &Interrupt0xbb;
	addrFun[188] = &Interrupt0xbc;
	addrFun[189] = &Interrupt0xbd;
	addrFun[190] = &Interrupt0xbe;
	addrFun[191] = &Interrupt0xbf;
	addrFun[192] = &Interrupt0xc0;
	addrFun[193] = &Interrupt0xc1;
	addrFun[194] = &Interrupt0xc2;
	addrFun[195] = &Interrupt0xc3;
	addrFun[196] = &Interrupt0xc4;
	addrFun[197] = &Interrupt0xc5;
	addrFun[198] = &Interrupt0xc6;
	addrFun[199] = &Interrupt0xc7;
	addrFun[200] = &Interrupt0xc8;
	addrFun[201] = &Interrupt0xc9;
	addrFun[202] = &Interrupt0xca;
	addrFun[203] = &Interrupt0xcb;
	addrFun[204] = &Interrupt0xcc;
	addrFun[205] = &Interrupt0xcd;
	addrFun[206] = &Interrupt0xce;
	addrFun[207] = &Interrupt0xcf;
	addrFun[208] = &Interrupt0xd0;
	addrFun[209] = &Interrupt0xd1;
	addrFun[210] = &Interrupt0xd2;
	addrFun[211] = &Interrupt0xd3;
	addrFun[212] = &Interrupt0xd4;
	addrFun[213] = &Interrupt0xd5;
	addrFun[214] = &Interrupt0xd6;
	addrFun[215] = &Interrupt0xd7;
	addrFun[216] = &Interrupt0xd8;
	addrFun[217] = &Interrupt0xd9;
	addrFun[218] = &Interrupt0xda;
	addrFun[219] = &Interrupt0xdb;
	addrFun[220] = &Interrupt0xdc;
	addrFun[221] = &Interrupt0xdd;
	addrFun[222] = &Interrupt0xde;
	addrFun[223] = &Interrupt0xdf;
	addrFun[224] = &Interrupt0xe0;
	addrFun[225] = &Interrupt0xe1;
	addrFun[226] = &Interrupt0xe2;
	addrFun[227] = &Interrupt0xe3;
	addrFun[228] = &Interrupt0xe4;
	addrFun[229] = &Interrupt0xe5;
	addrFun[230] = &Interrupt0xe6;
	addrFun[231] = &Interrupt0xe7;
	addrFun[232] = &Interrupt0xe8;
	addrFun[233] = &Interrupt0xe9;
	addrFun[234] = &Interrupt0xea;
	addrFun[235] = &Interrupt0xeb;
	addrFun[236] = &Interrupt0xec;
	addrFun[237] = &Interrupt0xed;
	addrFun[238] = &Interrupt0xee;
	addrFun[239] = &Interrupt0xef;
	addrFun[240] = &Interrupt0xf0;
	addrFun[241] = &Interrupt0xf1;
	addrFun[242] = &Interrupt0xf2;
	addrFun[243] = &Interrupt0xf3;
	addrFun[244] = &Interrupt0xf4;
	addrFun[245] = &Interrupt0xf5;
	addrFun[246] = &Interrupt0xf6;
	addrFun[247] = &Interrupt0xf7;
	addrFun[248] = &Interrupt0xf8;
	addrFun[249] = &Interrupt0xf9;
	addrFun[250] = &Interrupt0xfa;
	addrFun[251] = &Interrupt0xfb;
	addrFun[252] = &Interrupt0xfc;
	addrFun[253] = &Interrupt0xfd;
	addrFun[254] = &Interrupt0xfe;
	addrFun[255] = &Interrupt0xff;
}
//--------INTERRUPTS--------

