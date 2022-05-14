#include "hooksysenter.h"


void InitHookSysenter() {
	glNumberSysServices = KeServiceDescriptorTable->Limit;
	glSyscallEaxs = (ULONG*)ExAllocatePoolWithTag(PagedPool, (glNumberSysServices + 1) * sizeof(ULONG), 'oneN');
	RtlZeroMemory(glSyscallEaxs, (glNumberSysServices + 1) * sizeof(ULONG));

	//?
	ExInitializePagedLookasideList(&pagedContextSyscall, NULL, NULL, 0, sizeof(CONTEXT_SYSCALL), ' LFO', 0);
	pContextSyscalls = (PCONTEXT_SYSCALL)ExAllocatePoolWithTag(PagedPool, (glNumberSysServices + 1) * sizeof(CONTEXT_SYSCALL), 'oneN');
	RtlZeroMemory(pContextSyscalls, (glNumberSysServices + 1) * sizeof(CONTEXT_SYSCALL));
	//?

	return;
}

// Обработчик инструкции sysenter
__declspec(naked) void HandlerSysenter() {
	ULONG OldStackPointer;
	ULONG CurrentNumberService;
	ULONG BytesForArguments;
	PULONG CurrentUserStack;
	PCONTEXT_SYSCALL pCurrentContextSyscall;

	__asm {
		mov[glCurrentNumberService], eax        // индекс системного вызова
		mov[glCurrentUserStack], edx            // указатель на параметры в пользовательском стеке
		mov[glOldStackPointer], esp             // общий стек потоков
	}

	__asm pushad

	// проверяем, что это системный вызов
	if (glCurrentNumberService >= glNumberSysServices) {
		__asm popad
		__asm jmp[glRealAddressSysenter]
	}

	// получаем из TSS указатель на ядерный стек потока
	glTss = GetTSS();
	glThreadStackPointer = glTss->ESP0;

	__asm popad

	__asm {
		mov esp, [glThreadStackPointer]  // загружаем стек потока

		pushad                          // сохраняем регистры в стеке
		pushfd
		push fs
		push ds
		push es

		mov cx, 0x30                     // устанавливаем значение сегментных регистров
		mov fs, cx
		mov cx, 0x23
		mov ds, cx
		mov es, cx

		push ebp                        // формируем стековый кадр для доступа к локальным переменным
		mov ebp, esp
		sub esp, 0x48
	}
	// запоминаем данные в локальные переменные
	// запоминать их необходимо, если дальше будут разрешены прерывания,
	// т.к. эти значения в глобальных переменных будут перезаписаны в другом потоке
	// раньше сохранять в локальные переменные было нельзя,
	// т.к. не был сформирован стековый кадр
	OldStackPointer = glOldStackPointer;
	CurrentNumberService = glCurrentNumberService;
	CurrentUserStack = glCurrentUserStack;
	BytesForArguments = KeServiceDescriptorTable->Number[CurrentNumberService];

	// если необходима работа с функциями ядра, то разрешаем прерывания
	__asm sti

	// Вставить логику на самом деле надо вот сюда (ниже)

	__asm {
		mov eax, CurrentNumberService

		// int 3
		push eax
		push ebx  // Get address of needed syscall in array
		push ecx
		mov ebx, eax
		mov eax, 4
		mul ebx
		mov ecx, glSyscallEaxs
		add ecx, ebx

		inc dword ptr[ecx]  // Increase the value 

	}

	if (!pContextSyscalls[CurrentNumberService].b) {
		InitializeListHead(&pContextSyscalls[CurrentNumberService].link);
		pCurrentContextSyscall = &pContextSyscalls[CurrentNumberService];
		pContextSyscalls[CurrentNumberService].b = TRUE;
	}
	else {
		pCurrentContextSyscall = (PCONTEXT_SYSCALL)ExAllocateFromPagedLookasideList(&pagedContextSyscall);
		InsertTailList(&pContextSyscalls[CurrentNumberService].link, &pCurrentContextSyscall->link);
	}
	pCurrentContextSyscall->index = CurrentNumberService;
	pCurrentContextSyscall->userStack = CurrentUserStack;
	pCurrentContextSyscall->argBuffer.size = BytesForArguments;
	if (pCurrentContextSyscall->argBuffer.size) {
		pCurrentContextSyscall->argBuffer.buffer = (PULONG)ExAllocatePoolWithTag(PagedPool, BytesForArguments, 'oneN');
		RtlCopyMemory(pCurrentContextSyscall->argBuffer.buffer, CurrentUserStack, BytesForArguments);
	}
	else {
		pCurrentContextSyscall->argBuffer.buffer = NULL;
	}
	__asm {
		pop ecx // Get it back
		pop ebx
		pop eax

		mov dword ptr[glLastSC], eax

		cntr_increase :
		inc dword ptr[glNumberOfSysenters]
	}

	// Вставить логику на самом деле надо вот сюда (выше)

	// если прерывания были разрешены, то их необходимо запретить
	__asm cli

	glOldStackPointer = OldStackPointer;

	__asm {
		mov esp, ebp
		pop ebp

		pop es
		pop ds
		pop fs
		popfd
		popad

		mov esp, [glOldStackPointer]

		jmp[glRealAddressSysenter]
	}

}


// функция заменяет адрес обработчика инструкции SYSENTER
// возращает адрес прежнего обработчика
void HookSysenter(ULONG NewAddress, PULONG OldAddress) {
	_asm {
		mov ecx, 0x176
		rdmsr

		push ebx
		mov ebx, [OldAddress]
		mov[ebx], eax
		pop ebx
		mov eax, NewAddress
		wrmsr
	}
}

// получает указатель на TSS
PTSS GetTSS() {

	Selector			sTss;
	GDTR				Gdt;
	PTSS				pTss;
	PDescriptorSystem	dTss;

	_asm {
		str sTss    // получаем селектор сегмента состояния задачи
		sgdt Gdt    // получаем регистр gdtr
	}

	// получаем указатель на дескриптор сегмента состояния задачи
	dTss = (PDescriptorSystem)Gdt.Base + sTss.Index;

	// получаем указатель на сегмент состояния задачи
	pTss = (PTSS)((ULONG)dTss->BaseLow + (dTss->BaseMedium << 16) + (dTss->BaseHigh << 24));
	return pTss;
}

// ?
void PrintContextSyscalls() {
	ULONG i, j;
	PLIST_ENTRY link;

	for (i = 0; i < glNumberSysServices + 1; ++i) {

		if (pContextSyscalls[i].b) {
			link = &pContextSyscalls[i].link;
			do {
				PCONTEXT_SYSCALL entry = CONTAINING_RECORD(link, CONTEXT_SYSCALL, link);
				DbgPrint("\tindex:0x%X \t", entry->index);
				for (j = 0; j < entry->argBuffer.size; ++j) {
					DbgPrint("0x%X ", entry->argBuffer.buffer[j]);
				}
				DbgPrint("\n");
				link = link->Flink;
			} while (link != &pContextSyscalls[i].link);
		}
	}


	return;
}
// ?

void FreeHookSysenterEaxs() {
	// ?
	ULONG i;
	PLIST_ENTRY link;

	for (i = 0; i < glNumberSysServices + 1; ++i) {
		link = &pContextSyscalls->link;
		if (pContextSyscalls[i].b) {
			while (!IsListEmpty(&pContextSyscalls[i].link)) {
				PLIST_ENTRY pLink = RemoveHeadList(&pContextSyscalls[i].link);
				PCONTEXT_SYSCALL entry = CONTAINING_RECORD(pLink, CONTEXT_SYSCALL, link);
				if (entry->argBuffer.size) {
					ExFreePool(entry->argBuffer.buffer);
				}
				ExFreeToPagedLookasideList(&pagedContextSyscall, entry);
			}
		}
	}
	
	ExDeletePagedLookasideList(&pagedContextSyscall);
	ExFreePool(pContextSyscalls);
	// ? 
	ExFreePool(glSyscallEaxs);

	return;
}