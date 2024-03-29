#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include "..\ioctl.h"
#include "..\intel.h"
#include "..\pt.h"

#define sysenter __asm _emit 0x0F __asm _emit 0x34
#define SYSCALL_SIGNATURE 0x00ABBA00


void PrintMapDWORD(PVOID map, ULONG size, ULONG offset);
void PrintMapBYTE(PVOID map, ULONG size, ULONG offset);
PCHAR FindStrInMap(PVOID map, ULONG size, PCHAR str);

unsigned int AddressSystemCall;
__declspec(naked) void FastSystemCall(void) {
	__asm mov edx, esp
	__asm sysenter
}
__declspec(naked) void SysCall(void) {
	//__asm mov eax, <id>
	__asm mov edx, offset AddressSystemCall
	__asm call dword ptr[edx]
	__asm ret
}

int main(int argc, char* argv[]) {

	char out[0xFFFF];

	DWORD bytesReturned;
	unsigned int buffSize = 0;
	char* buffer;

	if (argc < 2) {

		printf("ioctl.exe [in]/[out]/[count]");
		return 0;
	}
	buffSize = 0xFFFF;
	buffer = (char*)malloc(buffSize * sizeof(char));
	memset(buffer, 0, buffSize);
	HANDLE file = CreateFileA("\\\\.\\Driver",
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		(HANDLE)NULL);

	if (!file) {
		printf("Driver dos`t loaded!");
		return 0;
	}
	LoadLibraryW(L"user32.dll");
	LoadLibraryW(L"gdi32.dll");
	if (!strcmp(argv[1], "init_dump")) {
		__asm {
			push edx
			push eax

			mov edx, esp
			int 0x75
			add esp, 8
			mov ax, 3bh
			mov fs, ax

			pop eax
			pop edx
		}
	}
	else if (!strcmp(argv[1], "dumpgdt")) {		//syscall 0x0215
		__asm {
			push buffSize
			push buffer
			mov eax, 0x0215
		}
		AddressSystemCall = (unsigned int)FastSystemCall;
		SysCall();
		printf(buffer);
	}
	else if (!strcmp(argv[1], "dumpidt")) {		 //syscall 0x11df
		__asm {
			push 0
			push 0
			push buffSize
			push buffer
			push SYSCALL_SIGNATURE
			mov eax, 0x11df
		}
		AddressSystemCall = (unsigned int)FastSystemCall;
		SysCall();
		printf(buffer);
	}
	else if (!strcmp(argv[1], "hook_count_int")) {		//syscall 0x2021
		if (argc > 2) {
			char* code = argv[2];
			int* size = (int*)out;
			size[0] = 0xFFFF;
			__asm {
				push code
				mov eax, 0x2021
			}
			AddressSystemCall = (unsigned int)FastSystemCall;
			SysCall();
			printf(out);
		}
	}
	else if (!strcmp(argv[1], "hook_count_info")) {		//syscall 0x3009
		int* size = (int*)out;
		size[0] = 0xFFFF;
		__asm {
			push buffer
			mov eax, 0x3009
		}
		AddressSystemCall = (unsigned int)FastSystemCall;
		SysCall();
		printf(buffer);
	}
	else if (!strcmp(argv[1], "hook_int")) {
		if (argc > 2) {
			char* code = argv[2];
			int* size = (int*)out;
			size[0] = 0xFFFF;
			__asm {
				push eax
				mov eax, code
				//call 0x9B:0x44332211		19*8 + 3		19 ������ (�� 8 ����) + ��� DPL
				_emit 0x9a // opcode
				_emit 0x11
				_emit 0x22
				_emit 0x33
				_emit 0x44
				_emit 0xF3 //selector	// 0x9B
				_emit 0x03				// 0x00
				pop eax
				mov ax, 3bh
				mov fs, ax
			}
			printf(out);
		}

	}
	else if (!strcmp(argv[1], "hook_info")) {
		int* size = (int*)out;
		size[0] = 0xFFFF;
		__asm {
			push eax
			mov eax, buffer
			//call 0x3fb:0x44332211		19*8 + 3		19 ������ (�� 8 ����) + ��� DPL
			_emit 0x9a // opcode
			_emit 0x11
			_emit 0x22
			_emit 0x33
			_emit 0x44
			_emit 0xFB //selector
			_emit 0x03
			pop eax
			mov ax, 3bh
			mov fs, ax
		}
		printf(buffer);

	}
	else if (!strcmp(argv[1], "hooksysent")) {
		if (!DeviceIoControl(file, START_HOOKING_SYSENTER,
			buffer, buffSize,
			out, 0xFFFF,
			&bytesReturned, NULL)) {
			printf("error hook sysenter");
		}
		printf(out);
	}
	else if (!strcmp(argv[1], "dehooksysent")) {
		if (!DeviceIoControl(file, STOP_HOOKING_SYSENTER,
			buffer, buffSize,
			out, 0xFFFF,
			&bytesReturned, NULL)) {
			printf("error dehook sysenter");
		}
		printf(out);
	}
	else if (!strcmp(argv[1], "infosysent2")) {
		if (argc > 2) {
			strncpy(buffer, argv[2], buffSize);
		}
		if (!DeviceIoControl(file, SYSCALL_IND_INFO_IOCTL,
			buffer, buffSize,
			out, 0xFFFF,
			&bytesReturned, NULL)) {
			printf("error info sysenter");
		}
		printf(out);
	}
	else if (!strcmp(argv[1], "infosysent1")) {
		if (argc > 2) {
			strncpy(buffer, argv[2], buffSize);
		}
		if (!DeviceIoControl(file, SYSCALL_ALL_INFO_IOCTL,
			buffer, buffSize,
			out, 0xFFFF,
			&bytesReturned, NULL)) {
			printf("error info sysenter");
		}
		printf(out);
	}
	else if (!strcmp(argv[1], "infosysent0")) {
		if (!DeviceIoControl(file, SYSCALL_CNT_INFO_IOCTL,
			buffer, buffSize,
			out, 0xFFFF,
			&bytesReturned, NULL)) {
			printf("error info sysenter");
		}
		printf(out);
	}
	else if (!strcmp(argv[1], "findstr")) {
		if (argc > 2) {
			PCHAR strinrng[] = {"qwertty"};
			ULONG i, j ,k;
			ULONG mem;
			ULONG sz = 0x1000;
			PCHAR str = argv[4];
			ULONG lenStr = strlen(str);
			PCHAR bytePtr;
			ULONG bytes = 0;
			PVOID address = NULL;
			PCHAR found = NULL;
			ULONG offset = (ULONG)strtoul(argv[2], NULL, 0);
			ULONG maxPhyMem = (ULONG)strtoul(argv[3], NULL, 0);
			printf("pages:%d-%d str:%s\n", offset, maxPhyMem, str);
			for (i = offset; i < maxPhyMem; i++) {
				mem = i * 0x1000;
				__asm {
					push edx
					push eax

					push sz
					push mem
					lea eax, [address]
					push eax
					mov edx, esp
					int 0x76
					add esp, 12
					mov ax, 3bh
					mov fs, ax

					pop eax
					pop edx
				}
				if (!address) {
					printf("end of search\n");
					break;
				}
				bytePtr = (PCHAR)address;
				for (j = 0; j < sz; ++j) {

					if (bytePtr[j] == str[bytes]) ++bytes;
					else if (bytes) bytes = 0;

					if (bytes == lenStr) {
						//printf("BYTEPTR : 0x%X %d\n", (DWORD)bytePtr, bytes);
						found = (bytePtr + j - bytes + 1);
						printf("FOUND VA:0x%X PAGE:0x%X STR:", (ULONG)found, mem);
						for (k = 0; k < lenStr; ++k) {
							printf("%c", found[k]);
						}
						printf("\n");
						bytes = 0;
					}
				}
				//found = FindStrInMap(address, sz, str);
				//if (found) {
				//	printf("FOUND VA:0x%X PAGE:0x%X STR:", (ULONG)found, mem);
				//	for (ULONG ij = 0; ij < lenStr; ++ij) {
				//		printf("%c", found[ij]);
				//	}
				//	printf("\n");
				//	//break;
				//}
				//if (address) {
				//	PrintMapDWORD(address, sz, 0);
				//}
				__asm {
					push edx
					push eax

					push sz
					push address
					mov edx, esp
					int 0x75
					add esp, 8
					mov ax, 3bh
					mov fs, ax

					pop eax
					pop edx
				}
				address = NULL;
			}

		}
	} 
	else if (!strcmp(argv[1], "rdmem")) {
		if (argc > 2) {
			ULONG address = (ULONG)strtol(argv[2], NULL, 0);
			ULONG sz = (ULONG)strtol(argv[3], NULL, 0);
			printf("addr:%X str:%s\n", address, buffer);
			__asm {
				push edx
				push eax

				push sz
				push buffer
				push address
				mov edx, esp
				int 0x3f
				add esp, 12
				mov ax, 3bh
				mov fs, ax

				pop eax
				pop edx
			}
			buffer += address;
			for (int i = 0; i < sz; i++) {
				printf(" %02X", (unsigned char)buffer[i]);
				if (i % 25 == 0)
					printf("\n");
			}
		}
	} 

	free(buffer);
	CloseHandle(file);

	return 0;
}

void PrintMapDWORD(PVOID map, ULONG size, ULONG offset) {

	PCHAR dbgStr = "%08X";
	ULONG i;
	printf("\n\nMAP ADDRESS : %X\n", (ULONG)map);
	printf("0: ");
	for (i = offset; i < size / 4; ++i) {

		if (i) {
			if (i == 0x1000 / 4) {
				printf("\n----------------------------------ALIGNMENT---------------------------------\n");
			}
			if (i % 8 == 0) {
				printf("\n%d: ", (i / 8));
			}
			else {
				printf(" ");
			}
			
		}
		__asm {
			push eax
			push ebx
			mov ebx, i
			mov eax, 4
			mul ebx
			mov ebx, map
			add ebx, eax
			mov ebx, dword ptr[ebx]
			push ebx
			push dbgStr
			call printf
			pop ebx
			pop eax
		}

	}
	printf("\n");
	return;
}

VOID PrintMapBYTE(PVOID map, ULONG size, ULONG offset) {

	PCHAR dbgStr = "%02X";
	ULONG i;
	printf("\n\nMAP ADDRESS : %X\n", (DWORD)map);
	printf("0: ");
	for (i = offset; i < size; ++i) {

		if (i) {
			if (i % 32 == 0) {
				printf("\n%d: ", (i / 32));
			}
			else {
				printf(" ");
			}
		}
		__asm {
			mov eax, map
			add eax, i
			xor ebx, ebx
			mov bl, byte ptr[eax]
			push ebx
			push dbgStr
			call printf
		}

	}
	printf("\n");

	return;
}

PCHAR FindStrInMap(PVOID map, ULONG size, PCHAR str) {
	DWORD i;
	DWORD bytes = 0;
	DWORD lenStr = strlen(str);
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