#ifndef _EXPTABLE_H
#define _EXPTABLE_H
#define IMAGE_DOS_SIGNATURE		0x4D5A		// MZ
#define IMAGE_OS2_SIGNATURE		0x4E45		// NE
#define IMAGE_OS2_SIGNATURE_LE	0x4C45		// LE
#define IMAGE_NT_SIGNATURE		0x50450000	// PE00
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16
#include <ntddk.h>
#include <ntimage.h>
#include <WinDef.h>

typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation = 0,
    SystemProcessorInformation = 1,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemPathInformation = 4,
    SystemProcessInformation = 5,
    SystemCallCountInformation = 6,
    SystemDeviceInformation = 7,
    SystemProcessorPerformanceInformation = 8,
    SystemFlagsInformation = 9,
    SystemCallTimeInformation = 10,
    SystemModuleInformation = 11,
    SystemLocksInformation = 12,
    SystemStackTraceInformation = 13,
    SystemPagedPoolInformation = 14,
    SystemNonPagedPoolInformation = 15,
    SystemHandleInformation = 16,
    SystemObjectInformation = 17,
    SystemPageFileInformation = 18,
    SystemVdmInstemulInformation = 19,
    SystemVdmBopInformation = 20,
    SystemFileCacheInformation = 21,
    SystemPoolTagInformation = 22,
    SystemInterruptInformation = 23,
    SystemDpcBehaviorInformation = 24,
    SystemFullMemoryInformation = 25,
    SystemLoadGdiDriverInformation = 26,
    SystemUnloadGdiDriverInformation = 27,
    SystemTimeAdjustmentInformation = 28,
    SystemSummaryMemoryInformation = 29,
    SystemMirrorMemoryInformation = 30,
    SystemPerformanceTraceInformation = 31,
    SystemObsolete0 = 32,
    SystemExceptionInformation = 33,
    SystemCrashDumpStateInformation = 34,
    SystemKernelDebuggerInformation = 35,
    SystemContextSwitchInformation = 36,
    SystemRegistryQuotaInformation = 37,
    SystemExtendServiceTableInformation = 38,
    SystemPrioritySeperation = 39,
    SystemVerifierAddDriverInformation = 40,
    SystemVerifierRemoveDriverInformation = 41,
    SystemProcessorIdleInformation = 42,
    SystemLegacyDriverInformation = 43,
    SystemCurrentTimeZoneInformation = 44,
    SystemLookasideInformation = 45,
    SystemTimeSlipNotification = 46,
    SystemSessionCreate = 47,
    SystemSessionDetach = 48,
    SystemSessionInformation = 49,
    SystemRangeStartInformation = 50,
    SystemVerifierInformation = 51,
    SystemVerifierThunkExtend = 52,
    SystemSessionProcessInformation = 53,
    SystemLoadGdiDriverInSystemSpace = 54,
    SystemNumaProcessorMap = 55,
    SystemPrefetcherInformation = 56,
    SystemExtendedProcessInformation = 57,
    SystemRecommendedSharedDataAlignment = 58,
    SystemComPlusPackage = 59,
    SystemNumaAvailableMemory = 60,
    SystemProcessorPowerInformation = 61,
    SystemEmulationBasicInformation = 62,
    SystemEmulationProcessorInformation = 63,
    SystemExtendedHandleInformation = 64,
    SystemLostDelayedWriteInformation = 65,
    SystemBigPoolInformation = 66,
    SystemSessionPoolTagInformation = 67,
    SystemSessionMappedViewInformation = 68,
    SystemHotpatchInformation = 69,
    SystemObjectSecurityMode = 70,
    SystemWatchdogTimerHandler = 71,
    SystemWatchdogTimerInformation = 72,
    SystemLogicalProcessorInformation = 73,
    SystemWow64SharedInformation = 74,
    SystemRegisterFirmwareTableInformationHandler = 75,
    SystemFirmwareTableInformation = 76,
    SystemModuleInformationEx = 77,
    SystemVerifierTriageInformation = 78,
    SystemSuperfetchInformation = 79,
    SystemMemoryListInformation = 80,
    SystemFileCacheInformationEx = 81,
    MaxSystemInfoClass = 82

} SYSTEM_INFORMATION_CLASS;

extern NTSTATUS ZwQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

//typedef struct _IMAGE_DOS_HEADER_RE {
//    USHORT e_magic;		// Сигнатура заголовка
//    USHORT e_cblp;		// количество байт на последней странице файла
//    USHORT e_cp;		// количество страниц в файле
//    USHORT e_crlc;		// Relocations
//    USHORT e_cparhdr;		// Размер заголовка в параграфах
//    USHORT e_minalloc;		// Минимальные дополнительные параграфы
//    USHORT e_maxalloc;		// Максимальные дополнительные параграфы
//    USHORT e_ss;		// начальное  относительное значение регистра SS
//    USHORT e_sp;		// начальное значение регистра SP
//    USHORT e_csum;		// контрольная сумма
//    USHORT e_ip;		// начальное значение регистра IP
//    USHORT e_cs;		// начальное относительное значение регистра CS
//    USHORT e_lfarlc;		// адрес в файле на таблицу переадресации
//    USHORT e_ovno;		// количество оверлеев
//    USHORT e_res[4];		// Зарезервировано
//    USHORT e_oemid;		// OEM идентифкатор
//    USHORT e_oeminfo;		// OEM информация
//    USHORT e_res2[10];		// Зарезервировано
//    LONG   e_lfanew;		// адрес в файле нового .exe заголовка (PE)
//} IMAGE_DOS_HEADER_RE, * PIMAGE_DOS_HEADER_RE;
//typedef struct _IMAGE_FILE_HEADER
//{
//    USHORT  Machine;
//    USHORT  NumberOfSections;
//    ULONG   TimeDateStamp;
//    ULONG   PointerToSymbolTable;
//    ULONG   NumberOfSymbols;
//    USHORT  SizeOfOptionalHeader;
//    USHORT  Characteristics;
//} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;
//typedef struct _IMAGE_DATA_DIRECTORY {
//    ULONG VirtualAddress;
//    ULONG Size;
//} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;
//typedef struct _IMAGE_OPTIONAL_HEADER {
//    //
//    // стандартные поля
//    //
//
//    USHORT Magic;
//    UCHAR MajorLinkerVersion;
//    UCHAR MinorLinkerVersion;
//    ULONG SizeOfCode;
//    ULONG SizeOfInitializedData;
//    ULONG SizeOfUninitializedData;
//    ULONG AddressOfEntryPoint;
//    ULONG BaseOfCode;
//    ULONG BaseOfData;
//
//    //
//    // NT дополнительные поля.
//    //
//
//    ULONG ImageBase;
//    ULONG SectionAlignment;
//    ULONG FileAlignment;
//    USHORT MajorOperatingSystemVersion;
//    USHORT MinorOperatingSystemVersion;
//    USHORT MajorImageVersion;
//    USHORT MinorImageVersion;
//    USHORT MajorSubsystemVersion;
//    USHORT MinorSubsystemVersion;
//    ULONG Win32VersionValue;
//    ULONG SizeOfImage;
//    ULONG SizeOfHeaders;
//    ULONG CheckSum;
//    USHORT Subsystem;
//    USHORT DllCharacteristics;
//    ULONG SizeOfStackReserve;
//    ULONG SizeOfStackCommit;
//    ULONG SizeOfHeapReserve;
//    ULONG SizeOfHeapCommit;
//    ULONG LoaderFlags;
//    ULONG NumberOfRvaAndSizes;
//    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
//} IMAGE_OPTIONAL_HEADER, * PIMAGE_OPTIONAL_HEADER;
//typedef struct _IMAGE_NT_HEADERS_RE {
//    ULONG Signature;
//    IMAGE_FILE_HEADER FileHeader;
//    IMAGE_OPTIONAL_HEADER OptionalHeader;
//} IMAGE_NT_HEADERS_RE, * PIMAGE_NT_HEADERS_RE;


typedef struct {
    PVOID   Unknown1;
    PVOID   Unknown2;
    PVOID   Base;
    ULONG   Size;
    ULONG   Flags;
    USHORT  Index;
    USHORT  NameLength;
    USHORT  LoadCount;
    USHORT  PathLength;
    CHAR    ImageName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, *PSYSTEM_MODULE_INFORMATION_ENTRY;

NTSTATUS MyEnumKernelModule(IN CHAR* str, OUT PVOID* moduleadd);
VOID ImgBase(IN PVOID lpBase, OUT PULONG pImageBase);

#endif // !_EXPTABLE_H
