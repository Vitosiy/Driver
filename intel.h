/****************************************************************************

    Файл intel.h

    Определения аппаратных структур данных процессоров архитектуры IA32.

    Маткин Илья Александрович               сентябрь 2007

****************************************************************************/

#ifndef	_INTEL_H_
#define _INTEL_H_

typedef unsigned long   ULONG;
typedef unsigned char   UCHAR;
typedef unsigned short  USHORT;

//*****************************************************************************
// Сегменты

#define MAKE_SELECTOR(index, RPL)   ((index << 3) + RPL)

#pragma pack(1)
typedef struct _Selector {			// Селектор
    USHORT	RPL : 2;
    USHORT	Tl : 1;
    USHORT	Index : 13;
} Selector, * PSelector;
#pragma pack()

#define TL_GLOBAL	0
#define TL_LOCAL	1



#pragma pack(1)
typedef struct _DescriptorCode {		// дескриптор кода

    USHORT	LimitLow;				// нижняя часть лимита (0-15)
    USHORT	BaseLow;				// нижняя часть базы (0-15)
    UCHAR	BaseMedium;				// средняя часть базы (16-23)
    union _ARB_CODE {				// байт управления доступом

        UCHAR	SecurityByte;		// обращаемся сразу ко всем битам
                                    // обращение ко всем полям в отдельности
        struct	_SecurityByteDetail_CODE {
            UCHAR	A : 1;			// обращение к сегменту
            UCHAR	R : 1;			// разрешение (1) или запрет (0) чтения сегмента
            UCHAR	C : 1;			// подчинённый (1) или неподчинённый (0)
            UCHAR	CodeOrData : 1;	// код (1) или данные (0)
            UCHAR	SystemOrUser : 1;	// системный (0) или пользовательский (1)
            UCHAR	DPL : 2;			// уровень привилегий
            UCHAR	P : 1;			// присутствие в памяти
        };

    };
    UCHAR	LimitHigh : 4;			// старшая часть предела (16-19)
    UCHAR	AVL : 1;
    UCHAR	Zero : 1;
    UCHAR	D : 1;					// разрядность по умолчанию: 16(0) или 32(1)
    UCHAR	G : 1;					// бит гранулярности: байты(0) или страницы(1)
    UCHAR	BaseHigh;				// верняя часть базы (24-31)

} DescriptorCode, * PDescriptorCode;
#pragma pack()



#pragma pack(1)
typedef struct _DescriptorData {		// дескриптор данных и стека

    USHORT	LimitLow;				// нижняя часть лимита (0-15)
    USHORT	BaseLow;				// нижняя часть базы (0-15)
    UCHAR	BaseMedium;				// средняя часть базы (16-23)
    union _ARB_DATA {						// байт управления доступом

        UCHAR	SecurityByte;		// обращаемся сразу ко всем битам
                                    // обращение ко всем полям в отдельности
        struct	_SecurityByteDetail_DATA {
            UCHAR	A : 1;			// обращение к сегменту
            UCHAR	W : 1;			// разрешение (1) или запрет (0) записи
            UCHAR	E : 1;			// расширение вверх (0) или расширение вниз (1)
            UCHAR	CodeOrData : 1;	// код (1) или данные (0)
            UCHAR	SystemOrUser : 1;	// системный (0) или пользовательский (1)
            UCHAR	DPL : 2;			// уровень привилегий
            UCHAR	P : 1;			// присутствие в памяти
        };

    };

    UCHAR	LimitHigh : 4;			// старшая часть предела (16-19)
    UCHAR	AVL : 1;
    UCHAR	Zero : 1;
    UCHAR	B : 1;					// разрядность верхней границы(+указателя стека): 16(0) или 32(1)
    UCHAR	G : 1;					// бит гранулярности
    UCHAR	BaseHigh;				// верняя часть базы (24-31)

} DescriptorData, * PDescriptorData;
#pragma pack()



#pragma pack(1)
typedef struct _DescriptorSystem {	// системный дескриптор (LDT, TSS)

    USHORT	LimitLow;				// нижняя часть лимита (0-15)
    USHORT	BaseLow;				// нижняя часть базы (0-15)
    UCHAR	BaseMedium;				// средняя часть базы (16-23)
    union _ARB_SYSTEM {						// байт управления доступом

        UCHAR	SecurityByte;		// обращаемся сразу ко всем битам
                                    // обращение ко всем полям в отдельности
        struct	_SecurityByteDetail_SYSTEM {
            UCHAR	Type : 4;			// тип системного дескриптора
            UCHAR	SystemOrUser : 1;	// системный (0) или пользовательский (1)
            UCHAR	DPL : 2;			// уровень привилегий
            UCHAR	P : 1;			// присутствие в памяти
        };

    };

    UCHAR	LimitHigh : 4;			// старшая часть предела (16-19)
    UCHAR	Zero : 3;
    UCHAR	G : 1;					// бит гранулярности
    UCHAR	BaseHigh;				// верняя часть базы (24-31)

} DescriptorSystem, * PDescriptorSystem;
#pragma pack()



#pragma pack(1)
typedef struct _DescriptorGate {		// дескриптор шлюза

    USHORT	DestinationOffsetLow;	// адрес назначения (0-15)
    USHORT	DestinationSelector;	// селектор назначения (0-15)
    UCHAR	WordCount;				// (5 бит) число параметров(слов) вызова(только для шлюзов вызова)
    union _ARB_GATE {						// байт управления доступом

        UCHAR	SecurityByte;		// обращаемся сразу ко всем битам
                                    // обращение ко всем полям в отдельности
        struct	_SecurityByteDetail_GATE {
            UCHAR	Type : 4;			// тип системного дескриптора
            UCHAR	SystemOrUser : 1;	// системный (0) или пользовательский (1)
            UCHAR	DPL : 2;			// уровень привилегий
            UCHAR	P : 1;			// присутствие в памяти
        };

    };

    USHORT	DestinationOffsetHigh;	// адрес назначения (16-31)

} DescriptorGate, * PDescriptorGate;
#pragma pack()



#pragma pack(1)
typedef struct Descriptor {			// Дескриптор

    union {
        struct {
            USHORT	LimitLow;				// нижняя часть лимита (0-15)
            USHORT	BaseLow;				// нижняя часть базы (0-15)
            UCHAR	BaseMedium;				// средняя часть базы (16-23)
            union {				// байт управления доступом

                UCHAR	SecurityByte;		// обращение сразу ко всем битам
                                            // обращение ко всем полям в отдельности
                struct {
                    UCHAR   NA : 4;
                    UCHAR	SystemOrUser : 1;	// системный (0) или пользовательский (1)
                    UCHAR	DPL : 2;			// уровень привилегий
                    UCHAR	P : 1;			// присутствие в памяти
                } SecurityByteDetail;

            };
            UCHAR	LimitAndBits;			// старшая часть предела (16-19) и биты управления
            UCHAR	BaseHigh;				// верняя часть базы (24-31)
        };
        DescriptorCode Code;
        DescriptorData Data;
        DescriptorSystem System;
        DescriptorGate Gate;
    };

} Descriptor, * PDescriptor;
#pragma pack()



// битовые поля дескрипторов

#define	CODE_OR_DATA	1	// значение бита CodeOrData для сегмента кода
#define DATA_OR_CODE	0	// значение бита CodeOrData для сегмента данных
#define SYSTEM_OR_USER	0	// значение бита SystemOrUser для системного сегмента
#define	USER_OR_SYSTEM	1	// значение бита SystemOrUser для пользовательского сегмента
#define	C_COMF			1	// значение бита С для подчинённого сегмента кода
#define C_NOCOMF		0	// значение бита С для неподчинённого сегмента кода
#define R_READ			1	// чтение сегмента кода разрешено
#define R_NOREAD		0	// чтение сегмента кода запрещено
#define	W_WRITE			1	// запись в сегмент данных разрешена
#define W_NOWRITE		0	// запись в сегмент данных запрещена
#define E_STACK			1	// расширение вниз для стека
#define E_DATA			0	// разширение вверх для данных
#define PRESENT			1<<7


// типы шлюзов

#define	TYPE_CALLGATE_286		4
#define	TYPE_TASKGATE			5
#define	TYPE_INTERRUPTGATE_286	6
#define	TYPE_TRAPGATE_286		7
#define	TYPE_CALLGATE_386		12
#define TYPE_GATE_RESERVED		13
#define	TYPE_INTERRUPTGATE		14
#define	TYPE_TRAPGATE_386		15


// типы системных дескрипторов

#define	TYPE_AVAILABLE_TSS_286	1	// свободный TSS-286
#define	TYPE_LDT				2	// LDT
#define	TYPE_BUZY_TSS_286		3	// занятый TSS-286
#define	TYPE_AVAILABLE_TSS_386	9	// свободный TSS-386
#define	TYPE_RESERVED			10	// зарезервировано
#define	TYPE_BUZY_TSS_386		11	// занятый TSS-386


// Константы для SecurityByte

#define	DATA_SEGMENT_READ_0		(USER_OR_SYSTEM<<4) | PRESENT
#define DATA_SEGMENT_READ_3		DATA_SEGMENT_READ_0 | (3<<5)
#define DATA_SEGMENT_WRITE_0	(USER_OR_SYSTEM<<4) | (W_WRITE<<1) | PRESENT	
#define DATA_SEGMENT_WRITE_3	DATA_SEGMENT_WRITE_0 | (3<<5)
#define STACK_SEGMENT_0			(USER_OR_SYSTEM<<4) | (E_STACK<<2) | PRESENT
#define STACK_SEGMENT_3			STACK_SEGMENT_0 | (3<<5)
#define	CODE_SEGMENT_NOREAD_0	(USER_OR_SYSTEM<<4) | (CODE_OR_DATA<<3) | PRESENT
#define CODE_SEGMENT_NOREAD_3	CODE_SEGMENT_NOREAD_0 | (3<<5)
#define CODE_SEGMENT_READ_0		(USER_OR_SYSTEM<<4) | (CODE_OR_DATA<<3) | (R_READ<<1) | PRESENT
#define CODE_SEGMENT_READ_3		CODE_SEGMENT_READ_0 | (3<<5)
#define	SYSTEM_SEGMENT_0		PRESENT
#define SYSTEM_SEGMENT_3		SYSTEM_SEGMENT_0 | (3<<5)



#pragma pack(1)
typedef struct _TSS {			// Формат TSS

    USHORT	Link;			// 0h
    USHORT	Null1;			// 2h
    ULONG	ESP0;			// 4h
    USHORT	SS0;			// 8h
    USHORT	Null2;			// 0Ah
    ULONG	ESP1;			// 0Ch
    USHORT	SS1;			// 10h
    USHORT	Null3;			// 12h
    ULONG	ESP2;			// 14h
    USHORT	SS2;			// 18h
    USHORT	Null4;			// 1Ah

    ULONG	CR3;			// 1Ch
    ULONG	EIP;			// 20h
    ULONG	EFLAGS;			// 24h
    ULONG	EAX;			// 28h
    ULONG	ECX;			// 2Ch
    ULONG	EDX;			// 30h
    ULONG	EBX;			// 34h
    ULONG	ESP;			// 38h
    ULONG	EBP;			// 3Ch
    ULONG	ESI;			// 40h
    ULONG	EDI;			// 44h

    USHORT	ES;				// 48h
    USHORT	Null5;			// 4Ah
    USHORT	CS;				// 4Ch
    USHORT	Null6;			// 4Eh
    USHORT	SS;				// 50h
    USHORT	Null7;			// 52h
    USHORT	DS;				// 54h
    USHORT	Null8;			// 56h
    USHORT	FS;				// 58h
    USHORT	Null9;			// 5Ah
    USHORT	GS;				// 5Ch
    USHORT	Null10;			// 5Eh
    USHORT	LDTR;			// 60h
    USHORT	Null11;			// 62h

    USHORT	Null12;			// 64h
    USHORT	BitMapOffset;	// 66h
} TSS, * PTSS;
#pragma pack()


//*****************************************************************************
// Страницы


#pragma pack(1)
typedef struct _PTE {

    ULONG P : 1;				// бит присутствия
    ULONG R_W : 1;			// бит разрешения записи
    ULONG U_S : 1;			// бит разрешения доступа пользователя
    ULONG PWT : 1;			// бит управления кэшированием
    ULONG PCD : 1;			// бит управления кэшированием
    ULONG A : 1;				// бит доступа к странице
    ULONG D : 1;				// бит изменения страницы
    ULONG PATi : 1;			// бит управления кэшированием страницы
    ULONG G : 1;				// бит глобальности страницы
    ULONG Used : 3;			// доступно
    ULONG Address : 20;		// физический адрес страницы(старшие 20 бит)

} PTE, * PPTE;
#pragma pack()



#pragma pack(1)
typedef struct _PDE {

    ULONG P : 1;				// бит присутствия
    ULONG R_W : 1;			// бит разрешения записи
    ULONG U_S : 1;			// бит разрешения доступа пользователя
    ULONG PWT : 1;			// биты управления кэшированием
    ULONG PCD : 1;
    ULONG A : 1;				// бит доступа к каталогу
    ULONG Zero1 : 1;			// бит D
    ULONG PS : 1;				// бит расширения размера страницы:4к(0) или 2/4М(1)
    ULONG G : 1;				// бит глобальности
    ULONG Used : 3;
    ULONG Address : 20;		// физический адрес таблицы страниц

} PDE, * PPDE;
#pragma pack()


/*
                    PDE

        31              12 11        9  8   7   6   5   4   3   2   1   0
        ___________________________________________________________________
        |                 |   |   |   |   |   |   |   | P | P | U | R |   |
        | Адрес таблицы   |  Доступны | G | P | 0 | A | C | W | / | / | P |
        |                 |           |   | S |   |   | D | T | S | W |   |
        -------------------------------------------------------------------


                    PTE

        31              12 11        9  8   7   6   5   4   3   2   1   0
        ___________________________________________________________________
        |                 |   |   |   |   | P |   |   | P | P | U | R |   |
        | Адрес страницы  |  Доступны | G | A | D | A | C | W | / | / | P |
        |                 |           |   | Ti|   |   | D | T | S | W |   |
        -------------------------------------------------------------------

*/



#pragma pack(1)
typedef struct _PSE32 {		// 4М страницы PSE 32-разрядные

    ULONG P : 1;				// бит присутствия
    ULONG R_W : 1;			// бит разрешения записи
    ULONG U_S : 1;			// бит разрешения доступа пользователя
    ULONG PWT : 1;			// биты управления кэшированием
    ULONG PCD : 1;
    ULONG A : 1;				// бит доступа
    ULONG D : 1;				// бит записи
    ULONG PS : 1;				// бит расширения размера страницы:4к(0) или 4М(1)
    ULONG G : 1;				// бит глобальности
    ULONG Used : 3;
    ULONG PATi : 1;
    ULONG Zero : 9;
    ULONG Address : 20;		// физический адрес каталога страниц

} PSE32, * PPSE32;
#pragma pack()



#pragma pack(1)
typedef struct _PSE36 {		// 4М страницы PSE 36-разрядные

    ULONG P : 1;				// бит присутствия
    ULONG R_W : 1;			// бит разрешения записи
    ULONG U_S : 1;			// бит разрешения доступа пользователя
    ULONG PWT : 1;			// биты управления кэшированием
    ULONG PCD : 1;
    ULONG A : 1;				// бит доступа
    ULONG D : 1;				// бит записи
    ULONG PS : 1;				// бит расширения размера страницы:4к(0) или 4М(1)
    ULONG G : 1;				// бит глобальности
    ULONG Used : 3;
    ULONG PATi : 1;
    ULONG HighAddress : 4;	// старшие 4 бита адреса (33-36)
    ULONG Zero : 5;
    ULONG Address : 20;		// физический адрес каталога страниц

} PSE36, * PPSE36;
#pragma pack()



/*
                    PSE-32

        31              22 21    17 16    13  12 11        9  8   7   6   5   4   3   2   1   0
        _________________________________________________________________________________________
        |                 |                 | P |   |   |   |   | PC|   |   | P | P | U | R |   |
        | Адрес таблицы   |      Резерв     | A |  Доступны | G | = | D | A | C | W | / | / | P |
        |   (PA-1)        |                 | Ti|           |   | 1 |   |   | D | T | S | W |   |
        -----------------------------------------------------------------------------------------


                    PSE-36

        31              22 21    17 16    13  12 11        9  8   7   6   5   4   3   2   1   0
        _________________________________________________________________________________________
        |                 |        |        | P |   |   |   |   | PC|   |   | P | P | U | R |   |
        | Адрес таблицы   | Резерв | Адрес  | A |  Доступны | G | = | D | A | C | W | / | / | P |
        |   (PA-1)        |        | (PA-2) | Ti|           |   | 1 |   |   | D | T | S | W |   |
        -----------------------------------------------------------------------------------------

*/



#pragma pack(1)
typedef struct _PAEPDPTE {		// указатель на каталог страниц

    ULONG P : 1;
    ULONG Zero1 : 2;
    ULONG PWT : 1;
    ULONG PCD : 1;
    ULONG Zero2 : 4;
    ULONG Used : 3;
    ULONG Address : 20;
    ULONG HighAddress : 4;
    ULONG Zero3 : 28;

} PAEPDPTE, * PPAEPDPTE;
#pragma pack()



#pragma pack(1)
typedef struct _PAEPDE4K {	// 4k PDE каталоги PAE

    ULONG P : 1;				// бит присутствия
    ULONG R_W : 1;			// бит разрешения записи
    ULONG U_S : 1;			// бит разрешения доступа пользователя
    ULONG PWT : 1;			// биты управления кэшированием
    ULONG PCD : 1;
    ULONG A : 1;				// бит доступа
    ULONG D : 1;				// бит записи
    ULONG PS : 1;				// бит расширения размера страницы:4к(0) или 2/4М(1)
    ULONG Zero1 : 1;
    ULONG Used : 3;			// Доступно
    ULONG Address : 20;		// физический адрес каталога страниц
    ULONG HighAddress : 4;	// старшие 4 бита адреса (33-36)
    ULONG Zero : 28;

} PAEPDE, * PPAEPDE, PAEPDE4K, * PPAEPDE4K;
#pragma pack()



#pragma pack(1)
typedef struct _PAEPDE2M {	// 2M PDE каталоги PAE

    ULONG P : 1;				// бит присутствия
    ULONG R_W : 1;			// бит разрешения записи
    ULONG U_S : 1;			// бит разрешения доступа пользователя
    ULONG PWT : 1;			// биты управления кэшированием
    ULONG PCD : 1;
    ULONG A : 1;				// бит доступа
    ULONG D : 1;				// бит записи
    ULONG PS : 1;				// бит расширения размера страницы:4к(0) или 2/4М(1)
    ULONG G : 1;
    ULONG Used : 3;			// Доступно
    ULONG PATi : 1;			// бит управления кэшированием
    ULONG Zero2 : 8;
    ULONG Address : 11;		// физический адрес каталога страниц
    ULONG HighAddress : 4;	// старшие 4 бита адреса (33-36)
    ULONG Zero : 28;

} PAEPDE2M, * PPAEPDE2M;
#pragma pack()



#pragma pack(1)
typedef struct _PAEPTE4K {	// 4k PTE страницы PAE

    ULONG P : 1;				// бит присутствия
    ULONG R_W : 1;			// бит разрешения записи
    ULONG U_S : 1;			// бит разрешения доступа пользователя
    ULONG PWT : 1;			// биты управления кэшированием
    ULONG PCD : 1;
    ULONG A : 1;				// бит доступа
    ULONG D : 1;				// бит записи
    ULONG PATi : 1;				// бит расширения размера страницы:4к(0) или 2/4М(1)
    ULONG G : 1;
    ULONG Used : 3;			// Доступно
    ULONG Address : 20;		// физический адрес каталога страниц
    ULONG HighAddress : 4;	// старшие 4 бита адреса (33-36)
    ULONG Zero : 28;

} PAEPTE, * PPAEPTE, PAEPTE4K, * PPAEPTE4K;
#pragma pack()


//*****************************************************************************
// Регистры


#pragma pack(1)
typedef struct _CR0 {		// регистр CR0

    ULONG PE : 1;				// разрешение защиты(переход в защищённый режим)
    ULONG MP : 1;				// мониторинг сопроцессора
    ULONG EM : 1;				// эмуляция сопроцессора
    ULONG TS : 1;				// флаг переключения задачи, устанавливается автоматически
    ULONG ET : 1;				// индикатор поддержки инструкция мат.сопроцессора
    ULONG NE : 1;				// разрешения сообщения об ошибке FPU через генерацию исключения
    ULONG Zero1 : 10;
    ULONG WP : 1;				// разрешение защиты страниц памяти
    ULONG Zero2 : 1;
    ULONG AM : 1;				// разрешение контроля выравнивания
    ULONG Zero3 : 10;
    ULONG NW : 1;				// запрет сквозной записи кэша и циклов анулирования
    ULONG CD : 1;				// запрет заполнения кэша
    ULONG PG : 1;				// включение страничной переадресации памяти

} CR0, * PCR0;
#pragma pack()



#pragma pack(1)
typedef struct _CR4 {	// регистр CR4

    ULONG VME : 1;		// разрешение использования виртуального флага прерываний в режиме V86
    ULONG PVI : 1;		// разрешение использования виртуального флага прерываний в защищённом режиме
    ULONG TSD : 1;		// превращение инструкции RDTSC в привилегированную
    ULONG DE : 1;			// расширение возможностей отладки(точки останова на обращение к заданным портам)
    ULONG PSE : 1;		// расширение размера страницы
    ULONG PAE : 1;		// расширение физического адреса
    ULONG MCE : 1;		// разрешение машинного контроля
    ULONG PGE : 1;		// разрешение глобальности в страничной переадресации
    ULONG PCE : 1;		// разрешение обращения к счётчикам событий (RDPMC) на любом уровне привилегий
    ULONG OSFXSR : 1;		// флаг использования инструкций FXSAVE/FXRSTOR	для быстрого сохранения и восстановления состояния FPU/MMX
    ULONG OSXMMEXCPT : 1;	// флаг поддержки ОС исключений от блока XMM
    ULONG Zero : 21;

} CR4, * PCR4;
#pragma pack()



/*

            CR0

        0              7 8            15 16           23 24            31
        +_______+_______+_______+_______+_______+_______+_______+_______+
        |P|M|E|T|E|N| | | | | | | | | | |W| |A| | | | | | | | | | |N|C|P|
        |E|P|M|S|T|E| | | | | | | | | | |P| |M| | | | | | | | | | |W|D|G|
        +-------+-------+-------+-------+-------+-------+-------+-------+
        \--------------\/--------------/
                      MSW


            CR4

        0              7 8            15 16           23 24            31
        +_______+_______+_______+_______+_______+_______+_______+_______+
        | | | | | | | | | | |O| | | | | | | | | | | | | | | | | | | | | |
        | | | | | | | | | | |S| | | | | | | | | | | | | | | | | | | | | |
        | | | | | | | | | |O|X| | | | | | | | | | | | | | | | | | | | | |
        |V|P|T|D|P|P|M|P|P|S|M| | | | | | | | | | | | | | | | | | | | | |
        |M|V|S|E|S|A|C|G|C|F|M| | | | | | | | | | | | | | | | | | | | | |
        |E|I|D| |E|E|E|E|E|X|E| | | | | | | | | | | | | | | | | | | | | |
        | | | | | | | | | |S|X| | | | | | | | | | | | | | | | | | | | | |
        | | | | | | | | | |R|C| | | | | | | | | | | | | | | | | | | | | |
        | | | | | | | | | | |P| | | | | | | | | | | | | | | | | | | | | |
        | | | | | | | | | | |T| | | | | | | | | | | | | | | | | | | | | |
        +-------+-------+-------+-------+-------+-------+-------+-------+


*/


#pragma pack(1)
typedef struct _DTR {

    USHORT	Limit;
    ULONG	Base;

} GDTR, IDTR, * PGDTR, * PIDTR;
#pragma pack()



#pragma pack(1)
typedef struct _EFLAGS {

    ULONG CF : 1;				// флаг переноса(заёма)
    ULONG : 1;
    ULONG PF : 1;				// флаг паритета (чётность)
    ULONG : 1;
    ULONG AF : 1;				// флаг дополнительного переноса(заёма) в тетраде для десятичной арифметики
    ULONG : 1;
    ULONG ZF : 1;				// флаг нулевого результата
    ULONG SF : 1;				// флаг знака
    ULONG TF : 1;				// флаг трассировки
    ULONG IF : 1;				// управление прерываниями
    ULONG DF : 1;				// флаг управления направления в строковых операциях
    ULONG OF : 1;				// флаг переполнения
    ULONG IOPL : 1;			// уровень привилегий ввода/вывода			
    ULONG NT : 1;				// флаг вложенносит задачи
    ULONG : 1;
    ULONG RF : 1;				// флаг возобновления
    ULONG VM : 1;				// режим виртуального процессора 8086
    ULONG AC : 1;				// контроль выравнивания (для 3 кольца)
    ULONG VIF : 1;			// виртуальная версия флага IF
    ULONG VIP : 1;			// виртуальный запрос прерывания
    ULONG ID : 1;				// флаг доступности команды идентификации CPUID
    ULONG : 10;

} EFLAGS, * PEFLAGS;
#pragma pack()


/*

            EFLAGS

        0              7 8             15 16           23 24            31
        +_______+_______+_______+________+_______+_______+_______+_______+
        | | | | | | | | | | | | | |  | | | | | |V|V| | | | | | | | | | | |
        |C|1|P|0|A|0|Z|S|T|I|D|O|IOPL|N|0|R|V|A|I|I|I|0|0|0|0|0|0|0|0|0|0|
        |F| |F| |F| |F|F|F|F|F|F|    |T| |F|M|C|F|P|D| | | | | | | | | | |
        +-------+-------+-------+--------+-------+-------+-------+-------+


*/

#pragma pack(1)
typedef struct _IDT_ENTRY {

    USHORT offsetLow; // offset bits 0..15
    USHORT selector; // a code segment selector in GDT or LDT
    UCHAR zero;      // unused, set to 0
    //UCHAR type_attr; // type and attributes, see below
    UCHAR type : 4;
    UCHAR S : 1;
    UCHAR DPL : 2;
    UCHAR P : 1;
    USHORT offsetHigh; // offset bits 16..31

} IDT_ENTRY, * PIDT_ENTRY;
#pragma pack()


#endif  // _INTEL_H_
