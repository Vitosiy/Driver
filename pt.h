/****************************************************************************

    Файл pt.h.

    Заголовочный файл для работы с таблицами страниц.

    Маткин Илья Александрович               29.05.2014

****************************************************************************/

#ifndef _PT_H_
#define _PT_H_


//*************************************************************

/*

                                 расположение                            описываемые адреса
                                                |                   |
                           +-----> 0xC0000000   +-------------------+
                           |                  / | PTE0              | -> 0x00000000 - 0x00000FFF
                           |                 |  +-------------------+
                           |            PT0 <   | ...               | -> 0x00001000 - 0x003FEFFF
                           |                 |  +-------------------+
                           |                  \ | PTE1023           | -> 0x003FF000 - 0x003FFFFF
                           | +---> 0xC0001000   +-------------------+
CR3                        | |                  |                   | -> 0x00400000 - 0xBFFFFFFF
 |                         | |                           ...
 +--+-> +---------------+  | |                  |                   |
    |   | PDE0          | -+ | +-> 0xC0030000   +-------------------+
    |   +---------------+    | |              / | PTE0/PDE0         | -> 0xC0000000 - 0xC0000FFF
    |   | PDE1          | ---+ |             |  +-------------------+
    ^   +---------------+      |             |  | ...               | -> 0xC0001000 - 0xC02FFFFF
    |   | ...           |      |   0xC0030C00|  +-------------------+
    |   +---------------+      |             |  | PTE768/PDE768     | -> 0xC0300000 - 0xC0300FFF
    +---| PDE768        | -----+   PT768/PD <   +-------------------+
        +---------------+                    |  | ...               | -> 0xC0301000 - 0xC03FEFFF
        | ...           |                    |  +-------------------+
        +---------------+                     \ | PTE1023/PDE1023   | -> 0xC03FF000 - 0xC03FFFFF
        | PDE1023       | -+                    +-------------------+
        +---------------+  |                    |                   | -> 0xC0400000 - 0xFFBFFFFF
                           |                             ...
                           |                    |                   |
                           +-----> 0xC03FF000   +-------------------+
                                              / | PTE0              | -> 0xFFC00000 - 0xFFC00FFF
                                             |  +-------------------+
                                     PT1023 <   | ...               | -> 0xFFC01000 - 0xFFFFEFFF
                                             |  +-------------------+
                                              \ | PTE1023           | -> 0xFFFFF000 - 0xFFFFFFFF
                                   0xC0400000   +-------------------+
                                                |                   |



virtual address 4K:

 31      22 21      12 11         0
+----------+----------+------------+
|pde index |pte index |000000000000|
+----------+----------+------------+
\____ ____/ \____ ___/ \_____ ____/
     v           v           v
     10          10          12


virtual address 4M(PSE):

 31      22 21                   0
+----------+----------------------+
|pde index |0000000000000000000000|
+----------+----------------------+
\____ ____/ \_________ __________/
     v                v
     10               22


PT address:

 31      22 21      12 11         0
+----------+----------+------------+
|1100000000|pde index |000000000000|
+----------+----------+------------+
\____ ____/ \____ ___/ \_____ ____/
     v           v           v
     10          10          12


PTE address:

 31      22 21      12 11       2 10
+----------+----------+----------+--+
|1100000000|pde index |pte index |00|
+----------+----------+----------+--+
\____ ____/ \____ ___/ \____ ___/
     v           v          v
     10          10         10


PDE address:

 31      22 21      12 11       2 10
+----------+----------+----------+--+
|1100000000|1100000000|pde index |00|
+----------+----------+----------+--+
\____ ____/ \____ ___/ \____ ___/
     v           v          v
     10          10         10

*/



#define PDE_BASE    0xC0300000
#define PTE_BASE    0xC0000000

// адрес PTE, описывающей PD
#define PD_PTE      0xC0300C00

#define MAX_PDE_INDEX   1024
#define MAX_PTE_INDEX   1024

#define GET_PDE_INDEX_FROM_VA(va)   (((ULONG)va >> 22) & 0x3FF)
#define GET_PTE_INDEX_FROM_VA(va)   (((ULONG)va >> 12) & 0x3FF)
#define GET_VA_FROM_PDE_INDEX_PTE_INDEX(pde,pte)    ((pde << 22) + (pte << 12))

#define GET_PTE_INDEX_FROM_PTE_ADDRESS(pte) (((ULONG)pte >> 2) & 0x3FF)
#define GET_PDE_INDEX_FROM_PTE_ADDRESS(pte) (((ULONG)pte >> 12) & 0x3FF)
#define GET_PDE_INDEX_FROM_PDE_ADDRESS(pde) (((ULONG)pde >> 2) & 0x3FF)

#define GET_PTE_ADDRESS_FROM_PDE_INDEX_PTE_INDEX(pde,pte)   (PTE_BASE + (pde << 12) + (pte << 2))
#define GET_PDE_ADDRESS_FROM_PDE_INDEX(pde) (PDE_BASE + (pde << 2))
#define GET_PDE_ADDRESS_FROM_PTE_ADDRESS(pte)   GET_PDE_ADDRESS_FROM_PDE_INDEX(GET_PTE_INDEX_FROM_PTE_ADDRESS(pte))

#define GET_PDE_ADDRESS_FROM_VA(va)     GET_PDE_ADDRESS_FROM_PDE_INDEX(GET_PDE_INDEX_FROM_VA(va))
#define GET_VA_FROM_PDE_INDEX(pde)      (pde << 22)
#define GET_LAST_VA_FROM_PDE_INDEX(pde) (((pde + 1) << 22) - 1)
#define GET_VA_FROM_PDE_ADDRESS(pde)    GET_VA_FROM_PDE_INDEX(GET_PDE_INDEX_FROM_PDE_ADDRESS(pde))
#define GET_LAST_VA_FROM_PDE_ADDRESS(pde)   GET_LAST_VA_FROM_PDE_INDEX(GET_PDE_INDEX_FROM_PDE_ADDRESS(pde))

#define GET_PTE_ADDRESS_FROM_VA(va) ((((ULONG)va & 0xFFFFF000) >> 10) + PTE_BASE)
#define GET_VA_FROM_PTE_ADDRESS(pte) ((ULONG)pte << 10)
#define GET_LAST_VA_FROM_PTE_ADDRESS(pte) (((((ULONG)pte) + sizeof(PTE)) << 10) - 1)


//*************************************************************


/*

                                                   расположение                            описываемые адреса
                                                                  |                   |
                                           +-------> 0xC0000000   +-------------------+
                                           |                    / | PTE0              | -> 0x00000000 - 0x00000FFF
                                           |                   |  +-------------------+
                                           |              PT0 <   | ...               | -> 0x00001000 - 0x001FEFFF
                                           |                   |  +-------------------+
                                           |                    \ | PTE512            | -> 0x001FF000 - 0x001FFFFF
                                           |         0xC0001000   +-------------------+
                                           |                      |                   |
                                           |                               ...          -> 0x00200000 - 0x3FFFFFFF
                                           |                      |                   |
                                           | +-----> 0xC0200000   +-------------------+
                                           | |                  / | PTE0              | -> 0x40000000 - 0x40000FFF
                                           | |                 |  +-------------------+
           +------^->   +----------------+ | |          PT512 <   | ...               | -> 0x40001000 - 0x401FEFFF
           |      |     | PDE0           | + |                 |  +-------------------+
           |      |     +----------------+   |                  \ | PTE512            | -> 0x401FF000 - 0x401FFFFF
           |      | PD0 | ...            |   |       0xC0201000   +-------------------+
           |      |     +----------------+   |                    |                   |
           |      |     | PDE511         |   |                             ...          -> 0x40200000 - 0x7FFFFFFF
           |      |     +----------------+   |                    |                   |
CR3        |      |                          | +---> 0xC0400000   +-------------------+
|          | +--^--->   +----------------+   | |                / | PTE0              | -> 0x80000000 - 0x00000FFF
|          | |  | |     | PDE0/PDE512    | - + |               |  +-------------------+
V          | |  | |     +----------------+     |       PT1024 <   | ...               | -> 0x80001000 - 0x801FEFFF
+--------+ | |  | | PD1 | ...            |     |               |  +-------------------+
| PDPTE0 | + |  | |     +----------------+     |                \ | PTE512            | -> 0x801FF000 - 0x801FFFFF
+--------+   |  | |     | PDE511/PDE1023 |     |     0xC0401000   +-------------------+
| PDPTE1 | - +  | |     +----------------+     |                  |                   |
+--------+      | |                            |                           ...          -> 0x80200000 - 0xBFFFFFFF
| PDPTE2 | ---^----->   +----------------+     |                  |                   |
+--------+    | | |     | PDE0/PDE1024   | ----+ +-> 0xC0060000   +-------------------+
| PDPTE3 | +  | | |     +----------------+       |              / | PTE0/PDE0         | -> 0xC0000000 - 0xC0000FFF
+--------+ |  | | | PD2 | ...            |       |             |  +-------------------+
           |  | | |     +----------------+       | PT1536/PD0 <   | ...               | -> 0xC0001000 - 0xC01FEFFF
           |  | | |     | PDE511/PDE1535 |       |             |  +-------------------+
           |  | | |     +----------------+       |              \ | PTE511/PDE511     | -> 0xC0300000 - 0xC0300FFF
           |  | | |                              |                +-------------------+
           +^------->   +----------------+       |   0xC0601000   +-------------------+
            | | | +---- | PDE0/PDE1536   | +-----+              / | PTE0/PDE512       | -> 0xC0200000 - 0xC0200FFF
            | | |       +----------------+                     |  +-------------------+
            | | +------ | PDE1/PDE1537   |         PT1537/PD1 <   | ...               | -> 0xC0201000 - 0xC03FEFFF
            | |         +----------------+                     |  +-------------------+
            | +-------- | PDE2/PDE1538   |                      \ | PTE511/PDE1023    | -> 0xC03FF000 - 0xC03FFFFF
            |           +----------------+                        +-------------------+
            +---------- | PDE3/PDE1539   |           0xC0602000   +-------------------+
                        +----------------+                      / | PTE0/PDE1024      | -> 0xC0400000 - 0xC0400FFF
                    PD3 | ...            |                     |  +-------------------+
                        +----------------+         PT1538/PD2 <   | ...               | -> 0xC0401000 - 0xC05FEFFF
                        | PDE511/PDE2047 |                     |  +-------------------+
                        +----------------+                      \ | PTE511/PDE1535    | -> 0xC05FF000 - 0xC05FFFFF
                                                                  +-------------------+
                                                     0xC0603000   +-------------------+
                                                                / | PTE0/PDE1536      | -> 0xC0600000 - 0xC0600FFF
                                                     0xC0603008|  +-------------------+
                                                               |  | PTE1/PDE1537      | -> 0xC0601000 - 0xC0601FFF
                                                     0xC0603010|  +-------------------+
                                                               |  | PTE2/PDE1538      | -> 0xC0602000 - 0xC0602FFF
                                                     0xC0603018|  +-------------------+
                                                               |  | PTE3/PDE1539      | -> 0xC0603000 - 0xC0603FFF
                                                               |  +-------------------+
                                                   PT1539/PD3 <   | ...               | -> 0xC0604000 - 0xC07FEFFF
                                                               |  +-------------------+
                                                                \ | PTE511/PDE2047    | -> 0xC07FF000 - 0xC07FFFFF
                                                                  +-------------------+
                                                                  |                   |
                                                                           ...          -> 0xC0800000 - 0xFFDFFFFF
                                                                  |                   |
                                                     0xC07FF000   +-------------------+
                                                                / | PTE0              | -> 0xFFE00000 + 0xFFE00FFF
                                                               |  +-------------------+
                                                       PT2047 <   | ...               | -> 0xFFE01000 + 0xFFFFEFFF
                                                               |  +-------------------+
                                                                \ | PTE1023           | -> 0xFFFFF000 + 0xFFFFFFFF
                                                     0xC0800000   +-------------------+
                                                                  |                   |



virtual PAE address 4K:

 31    30 29      21 20      12 11         0
+--------+----------+----------+------------+
|pd index|pde index |pte index |000000000000|
+--------+----------+----------+------------+
 \__ ___/ \____ ___/ \____ ___/ \_____ ____/
    v          v          v          v
    2          9          9          12


virtual PAE address 2M:

 31    30 29      21 20                   0
+--------+----------+----------------------+
|pd index|pde index |0000000000000000000000|
+--------+----------+----------------------+
 \__ ___/ \____ ___/ \__________ _________/
    v          v                v
    2          9                21


PAE PT address:

 31     23 22    21 20     12 11         0
+---------+--------+---------+------------+
|110000000|pd index|pde index|000000000000|
+---------+--------+---------+------------+
\____ ___/ \___ __/ \___ ___/ \_____ ____/
     v         v        v           v
     9         2        9           12


PAE PTE address:

 31     23 22    21 20     12 11      3 2 0
+---------+--------+---------+---------+---+
|110000000|pd index|pde index|pte index|000|
+---------+--------+---------+---------+---+
\____ ___/ \___ __/ \___ ___/ \___ ___/ \ /
     v         v        v         v      v
     9         2        9         9      3


PAE PDE address:

 31              14 13    12 11      3 2 0
+------------------+--------+---------+---+
|110000000110000000|pd index|pde index|000|
+------------------+--------+---------+---+
 \________ _______/ \___ __/ \___ ___/ \ /
          v             v        v      v
          18            2        9      2

Можно считать, что pde index = pd index || pde index.
Дальше при конвертации это предполагается.

*/

#define PAE_PDE_BASE    0xC0600000
#define PAE_PD0_BASE    0xC0600000
#define PAE_PD1_BASE    0xC0601000
#define PAE_PD2_BASE    0xC0602000
#define PAE_PD3_BASE    0xC0603000
#define PAE_PTE_BASE    0xC0000000

// адреса PTE, описывающих PD
#define PAE_PD0_PTE     0xC0603000
#define PAE_PD1_PTE     0xC0603008
#define PAE_PD2_PTE     0xC0603010
#define PAE_PD3_PTE     0xC0603018

#define MAX_PAE_PDE_INDEX   2048
#define MAX_PAE_PTE_INDEX   512

#define PAE_PTE_MASK    0x1FF
#define PAE_PDE_MASK    0x7FF

#define GET_PAE_PDE_INDEX_FROM_VA(va)   ((ULONG)va >> 20)
#define GET_PAE_PTE_INDEX_FROM_VA(va)   (((ULONG)va >> 12) & PAE_PTE_MASK)
#define GET_PAE_VA_FROM_PDE_INDEX_PTE_INDEX(pde,pte)    ((pde << 20) + (pte << 12))

#define GET_PAE_PTE_INDEX_FROM_PTE_ADDRESS(pte) (((ULONG)pte >> 3) & PAE_PTE_MASK)
#define GET_PAE_PDE_INDEX_FROM_PTE_ADDRESS(pte) (((ULONG)pte >> 12) & PAE_PDE_MASK)
#define GET_PAE_PDE_INDEX_FROM_PDE_ADDRESS(pde) (((ULONG)pde >> 3) & PAE_PDE_MASK)

#define GET_PAE_PTE_ADDRESS_FROM_PDE_INDEX_PTE_INDEX(pde,pte)   (PAE_PTE_BASE + (pde << 12) + (pte << 3))
#define GET_PAE_PDE_ADDRESS_FROM_PDE_INDEX(pde) (PAE_PDE_BASE + (pde << 3))
#define GET_PAE_PDE_ADDRESS_FROM_PTE_ADDRESS(pte)   GET_PAE_PDE_ADDRESS_FROM_PDE_INDEX(GET_PAE_PTE_INDEX_FROM_PTE_ADDRESS(pte))

#define GET_PAE_PDE_ADDRESS_FROM_VA(va)     GET_PAE_PDE_ADDRESS_FROM_PDE_INDEX(GET_PAE_PDE_INDEX_FROM_VA(va))
#define GET_PAE_VA_FROM_PDE_INDEX(pde)      (pde << 21)
#define GET_PAE_LAST_VA_FROM_PDE_INDEX(pde) (((pde + 1) << 21) - 1)
#define GET_PAE_VA_FROM_PDE_ADDRESS(pde)    GET_PAE_VA_FROM_PDE_INDEX(GET_PAE_PDE_INDEX_FROM_PDE_ADDRESS(pde))
#define GET_PAE_LAST_VA_FROM_PDE_ADDRESS(pde)   GET_PAE_LAST_VA_FROM_PDE_INDEX(GET_PAE_PDE_INDEX_FROM_PDE_ADDRESS(pde))

#define GET_PAE_PTE_ADDRESS_FROM_VA(va) ((((ULONG)va & 0xFFFFF000) >> 9) + PAE_PTE_BASE)
#define GET_PAE_VA_FROM_PTE_ADDRESS(pte) ((ULONG)pte << 9)
#define GET_PAE_LAST_VA_FROM_PTE_ADDRESS(pte) (((((ULONG)pte) + sizeof(PAEPTE)) << 9) - 1)

//*************************************************************

#endif  // _PT_H_
