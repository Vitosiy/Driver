#ifndef _DUMP_H
#define _DUMP_H

#include <ntddk.h>
#include <intel.h>
#include <stdio.h>


int ShowIDT(char* buf, int index);
int ShowGDT(char* buf, int index);

int ShowCodeSeg(DescriptorCode* des, ULONG index, char* buf, int curSize);
int ShowDataSeg(DescriptorData* des, ULONG index, char* buf, int curSize);
int ShowSystemSeg(DescriptorSystem* des, ULONG index, char* buf, int curSize);
int ShowInterruptEntry(PIDT_ENTRY ent, char* buf, unsigned int curSize);
int getOneInterruptEntry(PIDT_ENTRY ent, char* buf, ULONG offset, char* trapType, unsigned int curSize);
#endif // !_DUMP_H
