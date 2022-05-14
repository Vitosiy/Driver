#include "dump.h"


int ShowIDT(char* buf, int index) {
	IDTR idtr;
	ULONG i;
	ULONG intCount;
	PIDT_ENTRY idt;
	unsigned int curSize = 0;
	char indexFlag = index ? 1 : 0;

	__asm { sidt idtr }

	intCount = (idtr.Limit + 1) / sizeof(IDT_ENTRY);
	idt = (PIDT_ENTRY)(idtr.Base);

	curSize = sprintf(buf, "IDT (0x%08X) contains %d rows\n", idtr.Base, intCount);

	for (i = index; i < intCount; ++i) {
		if (!idt[i].P) {
			if (!indexFlag) {
				continue;
			}
			else {
				break;
			}
		}
		//curSize += sprintf(buf, "Index: 0x%X", i);
		curSize += ShowInterruptEntry(&idt[i], buf, curSize);

		if (indexFlag) {
			break;
		}

	}
	DbgPrint(buf);
	return curSize;
}

int ShowGDT(char* buf, int index) {
	GDTR gdtr;
	ULONG i;
	ULONG segCount;
	Descriptor* gdt;
	int curSize = 0;
	char indexFlag = index ? 1 : 0;

	__asm {sgdt gdtr}

	segCount = (gdtr.Limit + 1) / sizeof(Descriptor);
	gdt = (Descriptor*)gdtr.Base;

	curSize = sprintf(buf, "GDT (0x%08X) contains %d rows\n", gdtr.Base, segCount);

	for (i = index; i < segCount; ++i) {
		if (!gdt[i].SecurityByteDetail.P) {
			if (!indexFlag) {
				continue;
			}
			else {
				break;
			}
		}

		if (gdt[i].SecurityByteDetail.SystemOrUser) {
			if (gdt[i].Data.CodeOrData) {
				curSize += ShowCodeSeg(&gdt[i].Code, i, buf, curSize);
			}
			else {
				curSize += ShowDataSeg(&gdt[i].Data, i, buf, curSize);
			}
		}
		else {
			curSize += ShowSystemSeg(&gdt[i].System, i, buf, curSize);
		}

		if (indexFlag) {
			break;
		}
	}

	DbgPrint(buf);
	return curSize;
}

int ShowCodeSeg(DescriptorCode* des, ULONG index, char* buf, int curSize) {

	ULONG base = des->BaseLow + (des->BaseMedium << 16) + (des->BaseHigh << 24);
	ULONG limit = des->LimitLow + (des->LimitHigh << 16);

	return sprintf(buf + curSize, "\n\tindex: %d selector: %02x\n\tbase: %08x  limit: %08x\n\tA: %d  R: %d  P: %d  C: %d  DPL: %d  type: C%s\n",
		index,
		MAKE_SELECTOR(index, des->DPL),
		base,
		base + (des->G ? (limit << 12) + 0xFFF : limit),
		des->A,
		des->R,
		des->P,
		des->C,
		des->DPL,
		des->D ? "32" : "16");
}

int ShowDataSeg(DescriptorData* des, ULONG index, char* buf, int curSize) {

	ULONG base = des->BaseLow + (des->BaseMedium << 16) + (des->BaseHigh << 24);
	ULONG limit = des->LimitLow + (des->LimitHigh << 16);

	return sprintf(buf + curSize, "\n\tindex: %d,  selector: %02x\n\tbase: %08x  limit: %08x\n\tA: %d  W: %d  P: %d  E: %d  DPL: %d  type: D%s\n",
		index,
		MAKE_SELECTOR(index, des->DPL),
		base,
		base + (des->G ? (limit << 12) + 0xFFF : limit),
		des->A,
		des->W,
		des->P,
		des->E,
		des->DPL,
		des->B ? "32" : "16");
}

int ShowSystemSeg(DescriptorSystem* des, ULONG index, char* buf, int curSize) {

	ULONG base = des->BaseLow + (des->BaseMedium << 16) + (des->BaseHigh << 24);
	ULONG limit = des->LimitLow + (des->LimitHigh << 16);

	switch (des->Type) {
	case TYPE_AVAILABLE_TSS_286:
	case TYPE_BUZY_TSS_286:
	case TYPE_AVAILABLE_TSS_386:
	case TYPE_BUZY_TSS_386:
		return sprintf(buf + curSize, "\n\tindex: %d,  selector: %02x\n\tbase: %08x  limit: %08x\n\tP: %d  DPL: %d  type: TSS\n",
			index,
			MAKE_SELECTOR(index, des->DPL),
			base,
			des->G ? (limit << 12) + 0xFFFF : limit,
			des->P,
			des->DPL);
		break;
	case TYPE_LDT:
		return sprintf(buf + curSize, "\n\tindex: %d,  selector: %02x\n\tbase: %08x  limit: %08x\n\tDPL: %d  type: LDT\n",
			index,
			MAKE_SELECTOR(index, des->DPL),
			base,
			des->G ? (limit << 12) + 0xFFFF : limit,
			des->DPL);
		break;
	case TYPE_CALLGATE_286:
	case TYPE_TASKGATE:
	case TYPE_INTERRUPTGATE_286:
	case TYPE_TRAPGATE_286:
	case TYPE_CALLGATE_386:
	case TYPE_GATE_RESERVED:
	case TYPE_INTERRUPTGATE:
	case TYPE_TRAPGATE_386:
	{
		DescriptorGate* gate = (DescriptorGate*)des;
		ULONG offset = gate->DestinationOffsetLow + (gate->DestinationOffsetHigh << 16);
		return sprintf(buf + curSize, "\n\tselector: %02x   dstssel: %02x\n\toffset: %08x   DPL: %d   type: gate\n",
			MAKE_SELECTOR(index, des->DPL),
			gate->DestinationSelector,
			offset,
			gate->DPL);
	}
	break;
	}

	return 0;
}

int ShowInterruptEntry(PIDT_ENTRY ent, char* buf, unsigned int curSize) {

	ULONG offset = (ent->offsetLow) + (ent->offsetHigh << 16);

	switch (ent->type) {

	case TYPE_CALLGATE_286:
		return getOneInterruptEntry(ent, buf, offset, "80286 16 bit call gate", curSize);
	case TYPE_TASKGATE:
		return getOneInterruptEntry(ent, buf, offset, "80386 32 bit task gate", curSize);
	case TYPE_INTERRUPTGATE_286:
		return getOneInterruptEntry(ent, buf, offset, "80286 16-bit interrupt gate", curSize);
	case TYPE_TRAPGATE_286:
		return getOneInterruptEntry(ent, buf, offset, "80286 16-bit trap gate", curSize);
	case TYPE_GATE_RESERVED:
		return getOneInterruptEntry(ent, buf, offset, "reserved gate", curSize);
	case TYPE_CALLGATE_386:
		return getOneInterruptEntry(ent, buf, offset, "80386 32-bit call gate", curSize);
	case TYPE_INTERRUPTGATE:
		return getOneInterruptEntry(ent, buf, offset, "80386 32-bit interrupt gate", curSize);
	case TYPE_TRAPGATE_386:
		return getOneInterruptEntry(ent, buf, offset, "80386 32-bit trap gate", curSize);
	default:
		return getOneInterruptEntry(ent, buf, offset, "unknown", curSize);
	}
	return 0;
}

int getOneInterruptEntry(PIDT_ENTRY ent, char* buf, ULONG offset, char* trapType, unsigned int curSize) {

	//DbgPrint("buf + curSize: %d\n", buf + curSize);
	//DbgPrint("Offset: %d\n", offset);
	//DbgPrint("present: %d\n", ent->P);
	//DbgPrint("DPL: %d\n", ent->DPL);
	//DbgPrint("Storage Segment: %d\n", ent->S);
	//DbgPrint("Type: %s\n", trapType);
	//DbgPrint("Selector: %d\n", ent->selector);

	return sprintf(buf + curSize,
		"\n\tOffset: 0x%08X p: %d DPL: %d Storage Segment: %d\n\t"
		"Type: %s Selector: 0x%X\n", offset, ent->P,
		ent->DPL, ent->S, trapType, ent->selector);
}
