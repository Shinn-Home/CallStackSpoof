#include "Spoof.h"

typedef struct _SYSTEM_MODULE_ENTRY
{
#ifdef _WIN64
	ULONGLONG Unknown1;
	ULONGLONG Unknown2;
#else
	ULONG Unknown1;
	ULONG Unknown2;
#endif
	PVOID BaseAddress;
	ULONG Size;
	ULONG Flags;
	ULONG EntryIndex;
	USHORT NameLength;  // Length of module name not including the path, this field contains valid value only for NTOSKRNL module
	USHORT PathLength;  // Length of 'directory path' part of modulename
#ifdef _KERNEL_MODE
	CHAR Name[MAXIMUM_FILENAME_LENGTH];
#else
	CHAR Name[256];
#endif
} SYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG Count;
#ifdef _WIN64
	ULONG Unknown1;
#endif
	SYSTEM_MODULE_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS 
{
	SystemModuleInformation = 0xB,
} SYSTEM_INFORMATION_CLASS;

EXTERN_C 
__kernel_entry 
NTSTATUS 
ZwQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength
);

static ULONG64 g_XorKey = 0;

ULONG64 g_Trampoline = 0ull;

UCHAR spoof_callstack_shellcode[] =
{
	// 1. '动态'获取密钥并异或返回地址
	0x4C, 0x8B, 0x1D, 0xC1, 0x1F, 0x00, 0x00,  // mov     r11, cs:g_XorKey (RIP相对寻址)
	0x4C, 0x31, 0x1C, 0x24,                    // xor     [rsp+0], r11

	// 2. 保存非易失性寄存器
	0x56,                                      // push    rsi
	0x57,                                      // push    rdi

	// 3. 提升栈空间 0x300
	0x48, 0x81, 0xEC, 0x00, 0x03, 0x00, 0x00,  // sub     rsp, 300h

	// 4. 设置内存拷贝的源和目标地址
	0x48, 0x8D, 0xB4, 0x24, 0x40, 0x03, 0x00, 0x00, // lea   rsi, [rsp + 340h]
	0x48, 0x8D, 0x7C, 0x24, 0x20,              // lea     rdi, [rsp + 20h]

	// 5. 暂存 rcx 并执行内存拷贝 (rep movsq)
	0x4C, 0x8B, 0xD1,                          // mov     r10, rcx
	0xB9, 0x40, 0x00, 0x00, 0x00,              // mov     ecx, 40h
	0xF3, 0x48, 0xA5,                          // rep     movsq
	0x49, 0x8B, 0xCA,                          // mov     rcx, r10

	// 6. 调用目标函数
	0xFF, 0x94, 0x24, 0x38, 0x03, 0x00, 0x00,  // call    [rsp + 338h]

	// 7. 恢复栈空间和寄存器
	0x48, 0x81, 0xC4, 0x00, 0x03, 0x00, 0x00,  // add     rsp, 300h
	0x5F,                                      // pop     rdi
	0x5E,                                      // pop     rsi

	// 8. '动态'获取密钥并还原返回地址
	0x4C, 0x8B, 0x1D, 0x82, 0x1F, 0x00, 0x00,  // mov     r11, cs:g_XorKey
	0x4C, 0x31, 0x1C, 0x24,                    // xor     [rsp+0], r11

	// 9. 函数返回
	0xC3                                       // retn
};

VOID WriteKernelMem(PUCHAR DestAddr, PUCHAR Buffer, ULONG Size)
{
	do
	{
		if (0 == Size)
		{
			break;
		}

		if (!MmIsAddressValid(DestAddr) || !MmIsAddressValid(DestAddr + Size - 1))
		{
			break;
		}

		if (!MmIsAddressValid(Buffer) || !MmIsAddressValid(Buffer + Size - 1))
		{
			break;
		}

		PHYSICAL_ADDRESS PhyAddr = MmGetPhysicalAddress(DestAddr);
		if (0 == PhyAddr.QuadPart)
		{
			break;
		}

		PUCHAR MapAddr = (PUCHAR)MmMapIoSpace(PhyAddr, Size, MmNonCached);
		if (NULL == MapAddr)
		{
			break;
		}

		__movsb(MapAddr, Buffer, Size);

		MmUnmapIoSpace(MapAddr, Size);
	} while (FALSE);
}

PVOID SearchModuleSpacce(PVOID ModuleBase, ULONG ModuleSize, ULONG ShellCodeSize)
{
	PVOID RetSpace = NULL;

	do 
	{
		if (NULL == ModuleSize || 0 == ModuleSize || 0 == ShellCodeSize)
		{
			break;
		}

		PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)ModuleBase;
		if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
			break;
		}

		PIMAGE_NT_HEADERS64 NtHeader = (PIMAGE_NT_HEADERS64)((PUCHAR)ModuleBase + DosHeader->e_lfanew);
		if (NtHeader->Signature != IMAGE_NT_SIGNATURE)
		{
			break;
		}

		PUCHAR CmpBuf = (PUCHAR)ExAllocatePoolWithTag(NonPagedPoolNx, ShellCodeSize, 'empt');
		if (NULL == CmpBuf)
		{
			break;
		}
		else
		{
			RtlZeroMemory(CmpBuf, ShellCodeSize);
		}

		PIMAGE_SECTION_HEADER SectionHeader = IMAGE_FIRST_SECTION(NtHeader);
		for (size_t i = 0; i < NtHeader->FileHeader.NumberOfSections; i++)
		{
			if (_strnicmp((const char*)SectionHeader[i].Name, ".text", 5) != 0)
			{
				continue;
			}

			ULONG SectionRva = SectionHeader[i].VirtualAddress;
			ULONG SectionSize = SectionHeader[i].Misc.VirtualSize;
			for (size_t j = 0; j < SectionSize; j++)
			{
				PUCHAR Cur = (PUCHAR)ModuleBase + SectionRva + j;
				if (RtlCompareMemory(Cur, CmpBuf, ShellCodeSize) == ShellCodeSize)
				{
					RetSpace = Cur;
					break;
				}

			}

		}

		ExFreePoolWithTag(CmpBuf, 'empt');

	} while (FALSE);

	return RetSpace;
}

// 完善后的内核空间查找函数
PVOID SearchKernelSpace(ULONG ShellCodeSize)
{
	PVOID RetSpace = NULL;

	// Irql Check
	if (KeGetCurrentIrql() > PASSIVE_LEVEL) 
	{
		return NULL;
	}

	ULONG BufSize = 0;
	NTSTATUS Status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &BufSize);
	if (Status != STATUS_INFO_LENGTH_MISMATCH) 
	{
		return NULL;
	}

	// 增加冗余量
	BufSize += 1024;

	// 使用 NonPagedPoolNx (无执行权限) 存储元数据
	SYSTEM_MODULE_INFORMATION* InfoBuf = (SYSTEM_MODULE_INFORMATION*)ExAllocatePoolWithTag(NonPagedPoolNx, BufSize, 'mod');
	if (NULL == InfoBuf)
	{
		return NULL;
	}

	Status = ZwQuerySystemInformation(SystemModuleInformation, InfoBuf, BufSize, &BufSize);
	if (!NT_SUCCESS(Status)) 
	{
		ExFreePoolWithTag(InfoBuf, 'mod');
		return NULL;
	}

	for (ULONG i = 0; i < InfoBuf->Count; i++) 
	{
		SYSTEM_MODULE_ENTRY* ModEntry = &InfoBuf->Module[i];
		const char* ImageName = (const char*)ModEntry->Name;
		if (_strnicmp(ImageName, "ntoskrnl.exe", 12) == 0 ||
			_strnicmp(ImageName, "hal.dll", 7) == 0 ||
			_strnicmp(ImageName, "win32k.sys", 10) == 0 ||
			_strnicmp(ImageName, "win32kfull.sys", 14) == 0)
		{
			continue;
		}

#ifdef _DEBUG
		DbgPrint("ImageName = %s. \n", ImageName);
#endif // _DEBUG

		// 搜索0x00的填充区
		PVOID TmpAddr = SearchModuleSpacce(ModEntry->BaseAddress, ModEntry->Size, ShellCodeSize);
		if (NULL != TmpAddr)
		{
			UINT_PTR Start = (UINT_PTR)TmpAddr;
			UINT_PTR End = Start + ShellCodeSize - 1;

			// 检查跨页
			if ((Start >> PAGE_SHIFT) == (End >> PAGE_SHIFT)) 
			{
				RetSpace = TmpAddr;
				break;
			}

		}
	}

	// Free buf
	if (InfoBuf) 
	{
		ExFreePoolWithTag(InfoBuf, 'mod');
	}

#ifdef _DEBUG
	DbgPrint("RetSpace = 0x%p. \n", RetSpace);
#endif // _DEBUG

	return RetSpace;
}

BOOLEAN InitSpoof(ULONG64 XorKey)
{
	g_Trampoline = (ULONG64)SearchKernelSpace(sizeof(SPOOF_SHELLCODE_TEMPLATE));
	if (NULL == g_Trampoline)
	{
		return FALSE;
	}

	g_XorKey = XorKey;

	LONG Reloc_1 = (LONG)((ULONG_PTR)&g_XorKey - (g_Trampoline + OFFSET(SPOOF_SHELLCODE_TEMPLATE, pad_1)));
	LONG Reloc_2 = (LONG)((ULONG_PTR)&g_XorKey - (g_Trampoline + OFFSET(SPOOF_SHELLCODE_TEMPLATE, pad_2)));
	SPOOF_SHELLCODE_TEMPLATE* pShellCode = (SPOOF_SHELLCODE_TEMPLATE*)spoof_callstack_shellcode;
	pShellCode->first_xor_key_offset = Reloc_1;
	pShellCode->second_xor_key_offset = Reloc_2;

	WriteKernelMem((PUCHAR)g_Trampoline, (PUCHAR)pShellCode, sizeof(SPOOF_SHELLCODE_TEMPLATE));

	return TRUE;
}