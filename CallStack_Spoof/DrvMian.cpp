#include "Spoof.h"

// 非易失寄存器：Rbx、Rbp、Rsp、Rdi、Rsi、R12~R15，使用这些寄存器一定要遵循保存、使用、恢复
// 易失寄存器：Rcx、Rdx、R8~R11等等

ULONG64 TestFunc2(
	ULONG64 Arg1, 
	ULONG64 Arg2, 
	ULONG64 Arg3, 
	ULONG64 Arg4, 
	ULONG64 Arg5,
	ULONG64 Arg6, 
	ULONG64 Arg7, 
	ULONG64 Arg8,
	ULONG64 Arg9,
	ULONG64 Arg10,
	ULONG64 Arg11,
	ULONG64 Arg12)
{
	DbgPrint("%llX  %llX  %llX  %llX  %llX  %llX  %llX  %llX  %llX  %llX  %llX  %llX. \n", Arg1, Arg2, Arg3, Arg4, Arg5, Arg6, Arg7, Arg8, Arg9, Arg10, Arg11, Arg12);
	DbgBreakPoint();
	return Arg1 + Arg2 + Arg3 + Arg4 + Arg5 + Arg6 + Arg7 + Arg8 + Arg9 + Arg10 + Arg11 + Arg12;
}

EXTERN_C
NTSTATUS 
DriverEntry(
	PDRIVER_OBJECT pDrvObj,
	PUNICODE_STRING pRegPath)
{
	DbgBreakPoint();

	if (InitSpoof(0xF0F0F0F0F0F0F0F0ull))
	{
		UNICODE_STRING device_name = { 0 };
		PDEVICE_OBJECT pdev_obj = NULL;
		ULONG64 RetValue = 0;
		RetValue = STACK_SPOOF(TestFunc2, (ULONG64)pDrvObj, (ULONG64)pRegPath, (ULONG64)&device_name, (ULONG64)&device_name, pDrvObj, pDrvObj, &pdev_obj, &pdev_obj, 0x999ull, 0x1010ull, 0x1111ull, 0x1212ull);
		DbgPrint("RetValue = %llX. \n", RetValue);
	}

	return STATUS_UNSUCCESSFUL;
}