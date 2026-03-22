#pragma once
#include <ntddk.h>
#include <ntimage.h>

// 动态修复结构体
#pragma pack(push, 1)
typedef struct _SPOOF_SHELLCODE_TEMPLATE 
{
	UCHAR  mov_r11_opcode[3];      // mov r11, xxx
	LONG32 first_xor_key_offset;
	UCHAR  pad_1[56];
	UCHAR  mov_r11_opcode_2[3];    // mov r11, xxx
	LONG32 second_xor_key_offset;
	UCHAR  pad_2[5];
} SPOOF_SHELLCODE_TEMPLATE, *PSPOOF_SHELLCODE_TEMPLATE;
#pragma pack(pop)

#define OFFSET(type, field) ((ULONG_PTR)(&((type*)0)->field))

EXTERN_C ULONG64 g_Trampoline;

BOOLEAN InitSpoof(ULONG64 XorKey);

template<
	typename RetType = ULONG64,
	typename... Args,
	typename T1 = ULONG64,
	typename T2 = ULONG64,
	typename T3 = ULONG64,
	typename T4 = ULONG64>
	RetType __SpoofStub(const PVOID Func, T1 A1 = { }, T2 A2 = { }, T3 A3 = { }, T4 A4 = { }, Args... Arguments)
{
	return reinterpret_cast<RetType(*)(T1, T2, T3, T4, PVOID, Args...)>((PVOID)g_Trampoline)(A1, A2, A3, A4, Func, Arguments...);
}

template <class Ret, class... Args>
Ret GetRetType(Ret(*)(Args...));

#define STACK_SPOOF(Func, ...) __SpoofStub<decltype(GetRetType(Func))>(Func, __VA_ARGS__)