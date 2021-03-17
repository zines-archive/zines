#define _WIN32_WINNT 0x0600
#define UNICODE

#include <windows.h>
#include <stdio.h>
#include <wchar.h>
#include <stdlib.h>
#include <string.h>


bool
ReadULONG64Line(
	const wchar_t * Line,
	PULONG64 Val,
	wchar_t ** Rest
	)
{
	wchar_t *sep;
	ULONG32 high;
	ULONG32 low;

	while (*Line == L' ')
		Line += 1;

	sep = wcschr((wchar_t*)Line, L'`');

	if (sep != Line + 8)
		return false;

	high = wcstoul(Line, 0, 16);
	low  = wcstoul(sep+1, Rest, 16);

	*Val = ((ULONG64)high << 32) | low;

	return true;
}

#define MEM_SIZE 0x5000  // 4A50 + 48

bool
ParseMemFile(
	FILE *f,
	ULONG64 EncryptedFunc,
	PULONG64 Mem
	)
{
	WCHAR   Line[ 1025 ];
	ULONG   Offset;

	Offset = 0;

	while (fgetws(Line, 1024, f))
	{
		wchar_t *tokctx;
		wchar_t *Rest;
		ULONG64  Addr;
		ULONG64  a;
		ULONG64  b;

		wcstok_s(Line, L"\r\n", &tokctx);

		if (!ReadULONG64Line(Line, &Addr, &Rest))
			continue;
		if (Addr != EncryptedFunc + Offset * sizeof(ULONG64))
			continue;
		if (!ReadULONG64Line(Rest, &a, &Rest))
			continue;
		if (!ReadULONG64Line(Rest, &b, &Rest))
			continue;

		Mem[ Offset++ ] = a;
		Mem[ Offset++ ] = b;

		if (Offset >= MEM_SIZE - 2)
			break;
	}

	if (Offset > 0)
		return true;
	else
		return false;
}

int
__cdecl
wmain(
	int ac,
	wchar_t **av
	)
{
	if (ac != 4)
	{
		wprintf(L"Usage: %s <log> <key> <DeferredContext>\n",
			av[0]);
		return 0;
	}

	FILE* f = _wfopen(av[1], L"rt");

	if (!f)
	{
		wprintf(L"Couldn't open %s\n",
			av[1]);
		return 0;
	}

	ULONG64       DecryptionKey;
	ULONG64       DeferredContext;
	ULONG64       EncryptedFunc;
	ULONG64       DeobfuscateKey;
	const ULONG64 Magic = 0x8513148113148F0; /* Black lump of coal here... */
	ULONG64       Mem[ MEM_SIZE ] = { 0 };
	PUCHAR        Block;
	ULONG         Phase1Count;
	ULONG         i;

	DecryptionKey   = _wcstoui64(av[ 2 ], 0, 16);
	DeferredContext = _wcstoui64(av[ 3 ], 0, 16);

	EncryptedFunc   = (DecryptionKey ^ DeferredContext);

	wprintf(L"EncryptedFunc  : %016I64x\n",
		EncryptedFunc);

	if (!ParseMemFile(
		f,
		EncryptedFunc,
		Mem))
	{
		wprintf(L"Couldn't parse memory out of debugger log...\n");
		return 0;
	}

	fclose(f);

	DeobfuscateKey = Mem[ 0 ] ^ Magic;

	*(PULONG)Mem = 0x113148F0;

//	dumphex((char*)Mem, 256, 4);

	wprintf(L"DeobfuscateKey : %016I64X\n",
		DeobfuscateKey);

	for (i = 0;
		i < 0xa;
		i++)
	{
		Mem[ i ] ^= DeobfuscateKey;
	}

	FILE *out;

	out = _wfopen(L"patchguard_phase0.bin", L"wb");

	if (!out)
	{
		wprintf(L"Couldn't write patchguard_phase0.bin\n");
		return 0;
	}

	*(PULONG)Mem = 0x113148F0; // not real
	fwrite(Mem, sizeof(ULONG64), 0x48, out);
	fclose(out);

	Block       = (PUCHAR)Mem;
	Phase1Count = *(PULONG)(Block + 0x4C);

	if (Phase1Count * 8 + 0x48 > MEM_SIZE)
	{
		wprintf(L"Phase1Count is too long! (%lu)\n",
			Phase1Count);
		return 0;
	}

	for (i = Phase1Count;
		 i;
		 i -= 1)
	{
		*(PULONG64)(Block + 0x48 + 8*i) ^= DeobfuscateKey;
		DeobfuscateKey = _rotr64(DeobfuscateKey, (UCHAR)i);
	}

	out = _wfopen(L"patchguard_phase1.bin", L"wb");

	if (!out)
	{
		wprintf(L"Couldn't write patchguard_phase1.bin\n");
		return 0;
	}

	fwrite(Block, 0x48 + 8 * Phase1Count, 1, out);
	fclose(out);

	wprintf(L"Starting offset = %08X\n",
		*(PULONG)(Block + 0x208));

	/*

00000004: 48315108                     xor         [rcx][8],rdx
00000008: 48315110                     xor         [rcx][010],rdx
0000000C: 48315118                     xor         [rcx][018],rdx
00000010: 48315120                     xor         [rcx][020],rdx
00000014: 48315128                     xor         [rcx][028],rdx
00000018: 48315130                     xor         [rcx][030],rdx
0000001C: 48315138                     xor         [rcx][038],rdx
00000020: 48315140                     xor         [rcx][040],rdx
00000024: 48315148                     xor         [rcx][048],rdx
00000028: 3111                         xor         [rcx],edx
0000002A: 488BC2                       mov         rax,rdx
0000002D: 488BD1                       mov         rdx,rcx
00000030: 8B4A4C                       mov         ecx,[rdx][04C]
00000033: 483144CA48                  1xor         [rdx][rcx]*8[048],rax
00000038: 48D3C8                       ror         rax,cl
0000003B: E2F6                         loop        000000033 --1
0000003D: 8B8208020000                 mov         eax,[rdx][000000208]
00000043: 4803C2                       add         rax,rdx
00000046: FFE0                         jmp         rax
00000048: 66666690                     nop
*/

	return 0;
}
