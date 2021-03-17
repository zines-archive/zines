                        .586p
                        .model  flat, stdcall
                        locals
                        jumps
                        
include                 c:\tasm32\include\shitheap.inc
include                 fake_k32.inc
include                 ring0.inc
extrn                   C       _imp__wsprintfA:dword
wsprintfA               equ     _imp__wsprintfA

                        .data
szkernel32              db      "kernel32.dll", 0
old_dll_base            dd      ?

                        .code
public C start
start                   proc
                        arg     imagebase
                        arg     reason
                        arg     reserved
                        
                        pusha                       
                        cmp     reason, 1
                        jne     __e_dllinit
                        
                        mov     eax, dword ptr fs:[30h]
                        mov     eax, [eax+0ch]
                        mov     esi, [eax+0ch]

                        call    LoadLibraryA, offset szkernel32
                        mov     old_dll_base, eax
                        xchg    eax, ebx
                        
__find_dll:             cmp     [esi.lm_baseaddress], ebx
                        je      __esiedi
                        lodsd
                        xchg    eax, esi
                        jmp     __find_dll                        
                        
__esiedi:               cmp     ebx, imagebase
                        je      __hook
                        mov     edi, esi
                        mov     ebx, imagebase
                        jmp     __find_dll        

__hook:                 mov     eax, ebx
                        xchg    eax, [edi.lm_baseaddress]
                        mov     [esi.lm_baseaddress], eax
                        
                        add     ebx, [ebx+3ch]
                        mov     eax, [ebx.pe_addressofentrypoint]
                        add     eax, imagebase
                        xchg    eax, [edi.lm_entrypoint]
                        mov     [esi.lm_entrypoint], eax

                        mov     eax, [ebx.pe_sizeofimage]
                        xchg    eax, [edi.lm_sizeofimage]
                        mov     [esi.lm_sizeofimage], eax

__e_dllinit:            popa
                        mov     eax, 1
                        leave
                        retn    0ch
                        endp
                        
public my_ActivateActCtx
my_ActivateActCtx:
                        jmp     ActivateActCtx
                        retn


public my_AddAtomA
my_AddAtomA:
                        jmp     AddAtomA
                        retn


public my_AddAtomW
my_AddAtomW:
                        jmp     AddAtomW
                        retn


public my_AddConsoleAliasA
my_AddConsoleAliasA:
                        jmp     AddConsoleAliasA
                        retn


public my_AddConsoleAliasW
my_AddConsoleAliasW:
                        jmp     AddConsoleAliasW
                        retn


public my_AddLocalAlternateComputerNameA
my_AddLocalAlternateComputerNameA:
                        jmp     AddLocalAlternateComputerNameA
                        retn


public my_AddLocalAlternateComputerNameW
my_AddLocalAlternateComputerNameW:
                        jmp     AddLocalAlternateComputerNameW
                        retn


public my_AddRefActCtx
my_AddRefActCtx:
                        jmp     AddRefActCtx
                        retn


public my_AddVectoredExceptionHandler
my_AddVectoredExceptionHandler:
                        jmp     AddVectoredExceptionHandler
                        retn


public my_AllocConsole
my_AllocConsole:
                        jmp     AllocConsole
                        retn


public my_AllocateUserPhysicalPages
my_AllocateUserPhysicalPages:
                        jmp     AllocateUserPhysicalPages
                        retn


public my_AreFileApisANSI
my_AreFileApisANSI:
                        jmp     AreFileApisANSI
                        retn


public my_AssignProcessToJobObject
my_AssignProcessToJobObject:
                        jmp     AssignProcessToJobObject
                        retn


public my_AttachConsole
my_AttachConsole:
                        jmp     AttachConsole
                        retn


public my_BackupRead
my_BackupRead:
                        jmp     BackupRead
                        retn


public my_BackupSeek
my_BackupSeek:
                        jmp     BackupSeek
                        retn


public my_BackupWrite
my_BackupWrite:
                        jmp     BackupWrite
                        retn


public my_BaseCheckAppcompatCache
my_BaseCheckAppcompatCache:
                        jmp     BaseCheckAppcompatCache
                        retn


public my_BaseCleanupAppcompatCache
my_BaseCleanupAppcompatCache:
                        jmp     BaseCleanupAppcompatCache
                        retn


public my_BaseCleanupAppcompatCacheSupport
my_BaseCleanupAppcompatCacheSupport:
                        jmp     BaseCleanupAppcompatCacheSupport
                        retn


public my_BaseDumpAppcompatCache
my_BaseDumpAppcompatCache:
                        jmp     BaseDumpAppcompatCache
                        retn


public my_BaseFlushAppcompatCache
my_BaseFlushAppcompatCache:
                        jmp     BaseFlushAppcompatCache
                        retn


public my_BaseInitAppcompatCache
my_BaseInitAppcompatCache:
                        jmp     BaseInitAppcompatCache
                        retn


public my_BaseInitAppcompatCacheSupport
my_BaseInitAppcompatCacheSupport:
                        jmp     BaseInitAppcompatCacheSupport
                        retn


public my_BaseProcessInitPostImport
my_BaseProcessInitPostImport:
                        jmp     BaseProcessInitPostImport
                        retn


public my_BaseQueryModuleData
my_BaseQueryModuleData:
                        jmp     BaseQueryModuleData
                        retn


public my_BaseUpdateAppcompatCache
my_BaseUpdateAppcompatCache:
                        jmp     BaseUpdateAppcompatCache
                        retn


public my_BasepCheckWinSaferRestrictions
my_BasepCheckWinSaferRestrictions:
                        jmp     BasepCheckWinSaferRestrictions
                        retn


public my_Beep
my_Beep:
                        jmp     Beep
                        retn


public my_BeginUpdateResourceA
my_BeginUpdateResourceA:
                        jmp     BeginUpdateResourceA
                        retn


public my_BeginUpdateResourceW
my_BeginUpdateResourceW:
                        jmp     BeginUpdateResourceW
                        retn


public my_BindIoCompletionCallback
my_BindIoCompletionCallback:
                        jmp     BindIoCompletionCallback
                        retn


public my_BuildCommDCBA
my_BuildCommDCBA:
                        jmp     BuildCommDCBA
                        retn


public my_BuildCommDCBAndTimeoutsA
my_BuildCommDCBAndTimeoutsA:
                        jmp     BuildCommDCBAndTimeoutsA
                        retn


public my_BuildCommDCBAndTimeoutsW
my_BuildCommDCBAndTimeoutsW:
                        jmp     BuildCommDCBAndTimeoutsW
                        retn


public my_BuildCommDCBW
my_BuildCommDCBW:
                        jmp     BuildCommDCBW
                        retn


public my_CallNamedPipeA
my_CallNamedPipeA:
                        jmp     CallNamedPipeA
                        retn


public my_CallNamedPipeW
my_CallNamedPipeW:
                        jmp     CallNamedPipeW
                        retn


public my_CancelDeviceWakeupRequest
my_CancelDeviceWakeupRequest:
                        jmp     CancelDeviceWakeupRequest
                        retn


public my_CancelIo
my_CancelIo:
                        jmp     CancelIo
                        retn


public my_CancelTimerQueueTimer
my_CancelTimerQueueTimer:
                        jmp     CancelTimerQueueTimer
                        retn


public my_CancelWaitableTimer
my_CancelWaitableTimer:
                        jmp     CancelWaitableTimer
                        retn


public my_ChangeTimerQueueTimer
my_ChangeTimerQueueTimer:
                        jmp     ChangeTimerQueueTimer
                        retn


public my_CheckNameLegalDOS8Dot3A
my_CheckNameLegalDOS8Dot3A:
                        jmp     CheckNameLegalDOS8Dot3A
                        retn


public my_CheckNameLegalDOS8Dot3W
my_CheckNameLegalDOS8Dot3W:
                        jmp     CheckNameLegalDOS8Dot3W
                        retn


public my_CheckRemoteDebuggerPresent
my_CheckRemoteDebuggerPresent:
                        jmp     CheckRemoteDebuggerPresent
                        retn


public my_ClearCommBreak
my_ClearCommBreak:
                        jmp     ClearCommBreak
                        retn


public my_ClearCommError
my_ClearCommError:
                        jmp     ClearCommError
                        retn


public my_CloseConsoleHandle
my_CloseConsoleHandle:
                        jmp     CloseConsoleHandle
                        retn


public my_CloseHandle
my_CloseHandle:
                        jmp     CloseHandle
                        retn


public my_CloseProfileUserMapping
my_CloseProfileUserMapping:
                        jmp     CloseProfileUserMapping
                        retn


public my_CmdBatNotification
my_CmdBatNotification:
                        jmp     CmdBatNotification
                        retn


public my_CommConfigDialogA
my_CommConfigDialogA:
                        jmp     CommConfigDialogA
                        retn


public my_CommConfigDialogW
my_CommConfigDialogW:
                        jmp     CommConfigDialogW
                        retn


public my_CompareFileTime
my_CompareFileTime:
                        jmp     CompareFileTime
                        retn


public my_CompareStringA
my_CompareStringA:
                        jmp     CompareStringA
                        retn


public my_CompareStringW
my_CompareStringW:
                        jmp     CompareStringW
                        retn


public my_ConnectNamedPipe
my_ConnectNamedPipe:
                        jmp     ConnectNamedPipe
                        retn


public my_ConsoleMenuControl
my_ConsoleMenuControl:
                        jmp     ConsoleMenuControl
                        retn


public my_ContinueDebugEvent
my_ContinueDebugEvent:
                        jmp     ContinueDebugEvent
                        retn


public my_ConvertDefaultLocale
my_ConvertDefaultLocale:
                        jmp     ConvertDefaultLocale
                        retn


public my_ConvertFiberToThread
my_ConvertFiberToThread:
                        jmp     ConvertFiberToThread
                        retn


public my_ConvertThreadToFiber
my_ConvertThreadToFiber:
                        jmp     ConvertThreadToFiber
                        retn


public my_CopyFileA
my_CopyFileA:
                        jmp     CopyFileA
                        retn


public my_CopyFileExA
my_CopyFileExA:
                        jmp     CopyFileExA
                        retn


public my_CopyFileExW
my_CopyFileExW:
                        jmp     CopyFileExW
                        retn


public my_CopyFileW
my_CopyFileW:
                        jmp     CopyFileW
                        retn


public my_CopyLZFile
my_CopyLZFile:
                        jmp     CopyLZFile
                        retn


public my_CreateActCtxA
my_CreateActCtxA:
                        jmp     CreateActCtxA
                        retn


public my_CreateActCtxW
my_CreateActCtxW:
                        jmp     CreateActCtxW
                        retn


public my_CreateConsoleScreenBuffer
my_CreateConsoleScreenBuffer:
                        jmp     CreateConsoleScreenBuffer
                        retn


public my_CreateDirectoryA
my_CreateDirectoryA:
                        jmp     CreateDirectoryA
                        retn


public my_CreateDirectoryExA
my_CreateDirectoryExA:
                        jmp     CreateDirectoryExA
                        retn


public my_CreateDirectoryExW
my_CreateDirectoryExW:
                        jmp     CreateDirectoryExW
                        retn


public my_CreateDirectoryW
my_CreateDirectoryW:
                        jmp     CreateDirectoryW
                        retn


public my_CreateEventA
my_CreateEventA:
                        jmp     CreateEventA
                        retn


public my_CreateEventW
my_CreateEventW:
                        jmp     CreateEventW
                        retn


public my_CreateFiber
my_CreateFiber:
                        jmp     CreateFiber
                        retn


public my_CreateFiberEx
my_CreateFiberEx:
                        jmp     CreateFiberEx
                        retn


formatcfa               db      "opening : %s", 0
fakek32dll              db      "c:\fake_k32.dll", 0
errorcfa                db      "opening : 0 passed as file name", 0
public my_CreateFileA
my_CreateFileA:         pusha
                        mov     esi, [esp+24h]                   
                        test    esi, esi
                        jz      __err_cfa     
                        call    wsprintfA, offset buffer, offset formatcfa, esi
                        add     esp, 0ch
                        call    OutputDebugStringA, offset buffer               
__cycle:                cmp     dword ptr[esi], 'NREK'
                        je      __hookdll
                        lodsb
                        test    al, al
                        jnz     __cycle
                        popa
                        jmp     CreateFileA
                        
__hookdll:              mov     dword ptr[esp+24h], offset fakek32dll                        
__e_cfa:                popa
                        jmp     CreateFileA
                        retn

__err_cfa:              call    OutputDebugStringA, offset errorcfa
                        jmp     __e_cfa

public my_CreateFileMappingA
my_CreateFileMappingA:
                        jmp     CreateFileMappingA
                        retn


public my_CreateFileMappingW
my_CreateFileMappingW:
                        jmp     CreateFileMappingW
                        retn


public my_CreateFileW
my_CreateFileW:
                        jmp     CreateFileW
                        retn


public my_CreateHardLinkA
my_CreateHardLinkA:
                        jmp     CreateHardLinkA
                        retn


public my_CreateHardLinkW
my_CreateHardLinkW:
                        jmp     CreateHardLinkW
                        retn


public my_CreateIoCompletionPort
my_CreateIoCompletionPort:
                        jmp     CreateIoCompletionPort
                        retn


public my_CreateJobObjectA
my_CreateJobObjectA:
                        jmp     CreateJobObjectA
                        retn


public my_CreateJobObjectW
my_CreateJobObjectW:
                        jmp     CreateJobObjectW
                        retn


public my_CreateJobSet
my_CreateJobSet:
                        jmp     CreateJobSet
                        retn


public my_CreateMailslotA
my_CreateMailslotA:
                        jmp     CreateMailslotA
                        retn


public my_CreateMailslotW
my_CreateMailslotW:
                        jmp     CreateMailslotW
                        retn


public my_CreateMemoryResourceNotification
my_CreateMemoryResourceNotification:
                        jmp     CreateMemoryResourceNotification
                        retn


public my_CreateMutexA
my_CreateMutexA:
                        jmp     CreateMutexA
                        retn


public my_CreateMutexW
my_CreateMutexW:
                        jmp     CreateMutexW
                        retn


public my_CreateNamedPipeA
my_CreateNamedPipeA:
                        jmp     CreateNamedPipeA
                        retn


public my_CreateNamedPipeW
my_CreateNamedPipeW:
                        jmp     CreateNamedPipeW
                        retn


public my_CreateNlsSecurityDescriptor
my_CreateNlsSecurityDescriptor:
                        jmp     CreateNlsSecurityDescriptor
                        retn


public my_CreatePipe
my_CreatePipe:
                        jmp     CreatePipe
                        retn


public my_CreateProcessA
my_CreateProcessA:
                        jmp     CreateProcessA
                        retn


public my_CreateProcessInternalA
my_CreateProcessInternalA:
                        jmp     CreateProcessInternalA
                        retn


public my_CreateProcessInternalW
my_CreateProcessInternalW:
                        jmp     CreateProcessInternalW
                        retn


public my_CreateProcessInternalWSecure
my_CreateProcessInternalWSecure:
                        jmp     CreateProcessInternalWSecure
                        retn


public my_CreateProcessW
my_CreateProcessW:
                        jmp     CreateProcessW
                        retn


public my_CreateRemoteThread
my_CreateRemoteThread:
                        jmp     CreateRemoteThread
                        retn


public my_CreateSemaphoreA
my_CreateSemaphoreA:
                        jmp     CreateSemaphoreA
                        retn


public my_CreateSemaphoreW
my_CreateSemaphoreW:
                        jmp     CreateSemaphoreW
                        retn


public my_CreateSocketHandle
my_CreateSocketHandle:
                        jmp     CreateSocketHandle
                        retn


public my_CreateTapePartition
my_CreateTapePartition:
                        jmp     CreateTapePartition
                        retn

ctcalled                db      "CreateThread called", 0
public my_CreateThread
my_CreateThread:
                        pusha
                        call    OutputDebugStringA, offset ctcalled
                        popa
                        jmp     CreateThread
                        retn


public my_CreateTimerQueue
my_CreateTimerQueue:
                        jmp     CreateTimerQueue
                        retn


public my_CreateTimerQueueTimer
my_CreateTimerQueueTimer:
                        jmp     CreateTimerQueueTimer
                        retn


public my_CreateToolhelp32Snapshot
my_CreateToolhelp32Snapshot:
                        jmp     CreateToolhelp32Snapshot
                        retn


public my_CreateVirtualBuffer
my_CreateVirtualBuffer:
                        jmp     CreateVirtualBuffer
                        retn


public my_CreateWaitableTimerA
my_CreateWaitableTimerA:
                        jmp     CreateWaitableTimerA
                        retn


public my_CreateWaitableTimerW
my_CreateWaitableTimerW:
                        jmp     CreateWaitableTimerW
                        retn


public my_DeactivateActCtx
my_DeactivateActCtx:
                        jmp     DeactivateActCtx
                        retn


public my_DebugActiveProcess
my_DebugActiveProcess:
                        jmp     DebugActiveProcess
                        retn


public my_DebugActiveProcessStop
my_DebugActiveProcessStop:
                        jmp     DebugActiveProcessStop
                        retn


public my_DebugBreak
my_DebugBreak:
                        jmp     DebugBreak
                        retn


public my_DebugBreakProcess
my_DebugBreakProcess:
                        jmp     DebugBreakProcess
                        retn


public my_DebugSetProcessKillOnExit
my_DebugSetProcessKillOnExit:
                        jmp     DebugSetProcessKillOnExit
                        retn


public my_DecodePointer
my_DecodePointer:
                        jmp     DecodePointer
                        retn


public my_DecodeSystemPointer
my_DecodeSystemPointer:
                        jmp     DecodeSystemPointer
                        retn


public my_DefineDosDeviceA
my_DefineDosDeviceA:
                        jmp     DefineDosDeviceA
                        retn


public my_DefineDosDeviceW
my_DefineDosDeviceW:
                        jmp     DefineDosDeviceW
                        retn


public my_DelayLoadFailureHook
my_DelayLoadFailureHook:
                        jmp     DelayLoadFailureHook
                        retn


public my_DeleteAtom
my_DeleteAtom:
                        jmp     DeleteAtom
                        retn


public my_DeleteCriticalSection
my_DeleteCriticalSection:
                        jmp     DeleteCriticalSection
                        retn


public my_DeleteFiber
my_DeleteFiber:
                        jmp     DeleteFiber
                        retn


public my_DeleteFileA
my_DeleteFileA:
                        jmp     DeleteFileA
                        retn


public my_DeleteFileW
my_DeleteFileW:
                        jmp     DeleteFileW
                        retn


public my_DeleteTimerQueue
my_DeleteTimerQueue:
                        jmp     DeleteTimerQueue
                        retn


public my_DeleteTimerQueueEx
my_DeleteTimerQueueEx:
                        jmp     DeleteTimerQueueEx
                        retn


public my_DeleteTimerQueueTimer
my_DeleteTimerQueueTimer:
                        jmp     DeleteTimerQueueTimer
                        retn


public my_DeleteVolumeMountPointA
my_DeleteVolumeMountPointA:
                        jmp     DeleteVolumeMountPointA
                        retn


public my_DeleteVolumeMountPointW
my_DeleteVolumeMountPointW:
                        jmp     DeleteVolumeMountPointW
                        retn

formatdioc              db      "IOCTL code : 0x%.08X", 0
public my_DeviceIoControl
my_DeviceIoControl:     
                        pusha
                        mov     esi, [esp+28h]
                        call    wsprintfA, offset buffer, offset formatdioc, esi
                        add     esp, 0ch
                        call    OutputDebugStringA, offset buffer
                        popa
                        jmp     DeviceIoControl
                        retn


public my_DisableThreadLibraryCalls
my_DisableThreadLibraryCalls:
                        jmp     DisableThreadLibraryCalls
                        retn


public my_DisconnectNamedPipe
my_DisconnectNamedPipe:
                        jmp     DisconnectNamedPipe
                        retn


public my_DnsHostnameToComputerNameA
my_DnsHostnameToComputerNameA:
                        jmp     DnsHostnameToComputerNameA
                        retn


public my_DnsHostnameToComputerNameW
my_DnsHostnameToComputerNameW:
                        jmp     DnsHostnameToComputerNameW
                        retn


public my_DosDateTimeToFileTime
my_DosDateTimeToFileTime:
                        jmp     DosDateTimeToFileTime
                        retn


public my_DosPathToSessionPathA
my_DosPathToSessionPathA:
                        jmp     DosPathToSessionPathA
                        retn


public my_DosPathToSessionPathW
my_DosPathToSessionPathW:
                        jmp     DosPathToSessionPathW
                        retn


public my_DuplicateConsoleHandle
my_DuplicateConsoleHandle:
                        jmp     DuplicateConsoleHandle
                        retn


public my_DuplicateHandle
my_DuplicateHandle:
                        jmp     DuplicateHandle
                        retn


public my_EncodePointer
my_EncodePointer:
                        jmp     EncodePointer
                        retn


public my_EncodeSystemPointer
my_EncodeSystemPointer:
                        jmp     EncodeSystemPointer
                        retn


public my_EndUpdateResourceA
my_EndUpdateResourceA:
                        jmp     EndUpdateResourceA
                        retn


public my_EndUpdateResourceW
my_EndUpdateResourceW:
                        jmp     EndUpdateResourceW
                        retn


public my_EnterCriticalSection
my_EnterCriticalSection:
                        jmp     EnterCriticalSection
                        retn


public my_EnumCalendarInfoA
my_EnumCalendarInfoA:
                        jmp     EnumCalendarInfoA
                        retn


public my_EnumCalendarInfoExA
my_EnumCalendarInfoExA:
                        jmp     EnumCalendarInfoExA
                        retn


public my_EnumCalendarInfoExW
my_EnumCalendarInfoExW:
                        jmp     EnumCalendarInfoExW
                        retn


public my_EnumCalendarInfoW
my_EnumCalendarInfoW:
                        jmp     EnumCalendarInfoW
                        retn


public my_EnumDateFormatsA
my_EnumDateFormatsA:
                        jmp     EnumDateFormatsA
                        retn


public my_EnumDateFormatsExA
my_EnumDateFormatsExA:
                        jmp     EnumDateFormatsExA
                        retn


public my_EnumDateFormatsExW
my_EnumDateFormatsExW:
                        jmp     EnumDateFormatsExW
                        retn


public my_EnumDateFormatsW
my_EnumDateFormatsW:
                        jmp     EnumDateFormatsW
                        retn


public my_EnumLanguageGroupLocalesA
my_EnumLanguageGroupLocalesA:
                        jmp     EnumLanguageGroupLocalesA
                        retn


public my_EnumLanguageGroupLocalesW
my_EnumLanguageGroupLocalesW:
                        jmp     EnumLanguageGroupLocalesW
                        retn


public my_EnumResourceLanguagesA
my_EnumResourceLanguagesA:
                        jmp     EnumResourceLanguagesA
                        retn


public my_EnumResourceLanguagesW
my_EnumResourceLanguagesW:
                        jmp     EnumResourceLanguagesW
                        retn


public my_EnumResourceNamesA
my_EnumResourceNamesA:
                        jmp     EnumResourceNamesA
                        retn


public my_EnumResourceNamesW
my_EnumResourceNamesW:
                        jmp     EnumResourceNamesW
                        retn


public my_EnumResourceTypesA
my_EnumResourceTypesA:
                        jmp     EnumResourceTypesA
                        retn


public my_EnumResourceTypesW
my_EnumResourceTypesW:
                        jmp     EnumResourceTypesW
                        retn


public my_EnumSystemCodePagesA
my_EnumSystemCodePagesA:
                        jmp     EnumSystemCodePagesA
                        retn


public my_EnumSystemCodePagesW
my_EnumSystemCodePagesW:
                        jmp     EnumSystemCodePagesW
                        retn


public my_EnumSystemGeoID
my_EnumSystemGeoID:
                        jmp     EnumSystemGeoID
                        retn


public my_EnumSystemLanguageGroupsA
my_EnumSystemLanguageGroupsA:
                        jmp     EnumSystemLanguageGroupsA
                        retn


public my_EnumSystemLanguageGroupsW
my_EnumSystemLanguageGroupsW:
                        jmp     EnumSystemLanguageGroupsW
                        retn


public my_EnumSystemLocalesA
my_EnumSystemLocalesA:
                        jmp     EnumSystemLocalesA
                        retn


public my_EnumSystemLocalesW
my_EnumSystemLocalesW:
                        jmp     EnumSystemLocalesW
                        retn


public my_EnumTimeFormatsA
my_EnumTimeFormatsA:
                        jmp     EnumTimeFormatsA
                        retn


public my_EnumTimeFormatsW
my_EnumTimeFormatsW:
                        jmp     EnumTimeFormatsW
                        retn


public my_EnumUILanguagesA
my_EnumUILanguagesA:
                        jmp     EnumUILanguagesA
                        retn


public my_EnumUILanguagesW
my_EnumUILanguagesW:
                        jmp     EnumUILanguagesW
                        retn


public my_EnumerateLocalComputerNamesA
my_EnumerateLocalComputerNamesA:
                        jmp     EnumerateLocalComputerNamesA
                        retn


public my_EnumerateLocalComputerNamesW
my_EnumerateLocalComputerNamesW:
                        jmp     EnumerateLocalComputerNamesW
                        retn


public my_EraseTape
my_EraseTape:
                        jmp     EraseTape
                        retn


public my_EscapeCommFunction
my_EscapeCommFunction:
                        jmp     EscapeCommFunction
                        retn


public my_ExitProcess
my_ExitProcess:
                        jmp     ExitProcess
                        retn


public my_ExitThread
my_ExitThread:
                        jmp     ExitThread
                        retn


public my_ExitVDM
my_ExitVDM:
                        jmp     ExitVDM
                        retn


public my_ExpandEnvironmentStringsA
my_ExpandEnvironmentStringsA:
                        jmp     ExpandEnvironmentStringsA
                        retn


public my_ExpandEnvironmentStringsW
my_ExpandEnvironmentStringsW:
                        jmp     ExpandEnvironmentStringsW
                        retn


public my_ExpungeConsoleCommandHistoryA
my_ExpungeConsoleCommandHistoryA:
                        jmp     ExpungeConsoleCommandHistoryA
                        retn


public my_ExpungeConsoleCommandHistoryW
my_ExpungeConsoleCommandHistoryW:
                        jmp     ExpungeConsoleCommandHistoryW
                        retn


public my_ExtendVirtualBuffer
my_ExtendVirtualBuffer:
                        jmp     ExtendVirtualBuffer
                        retn


public my_FatalAppExitA
my_FatalAppExitA:
                        jmp     FatalAppExitA
                        retn


public my_FatalAppExitW
my_FatalAppExitW:
                        jmp     FatalAppExitW
                        retn


public my_FatalExit
my_FatalExit:
                        jmp     FatalExit
                        retn


public my_FileTimeToDosDateTime
my_FileTimeToDosDateTime:
                        jmp     FileTimeToDosDateTime
                        retn


public my_FileTimeToLocalFileTime
my_FileTimeToLocalFileTime:
                        jmp     FileTimeToLocalFileTime
                        retn


public my_FileTimeToSystemTime
my_FileTimeToSystemTime:
                        jmp     FileTimeToSystemTime
                        retn


public my_FillConsoleOutputAttribute
my_FillConsoleOutputAttribute:
                        jmp     FillConsoleOutputAttribute
                        retn


public my_FillConsoleOutputCharacterA
my_FillConsoleOutputCharacterA:
                        jmp     FillConsoleOutputCharacterA
                        retn


public my_FillConsoleOutputCharacterW
my_FillConsoleOutputCharacterW:
                        jmp     FillConsoleOutputCharacterW
                        retn


public my_FindActCtxSectionGuid
my_FindActCtxSectionGuid:
                        jmp     FindActCtxSectionGuid
                        retn


public my_FindActCtxSectionStringA
my_FindActCtxSectionStringA:
                        jmp     FindActCtxSectionStringA
                        retn


public my_FindActCtxSectionStringW
my_FindActCtxSectionStringW:
                        jmp     FindActCtxSectionStringW
                        retn


public my_FindAtomA
my_FindAtomA:
                        jmp     FindAtomA
                        retn


public my_FindAtomW
my_FindAtomW:
                        jmp     FindAtomW
                        retn


public my_FindClose
my_FindClose:
                        jmp     FindClose
                        retn


public my_FindCloseChangeNotification
my_FindCloseChangeNotification:
                        jmp     FindCloseChangeNotification
                        retn


public my_FindFirstChangeNotificationA
my_FindFirstChangeNotificationA:
                        jmp     FindFirstChangeNotificationA
                        retn


public my_FindFirstChangeNotificationW
my_FindFirstChangeNotificationW:
                        jmp     FindFirstChangeNotificationW
                        retn


public my_FindFirstFileA
my_FindFirstFileA:
                        jmp     FindFirstFileA
                        retn


public my_FindFirstFileExA
my_FindFirstFileExA:
                        jmp     FindFirstFileExA
                        retn


public my_FindFirstFileExW
my_FindFirstFileExW:
                        jmp     FindFirstFileExW
                        retn


public my_FindFirstFileW
my_FindFirstFileW:
                        jmp     FindFirstFileW
                        retn


public my_FindFirstVolumeA
my_FindFirstVolumeA:
                        jmp     FindFirstVolumeA
                        retn


public my_FindFirstVolumeMountPointA
my_FindFirstVolumeMountPointA:
                        jmp     FindFirstVolumeMountPointA
                        retn


public my_FindFirstVolumeMountPointW
my_FindFirstVolumeMountPointW:
                        jmp     FindFirstVolumeMountPointW
                        retn


public my_FindFirstVolumeW
my_FindFirstVolumeW:
                        jmp     FindFirstVolumeW
                        retn


public my_FindNextChangeNotification
my_FindNextChangeNotification:
                        jmp     FindNextChangeNotification
                        retn


public my_FindNextFileA
my_FindNextFileA:
                        jmp     FindNextFileA
                        retn


public my_FindNextFileW
my_FindNextFileW:
                        jmp     FindNextFileW
                        retn


public my_FindNextVolumeA
my_FindNextVolumeA:
                        jmp     FindNextVolumeA
                        retn


public my_FindNextVolumeMountPointA
my_FindNextVolumeMountPointA:
                        jmp     FindNextVolumeMountPointA
                        retn


public my_FindNextVolumeMountPointW
my_FindNextVolumeMountPointW:
                        jmp     FindNextVolumeMountPointW
                        retn


public my_FindNextVolumeW
my_FindNextVolumeW:
                        jmp     FindNextVolumeW
                        retn


public my_FindResourceA
my_FindResourceA:
                        jmp     FindResourceA
                        retn


public my_FindResourceExA
my_FindResourceExA:
                        jmp     FindResourceExA
                        retn


public my_FindResourceExW
my_FindResourceExW:
                        jmp     FindResourceExW
                        retn


public my_FindResourceW
my_FindResourceW:
                        jmp     FindResourceW
                        retn


public my_FindVolumeClose
my_FindVolumeClose:
                        jmp     FindVolumeClose
                        retn


public my_FindVolumeMountPointClose
my_FindVolumeMountPointClose:
                        jmp     FindVolumeMountPointClose
                        retn


public my_FlushConsoleInputBuffer
my_FlushConsoleInputBuffer:
                        jmp     FlushConsoleInputBuffer
                        retn


public my_FlushFileBuffers
my_FlushFileBuffers:
                        jmp     FlushFileBuffers
                        retn


public my_FlushInstructionCache
my_FlushInstructionCache:
                        jmp     FlushInstructionCache
                        retn


public my_FlushViewOfFile
my_FlushViewOfFile:
                        jmp     FlushViewOfFile
                        retn


public my_FoldStringA
my_FoldStringA:
                        jmp     FoldStringA
                        retn


public my_FoldStringW
my_FoldStringW:
                        jmp     FoldStringW
                        retn


public my_FormatMessageA
my_FormatMessageA:
                        jmp     FormatMessageA
                        retn


public my_FormatMessageW
my_FormatMessageW:
                        jmp     FormatMessageW
                        retn


public my_FreeConsole
my_FreeConsole:
                        jmp     FreeConsole
                        retn


public my_FreeEnvironmentStringsA
my_FreeEnvironmentStringsA:
                        jmp     FreeEnvironmentStringsA
                        retn


public my_FreeEnvironmentStringsW
my_FreeEnvironmentStringsW:
                        jmp     FreeEnvironmentStringsW
                        retn


public my_FreeLibrary
my_FreeLibrary:
                        jmp     FreeLibrary
                        retn


public my_FreeLibraryAndExitThread
my_FreeLibraryAndExitThread:
                        jmp     FreeLibraryAndExitThread
                        retn


public my_FreeResource
my_FreeResource:
                        jmp     FreeResource
                        retn


public my_FreeUserPhysicalPages
my_FreeUserPhysicalPages:
                        jmp     FreeUserPhysicalPages
                        retn


public my_FreeVirtualBuffer
my_FreeVirtualBuffer:
                        jmp     FreeVirtualBuffer
                        retn


public my_GenerateConsoleCtrlEvent
my_GenerateConsoleCtrlEvent:
                        jmp     GenerateConsoleCtrlEvent
                        retn


public my_GetACP
my_GetACP:
                        jmp     GetACP
                        retn


public my_GetAtomNameA
my_GetAtomNameA:
                        jmp     GetAtomNameA
                        retn


public my_GetAtomNameW
my_GetAtomNameW:
                        jmp     GetAtomNameW
                        retn


public my_GetBinaryType
my_GetBinaryType:
                        jmp     GetBinaryType
                        retn


public my_GetBinaryTypeA
my_GetBinaryTypeA:
                        jmp     GetBinaryTypeA
                        retn


public my_GetBinaryTypeW
my_GetBinaryTypeW:
                        jmp     GetBinaryTypeW
                        retn


public my_GetCPFileNameFromRegistry
my_GetCPFileNameFromRegistry:
                        jmp     GetCPFileNameFromRegistry
                        retn


public my_GetCPInfo
my_GetCPInfo:
                        jmp     GetCPInfo
                        retn


public my_GetCPInfoExA
my_GetCPInfoExA:
                        jmp     GetCPInfoExA
                        retn


public my_GetCPInfoExW
my_GetCPInfoExW:
                        jmp     GetCPInfoExW
                        retn


public my_GetCalendarInfoA
my_GetCalendarInfoA:
                        jmp     GetCalendarInfoA
                        retn


public my_GetCalendarInfoW
my_GetCalendarInfoW:
                        jmp     GetCalendarInfoW
                        retn


public my_GetComPlusPackageInstallStatus
my_GetComPlusPackageInstallStatus:
                        jmp     GetComPlusPackageInstallStatus
                        retn


public my_GetCommConfig
my_GetCommConfig:
                        jmp     GetCommConfig
                        retn


public my_GetCommMask
my_GetCommMask:
                        jmp     GetCommMask
                        retn


public my_GetCommModemStatus
my_GetCommModemStatus:
                        jmp     GetCommModemStatus
                        retn


public my_GetCommProperties
my_GetCommProperties:
                        jmp     GetCommProperties
                        retn


public my_GetCommState
my_GetCommState:
                        jmp     GetCommState
                        retn


public my_GetCommTimeouts
my_GetCommTimeouts:
                        jmp     GetCommTimeouts
                        retn


public my_GetCommandLineA
my_GetCommandLineA:
                        jmp     GetCommandLineA
                        retn


public my_GetCommandLineW
my_GetCommandLineW:
                        jmp     GetCommandLineW
                        retn


public my_GetCompressedFileSizeA
my_GetCompressedFileSizeA:
                        jmp     GetCompressedFileSizeA
                        retn


public my_GetCompressedFileSizeW
my_GetCompressedFileSizeW:
                        jmp     GetCompressedFileSizeW
                        retn


public my_GetComputerNameA
my_GetComputerNameA:
                        jmp     GetComputerNameA
                        retn


public my_GetComputerNameExA
my_GetComputerNameExA:
                        jmp     GetComputerNameExA
                        retn


public my_GetComputerNameExW
my_GetComputerNameExW:
                        jmp     GetComputerNameExW
                        retn


public my_GetComputerNameW
my_GetComputerNameW:
                        jmp     GetComputerNameW
                        retn


public my_GetConsoleAliasA
my_GetConsoleAliasA:
                        jmp     GetConsoleAliasA
                        retn


public my_GetConsoleAliasExesA
my_GetConsoleAliasExesA:
                        jmp     GetConsoleAliasExesA
                        retn


public my_GetConsoleAliasExesLengthA
my_GetConsoleAliasExesLengthA:
                        jmp     GetConsoleAliasExesLengthA
                        retn


public my_GetConsoleAliasExesLengthW
my_GetConsoleAliasExesLengthW:
                        jmp     GetConsoleAliasExesLengthW
                        retn


public my_GetConsoleAliasExesW
my_GetConsoleAliasExesW:
                        jmp     GetConsoleAliasExesW
                        retn


public my_GetConsoleAliasW
my_GetConsoleAliasW:
                        jmp     GetConsoleAliasW
                        retn


public my_GetConsoleAliasesA
my_GetConsoleAliasesA:
                        jmp     GetConsoleAliasesA
                        retn


public my_GetConsoleAliasesLengthA
my_GetConsoleAliasesLengthA:
                        jmp     GetConsoleAliasesLengthA
                        retn


public my_GetConsoleAliasesLengthW
my_GetConsoleAliasesLengthW:
                        jmp     GetConsoleAliasesLengthW
                        retn


public my_GetConsoleAliasesW
my_GetConsoleAliasesW:
                        jmp     GetConsoleAliasesW
                        retn


public my_GetConsoleCP
my_GetConsoleCP:
                        jmp     GetConsoleCP
                        retn


public my_GetConsoleCharType
my_GetConsoleCharType:
                        jmp     GetConsoleCharType
                        retn


public my_GetConsoleCommandHistoryA
my_GetConsoleCommandHistoryA:
                        jmp     GetConsoleCommandHistoryA
                        retn


public my_GetConsoleCommandHistoryLengthA
my_GetConsoleCommandHistoryLengthA:
                        jmp     GetConsoleCommandHistoryLengthA
                        retn


public my_GetConsoleCommandHistoryLengthW
my_GetConsoleCommandHistoryLengthW:
                        jmp     GetConsoleCommandHistoryLengthW
                        retn


public my_GetConsoleCommandHistoryW
my_GetConsoleCommandHistoryW:
                        jmp     GetConsoleCommandHistoryW
                        retn


public my_GetConsoleCursorInfo
my_GetConsoleCursorInfo:
                        jmp     GetConsoleCursorInfo
                        retn


public my_GetConsoleCursorMode
my_GetConsoleCursorMode:
                        jmp     GetConsoleCursorMode
                        retn


public my_GetConsoleDisplayMode
my_GetConsoleDisplayMode:
                        jmp     GetConsoleDisplayMode
                        retn


public my_GetConsoleFontInfo
my_GetConsoleFontInfo:
                        jmp     GetConsoleFontInfo
                        retn


public my_GetConsoleFontSize
my_GetConsoleFontSize:
                        jmp     GetConsoleFontSize
                        retn


public my_GetConsoleHardwareState
my_GetConsoleHardwareState:
                        jmp     GetConsoleHardwareState
                        retn


public my_GetConsoleInputExeNameA
my_GetConsoleInputExeNameA:
                        jmp     GetConsoleInputExeNameA
                        retn


public my_GetConsoleInputExeNameW
my_GetConsoleInputExeNameW:
                        jmp     GetConsoleInputExeNameW
                        retn


public my_GetConsoleInputWaitHandle
my_GetConsoleInputWaitHandle:
                        jmp     GetConsoleInputWaitHandle
                        retn


public my_GetConsoleKeyboardLayoutNameA
my_GetConsoleKeyboardLayoutNameA:
                        jmp     GetConsoleKeyboardLayoutNameA
                        retn


public my_GetConsoleKeyboardLayoutNameW
my_GetConsoleKeyboardLayoutNameW:
                        jmp     GetConsoleKeyboardLayoutNameW
                        retn


public my_GetConsoleMode
my_GetConsoleMode:
                        jmp     GetConsoleMode
                        retn


public my_GetConsoleNlsMode
my_GetConsoleNlsMode:
                        jmp     GetConsoleNlsMode
                        retn


public my_GetConsoleOutputCP
my_GetConsoleOutputCP:
                        jmp     GetConsoleOutputCP
                        retn


public my_GetConsoleProcessList
my_GetConsoleProcessList:
                        jmp     GetConsoleProcessList
                        retn


public my_GetConsoleScreenBufferInfo
my_GetConsoleScreenBufferInfo:
                        jmp     GetConsoleScreenBufferInfo
                        retn


public my_GetConsoleSelectionInfo
my_GetConsoleSelectionInfo:
                        jmp     GetConsoleSelectionInfo
                        retn


public my_GetConsoleTitleA
my_GetConsoleTitleA:
                        jmp     GetConsoleTitleA
                        retn


public my_GetConsoleTitleW
my_GetConsoleTitleW:
                        jmp     GetConsoleTitleW
                        retn


public my_GetConsoleWindow
my_GetConsoleWindow:
                        jmp     GetConsoleWindow
                        retn


public my_GetCurrencyFormatA
my_GetCurrencyFormatA:
                        jmp     GetCurrencyFormatA
                        retn


public my_GetCurrencyFormatW
my_GetCurrencyFormatW:
                        jmp     GetCurrencyFormatW
                        retn


public my_GetCurrentActCtx
my_GetCurrentActCtx:
                        jmp     GetCurrentActCtx
                        retn


public my_GetCurrentConsoleFont
my_GetCurrentConsoleFont:
                        jmp     GetCurrentConsoleFont
                        retn


public my_GetCurrentDirectoryA
my_GetCurrentDirectoryA:
                        jmp     GetCurrentDirectoryA
                        retn


public my_GetCurrentDirectoryW
my_GetCurrentDirectoryW:
                        jmp     GetCurrentDirectoryW
                        retn


public my_GetCurrentProcess
my_GetCurrentProcess:
                        jmp     GetCurrentProcess
                        retn


public my_GetCurrentProcessId
my_GetCurrentProcessId:
                        jmp     GetCurrentProcessId
                        retn


public my_GetCurrentThread
my_GetCurrentThread:
                        jmp     GetCurrentThread
                        retn


public my_GetCurrentThreadId
my_GetCurrentThreadId:
                        jmp     GetCurrentThreadId
                        retn


public my_GetDateFormatA
my_GetDateFormatA:
                        jmp     GetDateFormatA
                        retn


public my_GetDateFormatW
my_GetDateFormatW:
                        jmp     GetDateFormatW
                        retn


public my_GetDefaultCommConfigA
my_GetDefaultCommConfigA:
                        jmp     GetDefaultCommConfigA
                        retn


public my_GetDefaultCommConfigW
my_GetDefaultCommConfigW:
                        jmp     GetDefaultCommConfigW
                        retn


public my_GetDefaultSortkeySize
my_GetDefaultSortkeySize:
                        jmp     GetDefaultSortkeySize
                        retn


public my_GetDevicePowerState
my_GetDevicePowerState:
                        jmp     GetDevicePowerState
                        retn


public my_GetDiskFreeSpaceA
my_GetDiskFreeSpaceA:
                        jmp     GetDiskFreeSpaceA
                        retn


public my_GetDiskFreeSpaceExA
my_GetDiskFreeSpaceExA:
                        jmp     GetDiskFreeSpaceExA
                        retn


public my_GetDiskFreeSpaceExW
my_GetDiskFreeSpaceExW:
                        jmp     GetDiskFreeSpaceExW
                        retn


public my_GetDiskFreeSpaceW
my_GetDiskFreeSpaceW:
                        jmp     GetDiskFreeSpaceW
                        retn


public my_GetDllDirectoryA
my_GetDllDirectoryA:
                        jmp     GetDllDirectoryA
                        retn


public my_GetDllDirectoryW
my_GetDllDirectoryW:
                        jmp     GetDllDirectoryW
                        retn


public my_GetDriveTypeA
my_GetDriveTypeA:
                        jmp     GetDriveTypeA
                        retn


public my_GetDriveTypeW
my_GetDriveTypeW:
                        jmp     GetDriveTypeW
                        retn


public my_GetEnvironmentStrings
my_GetEnvironmentStrings:
                        jmp     GetEnvironmentStrings
                        retn


public my_GetEnvironmentStringsA
my_GetEnvironmentStringsA:
                        jmp     GetEnvironmentStringsA
                        retn


public my_GetEnvironmentStringsW
my_GetEnvironmentStringsW:
                        jmp     GetEnvironmentStringsW
                        retn


public my_GetEnvironmentVariableA
my_GetEnvironmentVariableA:
                        jmp     GetEnvironmentVariableA
                        retn


public my_GetEnvironmentVariableW
my_GetEnvironmentVariableW:
                        jmp     GetEnvironmentVariableW
                        retn


public my_GetExitCodeProcess
my_GetExitCodeProcess:
                        jmp     GetExitCodeProcess
                        retn


public my_GetExitCodeThread
my_GetExitCodeThread:
                        jmp     GetExitCodeThread
                        retn


public my_GetExpandedNameA
my_GetExpandedNameA:
                        jmp     GetExpandedNameA
                        retn


public my_GetExpandedNameW
my_GetExpandedNameW:
                        jmp     GetExpandedNameW
                        retn


public my_GetFileAttributesA
my_GetFileAttributesA:
                        jmp     GetFileAttributesA
                        retn


public my_GetFileAttributesExA
my_GetFileAttributesExA:
                        jmp     GetFileAttributesExA
                        retn


public my_GetFileAttributesExW
my_GetFileAttributesExW:
                        jmp     GetFileAttributesExW
                        retn


public my_GetFileAttributesW
my_GetFileAttributesW:
                        jmp     GetFileAttributesW
                        retn


public my_GetFileInformationByHandle
my_GetFileInformationByHandle:
                        jmp     GetFileInformationByHandle
                        retn


public my_GetFileSize
my_GetFileSize:
                        jmp     GetFileSize
                        retn


public my_GetFileSizeEx
my_GetFileSizeEx:
                        jmp     GetFileSizeEx
                        retn


public my_GetFileTime
my_GetFileTime:
                        jmp     GetFileTime
                        retn


public my_GetFileType
my_GetFileType:
                        jmp     GetFileType
                        retn


public my_GetFirmwareEnvironmentVariableA
my_GetFirmwareEnvironmentVariableA:
                        jmp     GetFirmwareEnvironmentVariableA
                        retn


public my_GetFirmwareEnvironmentVariableW
my_GetFirmwareEnvironmentVariableW:
                        jmp     GetFirmwareEnvironmentVariableW
                        retn


public my_GetFullPathNameA
my_GetFullPathNameA:
                        jmp     GetFullPathNameA
                        retn


public my_GetFullPathNameW
my_GetFullPathNameW:
                        jmp     GetFullPathNameW
                        retn


public my_GetGeoInfoA
my_GetGeoInfoA:
                        jmp     GetGeoInfoA
                        retn


public my_GetGeoInfoW
my_GetGeoInfoW:
                        jmp     GetGeoInfoW
                        retn


public my_GetHandleContext
my_GetHandleContext:
                        jmp     GetHandleContext
                        retn


public my_GetHandleInformation
my_GetHandleInformation:
                        jmp     GetHandleInformation
                        retn


public my_GetLargestConsoleWindowSize
my_GetLargestConsoleWindowSize:
                        jmp     GetLargestConsoleWindowSize
                        retn


public my_GetLastError
my_GetLastError:
                        jmp     GetLastError
                        retn


public my_GetLinguistLangSize
my_GetLinguistLangSize:
                        jmp     GetLinguistLangSize
                        retn


public my_GetLocalTime
my_GetLocalTime:
                        jmp     GetLocalTime
                        retn


public my_GetLocaleInfoA
my_GetLocaleInfoA:
                        jmp     GetLocaleInfoA
                        retn


public my_GetLocaleInfoW
my_GetLocaleInfoW:
                        jmp     GetLocaleInfoW
                        retn


public my_GetLogicalDriveStringsA
my_GetLogicalDriveStringsA:
                        jmp     GetLogicalDriveStringsA
                        retn


public my_GetLogicalDriveStringsW
my_GetLogicalDriveStringsW:
                        jmp     GetLogicalDriveStringsW
                        retn


public my_GetLogicalDrives
my_GetLogicalDrives:
                        jmp     GetLogicalDrives
                        retn


public my_GetLongPathNameA
my_GetLongPathNameA:
                        jmp     GetLongPathNameA
                        retn


public my_GetLongPathNameW
my_GetLongPathNameW:
                        jmp     GetLongPathNameW
                        retn


public my_GetMailslotInfo
my_GetMailslotInfo:
                        jmp     GetMailslotInfo
                        retn


public my_GetModuleFileNameA
my_GetModuleFileNameA:
                        jmp     GetModuleFileNameA
                        retn


public my_GetModuleFileNameW
my_GetModuleFileNameW:
                        jmp     GetModuleFileNameW
                        retn


formatgma               db      "getmodule : %s", 0
public my_GetModuleHandleA
my_GetModuleHandleA:
                        pusha
                        mov     esi, [esp+24h]
                        test    esi, esi
                        jz      __imagebase
                        call    wsprintfA, offset buffer, offset formatgma, esi
                        add     esp, 0ch
                        call    OutputDebugStringA, offset buffer
                        popa
                        jmp     GetModuleHandleA
                        retn
                        
__imagebase:            pushs   <"getmodule : imagebase">
                        call    OutputDebugStringA
                        popa
                        jmp     GetModuleHandleA
                        retn


public my_GetModuleHandleExA
my_GetModuleHandleExA:
                        jmp     GetModuleHandleExA
                        retn


public my_GetModuleHandleExW
my_GetModuleHandleExW:
                        jmp     GetModuleHandleExW
                        retn


public my_GetModuleHandleW
my_GetModuleHandleW:
                        jmp     GetModuleHandleW
                        retn


public my_GetNamedPipeHandleStateA
my_GetNamedPipeHandleStateA:
                        jmp     GetNamedPipeHandleStateA
                        retn


public my_GetNamedPipeHandleStateW
my_GetNamedPipeHandleStateW:
                        jmp     GetNamedPipeHandleStateW
                        retn


public my_GetNamedPipeInfo
my_GetNamedPipeInfo:
                        jmp     GetNamedPipeInfo
                        retn


public my_GetNativeSystemInfo
my_GetNativeSystemInfo:
                        jmp     GetNativeSystemInfo
                        retn


public my_GetNextVDMCommand
my_GetNextVDMCommand:
                        jmp     GetNextVDMCommand
                        retn


public my_GetNlsSectionName
my_GetNlsSectionName:
                        jmp     GetNlsSectionName
                        retn


public my_GetNumaAvailableMemory
my_GetNumaAvailableMemory:
                        jmp     GetNumaAvailableMemory
                        retn


public my_GetNumaAvailableMemoryNode
my_GetNumaAvailableMemoryNode:
                        jmp     GetNumaAvailableMemoryNode
                        retn


public my_GetNumaHighestNodeNumber
my_GetNumaHighestNodeNumber:
                        jmp     GetNumaHighestNodeNumber
                        retn


public my_GetNumaNodeProcessorMask
my_GetNumaNodeProcessorMask:
                        jmp     GetNumaNodeProcessorMask
                        retn


public my_GetNumaProcessorMap
my_GetNumaProcessorMap:
                        jmp     GetNumaProcessorMap
                        retn


public my_GetNumaProcessorNode
my_GetNumaProcessorNode:
                        jmp     GetNumaProcessorNode
                        retn


public my_GetNumberFormatA
my_GetNumberFormatA:
                        jmp     GetNumberFormatA
                        retn


public my_GetNumberFormatW
my_GetNumberFormatW:
                        jmp     GetNumberFormatW
                        retn


public my_GetNumberOfConsoleFonts
my_GetNumberOfConsoleFonts:
                        jmp     GetNumberOfConsoleFonts
                        retn


public my_GetNumberOfConsoleInputEvents
my_GetNumberOfConsoleInputEvents:
                        jmp     GetNumberOfConsoleInputEvents
                        retn


public my_GetNumberOfConsoleMouseButtons
my_GetNumberOfConsoleMouseButtons:
                        jmp     GetNumberOfConsoleMouseButtons
                        retn


public my_GetOEMCP
my_GetOEMCP:
                        jmp     GetOEMCP
                        retn


public my_GetOverlappedResult
my_GetOverlappedResult:
                        jmp     GetOverlappedResult
                        retn


public my_GetPriorityClass
my_GetPriorityClass:
                        jmp     GetPriorityClass
                        retn


public my_GetPrivateProfileIntA
my_GetPrivateProfileIntA:
                        jmp     GetPrivateProfileIntA
                        retn


public my_GetPrivateProfileIntW
my_GetPrivateProfileIntW:
                        jmp     GetPrivateProfileIntW
                        retn


public my_GetPrivateProfileSectionA
my_GetPrivateProfileSectionA:
                        jmp     GetPrivateProfileSectionA
                        retn


public my_GetPrivateProfileSectionNamesA
my_GetPrivateProfileSectionNamesA:
                        jmp     GetPrivateProfileSectionNamesA
                        retn


public my_GetPrivateProfileSectionNamesW
my_GetPrivateProfileSectionNamesW:
                        jmp     GetPrivateProfileSectionNamesW
                        retn


public my_GetPrivateProfileSectionW
my_GetPrivateProfileSectionW:
                        jmp     GetPrivateProfileSectionW
                        retn


public my_GetPrivateProfileStringA
my_GetPrivateProfileStringA:
                        jmp     GetPrivateProfileStringA
                        retn


public my_GetPrivateProfileStringW
my_GetPrivateProfileStringW:
                        jmp     GetPrivateProfileStringW
                        retn


public my_GetPrivateProfileStructA
my_GetPrivateProfileStructA:
                        jmp     GetPrivateProfileStructA
                        retn


public my_GetPrivateProfileStructW
my_GetPrivateProfileStructW:
                        jmp     GetPrivateProfileStructW
                        retn


public my_GetProcAddress
my_GetProcAddress:
                        jmp     GetProcAddress
                        retn


public my_GetProcessAffinityMask
my_GetProcessAffinityMask:
                        jmp     GetProcessAffinityMask
                        retn


public my_GetProcessHandleCount
my_GetProcessHandleCount:
                        jmp     GetProcessHandleCount
                        retn


public my_GetProcessHeap
my_GetProcessHeap:
                        jmp     GetProcessHeap
                        retn


public my_GetProcessHeaps
my_GetProcessHeaps:
                        jmp     GetProcessHeaps
                        retn


public my_GetProcessId
my_GetProcessId:
                        jmp     GetProcessId
                        retn


public my_GetProcessIoCounters
my_GetProcessIoCounters:
                        jmp     GetProcessIoCounters
                        retn


public my_GetProcessPriorityBoost
my_GetProcessPriorityBoost:
                        jmp     GetProcessPriorityBoost
                        retn


public my_GetProcessShutdownParameters
my_GetProcessShutdownParameters:
                        jmp     GetProcessShutdownParameters
                        retn


public my_GetProcessTimes
my_GetProcessTimes:
                        jmp     GetProcessTimes
                        retn


public my_GetProcessVersion
my_GetProcessVersion:
                        jmp     GetProcessVersion
                        retn


public my_GetProcessWorkingSetSize
my_GetProcessWorkingSetSize:
                        jmp     GetProcessWorkingSetSize
                        retn


public my_GetProfileIntA
my_GetProfileIntA:
                        jmp     GetProfileIntA
                        retn


public my_GetProfileIntW
my_GetProfileIntW:
                        jmp     GetProfileIntW
                        retn


public my_GetProfileSectionA
my_GetProfileSectionA:
                        jmp     GetProfileSectionA
                        retn


public my_GetProfileSectionW
my_GetProfileSectionW:
                        jmp     GetProfileSectionW
                        retn


public my_GetProfileStringA
my_GetProfileStringA:
                        jmp     GetProfileStringA
                        retn


public my_GetProfileStringW
my_GetProfileStringW:
                        jmp     GetProfileStringW
                        retn


public my_GetQueuedCompletionStatus
my_GetQueuedCompletionStatus:
                        jmp     GetQueuedCompletionStatus
                        retn


public my_GetShortPathNameA
my_GetShortPathNameA:
                        jmp     GetShortPathNameA
                        retn


public my_GetShortPathNameW
my_GetShortPathNameW:
                        jmp     GetShortPathNameW
                        retn


public my_GetStartupInfoA
my_GetStartupInfoA:
                        jmp     GetStartupInfoA
                        retn


public my_GetStartupInfoW
my_GetStartupInfoW:
                        jmp     GetStartupInfoW
                        retn


public my_GetStdHandle
my_GetStdHandle:
                        jmp     GetStdHandle
                        retn


public my_GetStringTypeA
my_GetStringTypeA:
                        jmp     GetStringTypeA
                        retn


public my_GetStringTypeExA
my_GetStringTypeExA:
                        jmp     GetStringTypeExA
                        retn


public my_GetStringTypeExW
my_GetStringTypeExW:
                        jmp     GetStringTypeExW
                        retn


public my_GetStringTypeW
my_GetStringTypeW:
                        jmp     GetStringTypeW
                        retn


public my_GetSystemDefaultLCID
my_GetSystemDefaultLCID:
                        jmp     GetSystemDefaultLCID
                        retn


public my_GetSystemDefaultLangID
my_GetSystemDefaultLangID:
                        jmp     GetSystemDefaultLangID
                        retn


public my_GetSystemDefaultUILanguage
my_GetSystemDefaultUILanguage:
                        jmp     GetSystemDefaultUILanguage
                        retn


public my_GetSystemDirectoryA
my_GetSystemDirectoryA:
                        jmp     GetSystemDirectoryA
                        retn


public my_GetSystemDirectoryW
my_GetSystemDirectoryW:
                        jmp     GetSystemDirectoryW
                        retn


public my_GetSystemInfo
my_GetSystemInfo:
                        jmp     GetSystemInfo
                        retn


public my_GetSystemPowerStatus
my_GetSystemPowerStatus:
                        jmp     GetSystemPowerStatus
                        retn


public my_GetSystemRegistryQuota
my_GetSystemRegistryQuota:
                        jmp     GetSystemRegistryQuota
                        retn


public my_GetSystemTime
my_GetSystemTime:
                        jmp     GetSystemTime
                        retn


public my_GetSystemTimeAdjustment
my_GetSystemTimeAdjustment:
                        jmp     GetSystemTimeAdjustment
                        retn


public my_GetSystemTimeAsFileTime
my_GetSystemTimeAsFileTime:
                        jmp     GetSystemTimeAsFileTime
                        retn


public my_GetSystemTimes
my_GetSystemTimes:
                        jmp     GetSystemTimes
                        retn


public my_GetSystemWindowsDirectoryA
my_GetSystemWindowsDirectoryA:
                        jmp     GetSystemWindowsDirectoryA
                        retn


public my_GetSystemWindowsDirectoryW
my_GetSystemWindowsDirectoryW:
                        jmp     GetSystemWindowsDirectoryW
                        retn


public my_GetSystemWow64DirectoryA
my_GetSystemWow64DirectoryA:
                        jmp     GetSystemWow64DirectoryA
                        retn


public my_GetSystemWow64DirectoryW
my_GetSystemWow64DirectoryW:
                        jmp     GetSystemWow64DirectoryW
                        retn


public my_GetTapeParameters
my_GetTapeParameters:
                        jmp     GetTapeParameters
                        retn


public my_GetTapePosition
my_GetTapePosition:
                        jmp     GetTapePosition
                        retn


public my_GetTapeStatus
my_GetTapeStatus:
                        jmp     GetTapeStatus
                        retn


public my_GetTempFileNameA
my_GetTempFileNameA:
                        jmp     GetTempFileNameA
                        retn


public my_GetTempFileNameW
my_GetTempFileNameW:
                        jmp     GetTempFileNameW
                        retn


public my_GetTempPathA
my_GetTempPathA:
                        jmp     GetTempPathA
                        retn


public my_GetTempPathW
my_GetTempPathW:
                        jmp     GetTempPathW
                        retn


public my_GetThreadContext
my_GetThreadContext:
                        jmp     GetThreadContext
                        retn


public my_GetThreadIOPendingFlag
my_GetThreadIOPendingFlag:
                        jmp     GetThreadIOPendingFlag
                        retn


public my_GetThreadLocale
my_GetThreadLocale:
                        jmp     GetThreadLocale
                        retn


public my_GetThreadPriority
my_GetThreadPriority:
                        jmp     GetThreadPriority
                        retn


public my_GetThreadPriorityBoost
my_GetThreadPriorityBoost:
                        jmp     GetThreadPriorityBoost
                        retn


public my_GetThreadSelectorEntry
my_GetThreadSelectorEntry:
                        jmp     GetThreadSelectorEntry
                        retn


public my_GetThreadTimes
my_GetThreadTimes:
                        jmp     GetThreadTimes
                        retn


public my_GetTickCount
my_GetTickCount:
                        jmp     GetTickCount
                        retn


public my_GetTimeFormatA
my_GetTimeFormatA:
                        jmp     GetTimeFormatA
                        retn


public my_GetTimeFormatW
my_GetTimeFormatW:
                        jmp     GetTimeFormatW
                        retn


public my_GetTimeZoneInformation
my_GetTimeZoneInformation:
                        jmp     GetTimeZoneInformation
                        retn


public my_GetUserDefaultLCID
my_GetUserDefaultLCID:
                        jmp     GetUserDefaultLCID
                        retn


public my_GetUserDefaultLangID
my_GetUserDefaultLangID:
                        jmp     GetUserDefaultLangID
                        retn


public my_GetUserDefaultUILanguage
my_GetUserDefaultUILanguage:
                        jmp     GetUserDefaultUILanguage
                        retn


public my_GetUserGeoID
my_GetUserGeoID:
                        jmp     GetUserGeoID
                        retn


public my_GetVDMCurrentDirectories
my_GetVDMCurrentDirectories:
                        jmp     GetVDMCurrentDirectories
                        retn


public my_GetVersion
my_GetVersion:
                        jmp     GetVersion
                        retn


public my_GetVersionExA
my_GetVersionExA:
                        jmp     GetVersionExA
                        retn


public my_GetVersionExW
my_GetVersionExW:
                        jmp     GetVersionExW
                        retn


public my_GetVolumeInformationA
my_GetVolumeInformationA:
                        jmp     GetVolumeInformationA
                        retn


public my_GetVolumeInformationW
my_GetVolumeInformationW:
                        jmp     GetVolumeInformationW
                        retn


public my_GetVolumeNameForVolumeMountPointA
my_GetVolumeNameForVolumeMountPointA:
                        jmp     GetVolumeNameForVolumeMountPointA
                        retn


public my_GetVolumeNameForVolumeMountPointW
my_GetVolumeNameForVolumeMountPointW:
                        jmp     GetVolumeNameForVolumeMountPointW
                        retn


public my_GetVolumePathNameA
my_GetVolumePathNameA:
                        jmp     GetVolumePathNameA
                        retn


public my_GetVolumePathNameW
my_GetVolumePathNameW:
                        jmp     GetVolumePathNameW
                        retn


public my_GetVolumePathNamesForVolumeNameA
my_GetVolumePathNamesForVolumeNameA:
                        jmp     GetVolumePathNamesForVolumeNameA
                        retn


public my_GetVolumePathNamesForVolumeNameW
my_GetVolumePathNamesForVolumeNameW:
                        jmp     GetVolumePathNamesForVolumeNameW
                        retn


public my_GetWindowsDirectoryA
my_GetWindowsDirectoryA:
                        jmp     GetWindowsDirectoryA
                        retn


public my_GetWindowsDirectoryW
my_GetWindowsDirectoryW:
                        jmp     GetWindowsDirectoryW
                        retn


public my_GetWriteWatch
my_GetWriteWatch:
                        jmp     GetWriteWatch
                        retn


public my_GlobalAddAtomA
my_GlobalAddAtomA:
                        jmp     GlobalAddAtomA
                        retn


public my_GlobalAddAtomW
my_GlobalAddAtomW:
                        jmp     GlobalAddAtomW
                        retn


public my_GlobalAlloc
my_GlobalAlloc:
                        jmp     GlobalAlloc
                        retn


public my_GlobalCompact
my_GlobalCompact:
                        jmp     GlobalCompact
                        retn


public my_GlobalDeleteAtom
my_GlobalDeleteAtom:
                        jmp     GlobalDeleteAtom
                        retn


public my_GlobalFindAtomA
my_GlobalFindAtomA:
                        jmp     GlobalFindAtomA
                        retn


public my_GlobalFindAtomW
my_GlobalFindAtomW:
                        jmp     GlobalFindAtomW
                        retn


public my_GlobalFix
my_GlobalFix:
                        jmp     GlobalFix
                        retn


public my_GlobalFlags
my_GlobalFlags:
                        jmp     GlobalFlags
                        retn


public my_GlobalFree
my_GlobalFree:
                        jmp     GlobalFree
                        retn


public my_GlobalGetAtomNameA
my_GlobalGetAtomNameA:
                        jmp     GlobalGetAtomNameA
                        retn


public my_GlobalGetAtomNameW
my_GlobalGetAtomNameW:
                        jmp     GlobalGetAtomNameW
                        retn


public my_GlobalHandle
my_GlobalHandle:
                        jmp     GlobalHandle
                        retn


public my_GlobalLock
my_GlobalLock:
                        jmp     GlobalLock
                        retn


public my_GlobalMemoryStatus
my_GlobalMemoryStatus:
                        jmp     GlobalMemoryStatus
                        retn


public my_GlobalMemoryStatusEx
my_GlobalMemoryStatusEx:
                        jmp     GlobalMemoryStatusEx
                        retn


public my_GlobalReAlloc
my_GlobalReAlloc:
                        jmp     GlobalReAlloc
                        retn


public my_GlobalSize
my_GlobalSize:
                        jmp     GlobalSize
                        retn


public my_GlobalUnWire
my_GlobalUnWire:
                        jmp     GlobalUnWire
                        retn


public my_GlobalUnfix
my_GlobalUnfix:
                        jmp     GlobalUnfix
                        retn


public my_GlobalUnlock
my_GlobalUnlock:
                        jmp     GlobalUnlock
                        retn


public my_GlobalWire
my_GlobalWire:
                        jmp     GlobalWire
                        retn


public my_Heap32First
my_Heap32First:
                        jmp     Heap32First
                        retn


public my_Heap32ListFirst
my_Heap32ListFirst:
                        jmp     Heap32ListFirst
                        retn


public my_Heap32ListNext
my_Heap32ListNext:
                        jmp     Heap32ListNext
                        retn


public my_Heap32Next
my_Heap32Next:
                        jmp     Heap32Next
                        retn


public my_HeapAlloc
my_HeapAlloc:
                        jmp     HeapAlloc
                        retn


public my_HeapCompact
my_HeapCompact:
                        jmp     HeapCompact
                        retn


public my_HeapCreate
my_HeapCreate:
                        jmp     HeapCreate
                        retn


public my_HeapCreateTagsW
my_HeapCreateTagsW:
                        jmp     HeapCreateTagsW
                        retn


public my_HeapDestroy
my_HeapDestroy:
                        jmp     HeapDestroy
                        retn


public my_HeapExtend
my_HeapExtend:
                        jmp     HeapExtend
                        retn


public my_HeapFree
my_HeapFree:
                        jmp     HeapFree
                        retn


public my_HeapLock
my_HeapLock:
                        jmp     HeapLock
                        retn


public my_HeapQueryInformation
my_HeapQueryInformation:
                        jmp     HeapQueryInformation
                        retn


public my_HeapQueryTagW
my_HeapQueryTagW:
                        jmp     HeapQueryTagW
                        retn


public my_HeapReAlloc
my_HeapReAlloc:
                        jmp     HeapReAlloc
                        retn


public my_HeapSetInformation
my_HeapSetInformation:
                        jmp     HeapSetInformation
                        retn


public my_HeapSize
my_HeapSize:
                        jmp     HeapSize
                        retn


public my_HeapSummary
my_HeapSummary:
                        jmp     HeapSummary
                        retn


public my_HeapUnlock
my_HeapUnlock:
                        jmp     HeapUnlock
                        retn


public my_HeapUsage
my_HeapUsage:
                        jmp     HeapUsage
                        retn


public my_HeapValidate
my_HeapValidate:
                        jmp     HeapValidate
                        retn


public my_HeapWalk
my_HeapWalk:
                        jmp     HeapWalk
                        retn


public my_InitAtomTable
my_InitAtomTable:
                        jmp     InitAtomTable
                        retn


public my_InitializeCriticalSection
my_InitializeCriticalSection:
                        jmp     InitializeCriticalSection
                        retn


public my_InitializeCriticalSectionAndSpinCount
my_InitializeCriticalSectionAndSpinCount:
                        jmp     InitializeCriticalSectionAndSpinCount
                        retn


public my_InitializeSListHead
my_InitializeSListHead:
                        jmp     InitializeSListHead
                        retn


public my_InterlockedCompareExchange
my_InterlockedCompareExchange:
                        jmp     InterlockedCompareExchange
                        retn


public my_InterlockedDecrement
my_InterlockedDecrement:
                        jmp     InterlockedDecrement
                        retn


public my_InterlockedExchange
my_InterlockedExchange:
                        jmp     InterlockedExchange
                        retn


public my_InterlockedExchangeAdd
my_InterlockedExchangeAdd:
                        jmp     InterlockedExchangeAdd
                        retn


public my_InterlockedFlushSList
my_InterlockedFlushSList:
                        jmp     InterlockedFlushSList
                        retn


public my_InterlockedIncrement
my_InterlockedIncrement:
                        jmp     InterlockedIncrement
                        retn


public my_InterlockedPopEntrySList
my_InterlockedPopEntrySList:
                        jmp     InterlockedPopEntrySList
                        retn


public my_InterlockedPushEntrySList
my_InterlockedPushEntrySList:
                        jmp     InterlockedPushEntrySList
                        retn


public my_InvalidateConsoleDIBits
my_InvalidateConsoleDIBits:
                        jmp     InvalidateConsoleDIBits
                        retn


public my_IsBadCodePtr
my_IsBadCodePtr:
                        jmp     IsBadCodePtr
                        retn


public my_IsBadHugeReadPtr
my_IsBadHugeReadPtr:
                        jmp     IsBadHugeReadPtr
                        retn


public my_IsBadHugeWritePtr
my_IsBadHugeWritePtr:
                        jmp     IsBadHugeWritePtr
                        retn


public my_IsBadReadPtr
my_IsBadReadPtr:
                        jmp     IsBadReadPtr
                        retn


public my_IsBadStringPtrA
my_IsBadStringPtrA:
                        jmp     IsBadStringPtrA
                        retn


public my_IsBadStringPtrW
my_IsBadStringPtrW:
                        jmp     IsBadStringPtrW
                        retn


public my_IsBadWritePtr
my_IsBadWritePtr:
                        jmp     IsBadWritePtr
                        retn


public my_IsDBCSLeadByte
my_IsDBCSLeadByte:
                        jmp     IsDBCSLeadByte
                        retn


public my_IsDBCSLeadByteEx
my_IsDBCSLeadByteEx:
                        jmp     IsDBCSLeadByteEx
                        retn


public my_IsDebuggerPresent
my_IsDebuggerPresent:
                        jmp     IsDebuggerPresent
                        retn


public my_IsProcessInJob
my_IsProcessInJob:
                        jmp     IsProcessInJob
                        retn


public my_IsProcessorFeaturePresent
my_IsProcessorFeaturePresent:
                        jmp     IsProcessorFeaturePresent
                        retn


public my_IsSystemResumeAutomatic
my_IsSystemResumeAutomatic:
                        jmp     IsSystemResumeAutomatic
                        retn


public my_IsValidCodePage
my_IsValidCodePage:
                        jmp     IsValidCodePage
                        retn


public my_IsValidLanguageGroup
my_IsValidLanguageGroup:
                        jmp     IsValidLanguageGroup
                        retn


public my_IsValidLocale
my_IsValidLocale:
                        jmp     IsValidLocale
                        retn


public my_IsValidUILanguage
my_IsValidUILanguage:
                        jmp     IsValidUILanguage
                        retn


public my_IsWow64Process
my_IsWow64Process:
                        jmp     IsWow64Process
                        retn


public my_LCMapStringA
my_LCMapStringA:
                        jmp     LCMapStringA
                        retn


public my_LCMapStringW
my_LCMapStringW:
                        jmp     LCMapStringW
                        retn


public my_LZClose
my_LZClose:
                        jmp     LZClose
                        retn


public my_LZCloseFile
my_LZCloseFile:
                        jmp     LZCloseFile
                        retn


public my_LZCopy
my_LZCopy:
                        jmp     LZCopy
                        retn


public my_LZCreateFileW
my_LZCreateFileW:
                        jmp     LZCreateFileW
                        retn


public my_LZDone
my_LZDone:
                        jmp     LZDone
                        retn


public my_LZInit
my_LZInit:
                        jmp     LZInit
                        retn


public my_LZOpenFileA
my_LZOpenFileA:
                        jmp     LZOpenFileA
                        retn


public my_LZOpenFileW
my_LZOpenFileW:
                        jmp     LZOpenFileW
                        retn


public my_LZRead
my_LZRead:
                        jmp     LZRead
                        retn


public my_LZSeek
my_LZSeek:
                        jmp     LZSeek
                        retn


public my_LZStart
my_LZStart:
                        jmp     LZStart
                        retn


public my_LeaveCriticalSection
my_LeaveCriticalSection:
                        jmp     LeaveCriticalSection
                        retn


buffer                  db      256     dup(0)
formatlla               db      "loading dll : %s", 0
public my_LoadLibraryA
my_LoadLibraryA:
                        pusha
                        mov     esi, [esp+24h]
                        call    wsprintfA, offset buffer, offset formatlla, esi
                        add     esp, 0ch
                        call    OutputDebugStringA, offset buffer
                        popa
                        jmp     LoadLibraryA
                        retn


public my_LoadLibraryExA
my_LoadLibraryExA:
                        jmp     LoadLibraryExA
                        retn


public my_LoadLibraryExW
my_LoadLibraryExW:
                        jmp     LoadLibraryExW
                        retn


public my_LoadLibraryW
my_LoadLibraryW:
                        jmp     LoadLibraryW
                        retn


public my_LoadModule
my_LoadModule:
                        jmp     LoadModule
                        retn


public my_LoadResource
my_LoadResource:
                        jmp     LoadResource
                        retn


public my_LocalAlloc
my_LocalAlloc:
                        jmp     LocalAlloc
                        retn


public my_LocalCompact
my_LocalCompact:
                        jmp     LocalCompact
                        retn


public my_LocalFileTimeToFileTime
my_LocalFileTimeToFileTime:
                        jmp     LocalFileTimeToFileTime
                        retn


public my_LocalFlags
my_LocalFlags:
                        jmp     LocalFlags
                        retn


public my_LocalFree
my_LocalFree:
                        jmp     LocalFree
                        retn


public my_LocalHandle
my_LocalHandle:
                        jmp     LocalHandle
                        retn


public my_LocalLock
my_LocalLock:
                        jmp     LocalLock
                        retn


public my_LocalReAlloc
my_LocalReAlloc:
                        jmp     LocalReAlloc
                        retn


public my_LocalShrink
my_LocalShrink:
                        jmp     LocalShrink
                        retn


public my_LocalSize
my_LocalSize:
                        jmp     LocalSize
                        retn


public my_LocalUnlock
my_LocalUnlock:
                        jmp     LocalUnlock
                        retn


public my_LockFile
my_LockFile:
                        jmp     LockFile
                        retn


public my_LockFileEx
my_LockFileEx:
                        jmp     LockFileEx
                        retn


public my_LockResource
my_LockResource:
                        jmp     LockResource
                        retn


public my_MapUserPhysicalPages
my_MapUserPhysicalPages:
                        jmp     MapUserPhysicalPages
                        retn


public my_MapUserPhysicalPagesScatter
my_MapUserPhysicalPagesScatter:
                        jmp     MapUserPhysicalPagesScatter
                        retn


public my_MapViewOfFile
my_MapViewOfFile:
                        jmp     MapViewOfFile
                        retn


public my_MapViewOfFileEx
my_MapViewOfFileEx:
                        jmp     MapViewOfFileEx
                        retn


public my_Module32First
my_Module32First:
                        jmp     Module32First
                        retn


public my_Module32FirstW
my_Module32FirstW:
                        jmp     Module32FirstW
                        retn


public my_Module32Next
my_Module32Next:
                        jmp     Module32Next
                        retn


public my_Module32NextW
my_Module32NextW:
                        jmp     Module32NextW
                        retn


public my_MoveFileA
my_MoveFileA:
                        jmp     MoveFileA
                        retn


public my_MoveFileExA
my_MoveFileExA:
                        jmp     MoveFileExA
                        retn


public my_MoveFileExW
my_MoveFileExW:
                        jmp     MoveFileExW
                        retn


public my_MoveFileW
my_MoveFileW:
                        jmp     MoveFileW
                        retn


public my_MoveFileWithProgressA
my_MoveFileWithProgressA:
                        jmp     MoveFileWithProgressA
                        retn


public my_MoveFileWithProgressW
my_MoveFileWithProgressW:
                        jmp     MoveFileWithProgressW
                        retn


public my_MulDiv
my_MulDiv:
                        jmp     MulDiv
                        retn


public my_MultiByteToWideChar
my_MultiByteToWideChar:
                        jmp     MultiByteToWideChar
                        retn


public my_NlsConvertIntegerToString
my_NlsConvertIntegerToString:
                        jmp     NlsConvertIntegerToString
                        retn


public my_NlsGetCacheUpdateCount
my_NlsGetCacheUpdateCount:
                        jmp     NlsGetCacheUpdateCount
                        retn


public my_NlsResetProcessLocale
my_NlsResetProcessLocale:
                        jmp     NlsResetProcessLocale
                        retn


public my_NumaVirtualQueryNode
my_NumaVirtualQueryNode:
                        jmp     NumaVirtualQueryNode
                        retn


public my_OpenConsoleW
my_OpenConsoleW:
                        jmp     OpenConsoleW
                        retn


public my_OpenDataFile
my_OpenDataFile:
                        jmp     OpenDataFile
                        retn


public my_OpenEventA
my_OpenEventA:
                        jmp     OpenEventA
                        retn


public my_OpenEventW
my_OpenEventW:
                        jmp     OpenEventW
                        retn


public my_OpenFile
my_OpenFile:
                        jmp     OpenFile
                        retn


public my_OpenFileMappingA
my_OpenFileMappingA:
                        jmp     OpenFileMappingA
                        retn


public my_OpenFileMappingW
my_OpenFileMappingW:
                        jmp     OpenFileMappingW
                        retn


public my_OpenJobObjectA
my_OpenJobObjectA:
                        jmp     OpenJobObjectA
                        retn


public my_OpenJobObjectW
my_OpenJobObjectW:
                        jmp     OpenJobObjectW
                        retn


public my_OpenMutexA
my_OpenMutexA:
                        jmp     OpenMutexA
                        retn


public my_OpenMutexW
my_OpenMutexW:
                        jmp     OpenMutexW
                        retn


formatop                db      "opening process : %.04X", 0
public my_OpenProcess
my_OpenProcess:         pusha
                        mov     esi, [esp+2ch]
                        call    wsprintfA, offset  buffer, offset formatop, esi
                        add     esp, 0ch
                        call    OutputDebugStringA, offset buffer
                        popa
                        jmp     OpenProcess
                        retn


public my_OpenProfileUserMapping
my_OpenProfileUserMapping:
                        jmp     OpenProfileUserMapping
                        retn


public my_OpenSemaphoreA
my_OpenSemaphoreA:
                        jmp     OpenSemaphoreA
                        retn


public my_OpenSemaphoreW
my_OpenSemaphoreW:
                        jmp     OpenSemaphoreW
                        retn


public my_OpenThread
my_OpenThread:
                        jmp     OpenThread
                        retn


public my_OpenWaitableTimerA
my_OpenWaitableTimerA:
                        jmp     OpenWaitableTimerA
                        retn


public my_OpenWaitableTimerW
my_OpenWaitableTimerW:
                        jmp     OpenWaitableTimerW
                        retn


public my_OutputDebugStringA
my_OutputDebugStringA:
                        jmp     OutputDebugStringA
                        retn


public my_OutputDebugStringW
my_OutputDebugStringW:
                        jmp     OutputDebugStringW
                        retn


public my_PeekConsoleInputA
my_PeekConsoleInputA:
                        jmp     PeekConsoleInputA
                        retn


public my_PeekConsoleInputW
my_PeekConsoleInputW:
                        jmp     PeekConsoleInputW
                        retn


public my_PeekNamedPipe
my_PeekNamedPipe:
                        jmp     PeekNamedPipe
                        retn


public my_PostQueuedCompletionStatus
my_PostQueuedCompletionStatus:
                        jmp     PostQueuedCompletionStatus
                        retn


public my_PrepareTape
my_PrepareTape:
                        jmp     PrepareTape
                        retn


public my_PrivCopyFileExW
my_PrivCopyFileExW:
                        jmp     PrivCopyFileExW
                        retn


public my_PrivMoveFileIdentityW
my_PrivMoveFileIdentityW:
                        jmp     PrivMoveFileIdentityW
                        retn


public my_Process32First
my_Process32First:
                        jmp     Process32First
                        retn


public my_Process32FirstW
my_Process32FirstW:
                        jmp     Process32FirstW
                        retn


public my_Process32Next
my_Process32Next:
                        jmp     Process32Next
                        retn


public my_Process32NextW
my_Process32NextW:
                        jmp     Process32NextW
                        retn


public my_ProcessIdToSessionId
my_ProcessIdToSessionId:
                        jmp     ProcessIdToSessionId
                        retn


public my_PulseEvent
my_PulseEvent:
                        jmp     PulseEvent
                        retn


public my_PurgeComm
my_PurgeComm:
                        jmp     PurgeComm
                        retn


public my_QueryActCtxW
my_QueryActCtxW:
                        jmp     QueryActCtxW
                        retn


public my_QueryDepthSList
my_QueryDepthSList:
                        jmp     QueryDepthSList
                        retn


public my_QueryDosDeviceA
my_QueryDosDeviceA:
                        jmp     QueryDosDeviceA
                        retn


public my_QueryDosDeviceW
my_QueryDosDeviceW:
                        jmp     QueryDosDeviceW
                        retn


public my_QueryInformationJobObject
my_QueryInformationJobObject:
                        jmp     QueryInformationJobObject
                        retn


public my_QueryMemoryResourceNotification
my_QueryMemoryResourceNotification:
                        jmp     QueryMemoryResourceNotification
                        retn


public my_QueryPerformanceCounter
my_QueryPerformanceCounter:
                        jmp     QueryPerformanceCounter
                        retn


public my_QueryPerformanceFrequency
my_QueryPerformanceFrequency:
                        jmp     QueryPerformanceFrequency
                        retn


public my_QueryWin31IniFilesMappedToRegistry
my_QueryWin31IniFilesMappedToRegistry:
                        jmp     QueryWin31IniFilesMappedToRegistry
                        retn


public my_QueueUserAPC
my_QueueUserAPC:
                        jmp     QueueUserAPC
                        retn


public my_QueueUserWorkItem
my_QueueUserWorkItem:
                        jmp     QueueUserWorkItem
                        retn


public my_RaiseException
my_RaiseException:
                        jmp     RaiseException
                        retn


public my_ReadConsoleA
my_ReadConsoleA:
                        jmp     ReadConsoleA
                        retn


public my_ReadConsoleInputA
my_ReadConsoleInputA:
                        jmp     ReadConsoleInputA
                        retn


public my_ReadConsoleInputExA
my_ReadConsoleInputExA:
                        jmp     ReadConsoleInputExA
                        retn


public my_ReadConsoleInputExW
my_ReadConsoleInputExW:
                        jmp     ReadConsoleInputExW
                        retn


public my_ReadConsoleInputW
my_ReadConsoleInputW:
                        jmp     ReadConsoleInputW
                        retn


public my_ReadConsoleOutputA
my_ReadConsoleOutputA:
                        jmp     ReadConsoleOutputA
                        retn


public my_ReadConsoleOutputAttribute
my_ReadConsoleOutputAttribute:
                        jmp     ReadConsoleOutputAttribute
                        retn


public my_ReadConsoleOutputCharacterA
my_ReadConsoleOutputCharacterA:
                        jmp     ReadConsoleOutputCharacterA
                        retn


public my_ReadConsoleOutputCharacterW
my_ReadConsoleOutputCharacterW:
                        jmp     ReadConsoleOutputCharacterW
                        retn


public my_ReadConsoleOutputW
my_ReadConsoleOutputW:
                        jmp     ReadConsoleOutputW
                        retn


public my_ReadConsoleW
my_ReadConsoleW:
                        jmp     ReadConsoleW
                        retn


public my_ReadDirectoryChangesW
my_ReadDirectoryChangesW:
                        jmp     ReadDirectoryChangesW
                        retn


public my_ReadFile
my_ReadFile:
                        jmp     ReadFile
                        retn


public my_ReadFileEx
my_ReadFileEx:
                        jmp     ReadFileEx
                        retn


public my_ReadFileScatter
my_ReadFileScatter:
                        jmp     ReadFileScatter
                        retn

rpmcalled               db      "ReadProcessMemory called",0
public my_ReadProcessMemory
my_ReadProcessMemory:
                        pusha
                        call    OutputDebugStringA, o rpmcalled
                        popa
                        xor     eax, eax
                        retn    14
                        jmp     ReadProcessMemory
                        retn


public my_RegisterConsoleIME
my_RegisterConsoleIME:
                        jmp     RegisterConsoleIME
                        retn


public my_RegisterConsoleOS2
my_RegisterConsoleOS2:
                        jmp     RegisterConsoleOS2
                        retn


public my_RegisterConsoleVDM
my_RegisterConsoleVDM:
                        jmp     RegisterConsoleVDM
                        retn


public my_RegisterWaitForInputIdle
my_RegisterWaitForInputIdle:
                        jmp     RegisterWaitForInputIdle
                        retn


public my_RegisterWaitForSingleObject
my_RegisterWaitForSingleObject:
                        jmp     RegisterWaitForSingleObject
                        retn


public my_RegisterWaitForSingleObjectEx
my_RegisterWaitForSingleObjectEx:
                        jmp     RegisterWaitForSingleObjectEx
                        retn


public my_RegisterWowBaseHandlers
my_RegisterWowBaseHandlers:
                        jmp     RegisterWowBaseHandlers
                        retn


public my_RegisterWowExec
my_RegisterWowExec:
                        jmp     RegisterWowExec
                        retn


public my_ReleaseActCtx
my_ReleaseActCtx:
                        jmp     ReleaseActCtx
                        retn


public my_ReleaseMutex
my_ReleaseMutex:
                        jmp     ReleaseMutex
                        retn


public my_ReleaseSemaphore
my_ReleaseSemaphore:
                        jmp     ReleaseSemaphore
                        retn


public my_RemoveDirectoryA
my_RemoveDirectoryA:
                        jmp     RemoveDirectoryA
                        retn


public my_RemoveDirectoryW
my_RemoveDirectoryW:
                        jmp     RemoveDirectoryW
                        retn


public my_RemoveLocalAlternateComputerNameA
my_RemoveLocalAlternateComputerNameA:
                        jmp     RemoveLocalAlternateComputerNameA
                        retn


public my_RemoveLocalAlternateComputerNameW
my_RemoveLocalAlternateComputerNameW:
                        jmp     RemoveLocalAlternateComputerNameW
                        retn


public my_RemoveVectoredExceptionHandler
my_RemoveVectoredExceptionHandler:
                        jmp     RemoveVectoredExceptionHandler
                        retn


public my_ReplaceFile
my_ReplaceFile:
                        jmp     ReplaceFile
                        retn


public my_ReplaceFileA
my_ReplaceFileA:
                        jmp     ReplaceFileA
                        retn


public my_ReplaceFileW
my_ReplaceFileW:
                        jmp     ReplaceFileW
                        retn


public my_RequestDeviceWakeup
my_RequestDeviceWakeup:
                        jmp     RequestDeviceWakeup
                        retn


public my_RequestWakeupLatency
my_RequestWakeupLatency:
                        jmp     RequestWakeupLatency
                        retn


public my_ResetEvent
my_ResetEvent:
                        jmp     ResetEvent
                        retn


public my_ResetWriteWatch
my_ResetWriteWatch:
                        jmp     ResetWriteWatch
                        retn


public my_RestoreLastError
my_RestoreLastError:
                        jmp     RestoreLastError
                        retn


public my_ResumeThread
my_ResumeThread:
                        jmp     ResumeThread
                        retn


public my_RtlCaptureContext
my_RtlCaptureContext:
                        jmp     RtlCaptureContext
                        retn


public my_RtlCaptureStackBackTrace
my_RtlCaptureStackBackTrace:
                        jmp     RtlCaptureStackBackTrace
                        retn


public my_RtlFillMemory
my_RtlFillMemory:
                        jmp     RtlFillMemory
                        retn


public my_RtlMoveMemory
my_RtlMoveMemory:
                        jmp     RtlMoveMemory
                        retn


public my_RtlUnwind
my_RtlUnwind:
                        jmp     RtlUnwind
                        retn


public my_RtlZeroMemory
my_RtlZeroMemory:
                        jmp     RtlZeroMemory
                        retn


public my_ScrollConsoleScreenBufferA
my_ScrollConsoleScreenBufferA:
                        jmp     ScrollConsoleScreenBufferA
                        retn


public my_ScrollConsoleScreenBufferW
my_ScrollConsoleScreenBufferW:
                        jmp     ScrollConsoleScreenBufferW
                        retn


public my_SearchPathA
my_SearchPathA:
                        jmp     SearchPathA
                        retn


public my_SearchPathW
my_SearchPathW:
                        jmp     SearchPathW
                        retn


public my_SetCPGlobal
my_SetCPGlobal:
                        jmp     SetCPGlobal
                        retn


public my_SetCalendarInfoA
my_SetCalendarInfoA:
                        jmp     SetCalendarInfoA
                        retn


public my_SetCalendarInfoW
my_SetCalendarInfoW:
                        jmp     SetCalendarInfoW
                        retn


public my_SetClientTimeZoneInformation
my_SetClientTimeZoneInformation:
                        jmp     SetClientTimeZoneInformation
                        retn


public my_SetComPlusPackageInstallStatus
my_SetComPlusPackageInstallStatus:
                        jmp     SetComPlusPackageInstallStatus
                        retn


public my_SetCommBreak
my_SetCommBreak:
                        jmp     SetCommBreak
                        retn


public my_SetCommConfig
my_SetCommConfig:
                        jmp     SetCommConfig
                        retn


public my_SetCommMask
my_SetCommMask:
                        jmp     SetCommMask
                        retn


public my_SetCommState
my_SetCommState:
                        jmp     SetCommState
                        retn


public my_SetCommTimeouts
my_SetCommTimeouts:
                        jmp     SetCommTimeouts
                        retn


public my_SetComputerNameA
my_SetComputerNameA:
                        jmp     SetComputerNameA
                        retn


public my_SetComputerNameExA
my_SetComputerNameExA:
                        jmp     SetComputerNameExA
                        retn


public my_SetComputerNameExW
my_SetComputerNameExW:
                        jmp     SetComputerNameExW
                        retn


public my_SetComputerNameW
my_SetComputerNameW:
                        jmp     SetComputerNameW
                        retn


public my_SetConsoleActiveScreenBuffer
my_SetConsoleActiveScreenBuffer:
                        jmp     SetConsoleActiveScreenBuffer
                        retn


public my_SetConsoleCP
my_SetConsoleCP:
                        jmp     SetConsoleCP
                        retn


public my_SetConsoleCommandHistoryMode
my_SetConsoleCommandHistoryMode:
                        jmp     SetConsoleCommandHistoryMode
                        retn


public my_SetConsoleCtrlHandler
my_SetConsoleCtrlHandler:
                        jmp     SetConsoleCtrlHandler
                        retn


public my_SetConsoleCursor
my_SetConsoleCursor:
                        jmp     SetConsoleCursor
                        retn


public my_SetConsoleCursorInfo
my_SetConsoleCursorInfo:
                        jmp     SetConsoleCursorInfo
                        retn


public my_SetConsoleCursorMode
my_SetConsoleCursorMode:
                        jmp     SetConsoleCursorMode
                        retn


public my_SetConsoleCursorPosition
my_SetConsoleCursorPosition:
                        jmp     SetConsoleCursorPosition
                        retn


public my_SetConsoleDisplayMode
my_SetConsoleDisplayMode:
                        jmp     SetConsoleDisplayMode
                        retn


public my_SetConsoleFont
my_SetConsoleFont:
                        jmp     SetConsoleFont
                        retn


public my_SetConsoleHardwareState
my_SetConsoleHardwareState:
                        jmp     SetConsoleHardwareState
                        retn


public my_SetConsoleIcon
my_SetConsoleIcon:
                        jmp     SetConsoleIcon
                        retn


public my_SetConsoleInputExeNameA
my_SetConsoleInputExeNameA:
                        jmp     SetConsoleInputExeNameA
                        retn


public my_SetConsoleInputExeNameW
my_SetConsoleInputExeNameW:
                        jmp     SetConsoleInputExeNameW
                        retn


public my_SetConsoleKeyShortcuts
my_SetConsoleKeyShortcuts:
                        jmp     SetConsoleKeyShortcuts
                        retn


public my_SetConsoleLocalEUDC
my_SetConsoleLocalEUDC:
                        jmp     SetConsoleLocalEUDC
                        retn


public my_SetConsoleMaximumWindowSize
my_SetConsoleMaximumWindowSize:
                        jmp     SetConsoleMaximumWindowSize
                        retn


public my_SetConsoleMenuClose
my_SetConsoleMenuClose:
                        jmp     SetConsoleMenuClose
                        retn


public my_SetConsoleMode
my_SetConsoleMode:
                        jmp     SetConsoleMode
                        retn


public my_SetConsoleNlsMode
my_SetConsoleNlsMode:
                        jmp     SetConsoleNlsMode
                        retn


public my_SetConsoleNumberOfCommandsA
my_SetConsoleNumberOfCommandsA:
                        jmp     SetConsoleNumberOfCommandsA
                        retn


public my_SetConsoleNumberOfCommandsW
my_SetConsoleNumberOfCommandsW:
                        jmp     SetConsoleNumberOfCommandsW
                        retn


public my_SetConsoleOS2OemFormat
my_SetConsoleOS2OemFormat:
                        jmp     SetConsoleOS2OemFormat
                        retn


public my_SetConsoleOutputCP
my_SetConsoleOutputCP:
                        jmp     SetConsoleOutputCP
                        retn


public my_SetConsolePalette
my_SetConsolePalette:
                        jmp     SetConsolePalette
                        retn


public my_SetConsoleScreenBufferSize
my_SetConsoleScreenBufferSize:
                        jmp     SetConsoleScreenBufferSize
                        retn


public my_SetConsoleTextAttribute
my_SetConsoleTextAttribute:
                        jmp     SetConsoleTextAttribute
                        retn


public my_SetConsoleTitleA
my_SetConsoleTitleA:
                        jmp     SetConsoleTitleA
                        retn


public my_SetConsoleTitleW
my_SetConsoleTitleW:
                        jmp     SetConsoleTitleW
                        retn


public my_SetConsoleWindowInfo
my_SetConsoleWindowInfo:
                        jmp     SetConsoleWindowInfo
                        retn


public my_SetCriticalSectionSpinCount
my_SetCriticalSectionSpinCount:
                        jmp     SetCriticalSectionSpinCount
                        retn


public my_SetCurrentDirectoryA
my_SetCurrentDirectoryA:
                        jmp     SetCurrentDirectoryA
                        retn


public my_SetCurrentDirectoryW
my_SetCurrentDirectoryW:
                        jmp     SetCurrentDirectoryW
                        retn


public my_SetDefaultCommConfigA
my_SetDefaultCommConfigA:
                        jmp     SetDefaultCommConfigA
                        retn


public my_SetDefaultCommConfigW
my_SetDefaultCommConfigW:
                        jmp     SetDefaultCommConfigW
                        retn


public my_SetDllDirectoryA
my_SetDllDirectoryA:
                        jmp     SetDllDirectoryA
                        retn


public my_SetDllDirectoryW
my_SetDllDirectoryW:
                        jmp     SetDllDirectoryW
                        retn


public my_SetEndOfFile
my_SetEndOfFile:
                        jmp     SetEndOfFile
                        retn


public my_SetEnvironmentVariableA
my_SetEnvironmentVariableA:
                        jmp     SetEnvironmentVariableA
                        retn


public my_SetEnvironmentVariableW
my_SetEnvironmentVariableW:
                        jmp     SetEnvironmentVariableW
                        retn


public my_SetErrorMode
my_SetErrorMode:
                        jmp     SetErrorMode
                        retn


public my_SetEvent
my_SetEvent:
                        jmp     SetEvent
                        retn


public my_SetFileApisToANSI
my_SetFileApisToANSI:
                        jmp     SetFileApisToANSI
                        retn


public my_SetFileApisToOEM
my_SetFileApisToOEM:
                        jmp     SetFileApisToOEM
                        retn


public my_SetFileAttributesA
my_SetFileAttributesA:
                        jmp     SetFileAttributesA
                        retn


public my_SetFileAttributesW
my_SetFileAttributesW:
                        jmp     SetFileAttributesW
                        retn


public my_SetFilePointer
my_SetFilePointer:
                        jmp     SetFilePointer
                        retn


public my_SetFilePointerEx
my_SetFilePointerEx:
                        jmp     SetFilePointerEx
                        retn


public my_SetFileShortNameA
my_SetFileShortNameA:
                        jmp     SetFileShortNameA
                        retn


public my_SetFileShortNameW
my_SetFileShortNameW:
                        jmp     SetFileShortNameW
                        retn


public my_SetFileTime
my_SetFileTime:
                        jmp     SetFileTime
                        retn


public my_SetFileValidData
my_SetFileValidData:
                        jmp     SetFileValidData
                        retn


public my_SetFirmwareEnvironmentVariableA
my_SetFirmwareEnvironmentVariableA:
                        jmp     SetFirmwareEnvironmentVariableA
                        retn


public my_SetFirmwareEnvironmentVariableW
my_SetFirmwareEnvironmentVariableW:
                        jmp     SetFirmwareEnvironmentVariableW
                        retn


public my_SetHandleContext
my_SetHandleContext:
                        jmp     SetHandleContext
                        retn


public my_SetHandleCount
my_SetHandleCount:
                        jmp     SetHandleCount
                        retn


public my_SetHandleInformation
my_SetHandleInformation:
                        jmp     SetHandleInformation
                        retn


public my_SetInformationJobObject
my_SetInformationJobObject:
                        jmp     SetInformationJobObject
                        retn


public my_SetLastConsoleEventActive
my_SetLastConsoleEventActive:
                        jmp     SetLastConsoleEventActive
                        retn


public my_SetLastError
my_SetLastError:
                        jmp     SetLastError
                        retn


public my_SetLocalPrimaryComputerNameA
my_SetLocalPrimaryComputerNameA:
                        jmp     SetLocalPrimaryComputerNameA
                        retn


public my_SetLocalPrimaryComputerNameW
my_SetLocalPrimaryComputerNameW:
                        jmp     SetLocalPrimaryComputerNameW
                        retn


public my_SetLocalTime
my_SetLocalTime:
                        jmp     SetLocalTime
                        retn


public my_SetLocaleInfoA
my_SetLocaleInfoA:
                        jmp     SetLocaleInfoA
                        retn


public my_SetLocaleInfoW
my_SetLocaleInfoW:
                        jmp     SetLocaleInfoW
                        retn


public my_SetMailslotInfo
my_SetMailslotInfo:
                        jmp     SetMailslotInfo
                        retn


public my_SetMessageWaitingIndicator
my_SetMessageWaitingIndicator:
                        jmp     SetMessageWaitingIndicator
                        retn


public my_SetNamedPipeHandleState
my_SetNamedPipeHandleState:
                        jmp     SetNamedPipeHandleState
                        retn


public my_SetPriorityClass
my_SetPriorityClass:
                        jmp     SetPriorityClass
                        retn


public my_SetProcessAffinityMask
my_SetProcessAffinityMask:
                        jmp     SetProcessAffinityMask
                        retn


public my_SetProcessPriorityBoost
my_SetProcessPriorityBoost:
                        jmp     SetProcessPriorityBoost
                        retn


public my_SetProcessShutdownParameters
my_SetProcessShutdownParameters:
                        jmp     SetProcessShutdownParameters
                        retn


public my_SetProcessWorkingSetSize
my_SetProcessWorkingSetSize:
                        jmp     SetProcessWorkingSetSize
                        retn


public my_SetStdHandle
my_SetStdHandle:
                        jmp     SetStdHandle
                        retn


public my_SetSystemPowerState
my_SetSystemPowerState:
                        jmp     SetSystemPowerState
                        retn


public my_SetSystemTime
my_SetSystemTime:
                        jmp     SetSystemTime
                        retn


public my_SetSystemTimeAdjustment
my_SetSystemTimeAdjustment:
                        jmp     SetSystemTimeAdjustment
                        retn


public my_SetTapeParameters
my_SetTapeParameters:
                        jmp     SetTapeParameters
                        retn


public my_SetTapePosition
my_SetTapePosition:
                        jmp     SetTapePosition
                        retn


public my_SetTermsrvAppInstallMode
my_SetTermsrvAppInstallMode:
                        jmp     SetTermsrvAppInstallMode
                        retn


public my_SetThreadAffinityMask
my_SetThreadAffinityMask:
                        jmp     SetThreadAffinityMask
                        retn


public my_SetThreadContext
my_SetThreadContext:
                        jmp     SetThreadContext
                        retn


public my_SetThreadExecutionState
my_SetThreadExecutionState:
                        jmp     SetThreadExecutionState
                        retn


public my_SetThreadIdealProcessor
my_SetThreadIdealProcessor:
                        jmp     SetThreadIdealProcessor
                        retn


public my_SetThreadLocale
my_SetThreadLocale:
                        jmp     SetThreadLocale
                        retn


public my_SetThreadPriority
my_SetThreadPriority:
                        jmp     SetThreadPriority
                        retn


public my_SetThreadPriorityBoost
my_SetThreadPriorityBoost:
                        jmp     SetThreadPriorityBoost
                        retn


public my_SetThreadUILanguage
my_SetThreadUILanguage:
                        jmp     SetThreadUILanguage
                        retn


public my_SetTimeZoneInformation
my_SetTimeZoneInformation:
                        jmp     SetTimeZoneInformation
                        retn


public my_SetTimerQueueTimer
my_SetTimerQueueTimer:
                        jmp     SetTimerQueueTimer
                        retn


public my_SetUnhandledExceptionFilter
my_SetUnhandledExceptionFilter:
                        jmp     SetUnhandledExceptionFilter
                        retn


public my_SetUserGeoID
my_SetUserGeoID:
                        jmp     SetUserGeoID
                        retn


public my_SetVDMCurrentDirectories
my_SetVDMCurrentDirectories:
                        jmp     SetVDMCurrentDirectories
                        retn


public my_SetVolumeLabelA
my_SetVolumeLabelA:
                        jmp     SetVolumeLabelA
                        retn


public my_SetVolumeLabelW
my_SetVolumeLabelW:
                        jmp     SetVolumeLabelW
                        retn


public my_SetVolumeMountPointA
my_SetVolumeMountPointA:
                        jmp     SetVolumeMountPointA
                        retn


public my_SetVolumeMountPointW
my_SetVolumeMountPointW:
                        jmp     SetVolumeMountPointW
                        retn


public my_SetWaitableTimer
my_SetWaitableTimer:
                        jmp     SetWaitableTimer
                        retn


public my_SetupComm
my_SetupComm:
                        jmp     SetupComm
                        retn


public my_ShowConsoleCursor
my_ShowConsoleCursor:
                        jmp     ShowConsoleCursor
                        retn


public my_SignalObjectAndWait
my_SignalObjectAndWait:
                        jmp     SignalObjectAndWait
                        retn


public my_SizeofResource
my_SizeofResource:
                        jmp     SizeofResource
                        retn


public my_Sleep
my_Sleep:
                        jmp     Sleep
                        retn


public my_SleepEx
my_SleepEx:
                        jmp     SleepEx
                        retn


public my_SuspendThread
my_SuspendThread:
                        jmp     SuspendThread
                        retn


public my_SwitchToFiber
my_SwitchToFiber:
                        jmp     SwitchToFiber
                        retn


public my_SwitchToThread
my_SwitchToThread:
                        jmp     SwitchToThread
                        retn


public my_SystemTimeToFileTime
my_SystemTimeToFileTime:
                        jmp     SystemTimeToFileTime
                        retn


public my_SystemTimeToTzSpecificLocalTime
my_SystemTimeToTzSpecificLocalTime:
                        jmp     SystemTimeToTzSpecificLocalTime
                        retn


public my_TerminateJobObject
my_TerminateJobObject:
                        jmp     TerminateJobObject
                        retn


public my_TerminateProcess
my_TerminateProcess:
                        jmp     TerminateProcess
                        retn


public my_TerminateThread
my_TerminateThread:
                        jmp     TerminateThread
                        retn


public my_TermsrvAppInstallMode
my_TermsrvAppInstallMode:
                        jmp     TermsrvAppInstallMode
                        retn


public my_Thread32First
my_Thread32First:
                        jmp     Thread32First
                        retn


public my_Thread32Next
my_Thread32Next:
                        jmp     Thread32Next
                        retn


public my_TlsAlloc
my_TlsAlloc:
                        jmp     TlsAlloc
                        retn


public my_TlsFree
my_TlsFree:
                        jmp     TlsFree
                        retn


public my_TlsGetValue
my_TlsGetValue:
                        jmp     TlsGetValue
                        retn


public my_TlsSetValue
my_TlsSetValue:
                        jmp     TlsSetValue
                        retn


public my_Toolhelp32ReadProcessMemory
my_Toolhelp32ReadProcessMemory:
                        jmp     Toolhelp32ReadProcessMemory
                        retn


public my_TransactNamedPipe
my_TransactNamedPipe:
                        jmp     TransactNamedPipe
                        retn


public my_TransmitCommChar
my_TransmitCommChar:
                        jmp     TransmitCommChar
                        retn


public my_TrimVirtualBuffer
my_TrimVirtualBuffer:
                        jmp     TrimVirtualBuffer
                        retn


public my_TryEnterCriticalSection
my_TryEnterCriticalSection:
                        jmp     TryEnterCriticalSection
                        retn


public my_TzSpecificLocalTimeToSystemTime
my_TzSpecificLocalTimeToSystemTime:
                        jmp     TzSpecificLocalTimeToSystemTime
                        retn


public my_UTRegister
my_UTRegister:
                        jmp     UTRegister
                        retn


public my_UTUnRegister
my_UTUnRegister:
                        jmp     UTUnRegister
                        retn


public my_UnhandledExceptionFilter
my_UnhandledExceptionFilter:
                        jmp     UnhandledExceptionFilter
                        retn


public my_UnlockFile
my_UnlockFile:
                        jmp     UnlockFile
                        retn


public my_UnlockFileEx
my_UnlockFileEx:
                        jmp     UnlockFileEx
                        retn


public my_UnmapViewOfFile
my_UnmapViewOfFile:
                        jmp     UnmapViewOfFile
                        retn


public my_UnregisterConsoleIME
my_UnregisterConsoleIME:
                        jmp     UnregisterConsoleIME
                        retn


public my_UnregisterWait
my_UnregisterWait:
                        jmp     UnregisterWait
                        retn


public my_UnregisterWaitEx
my_UnregisterWaitEx:
                        jmp     UnregisterWaitEx
                        retn


public my_UpdateResourceA
my_UpdateResourceA:
                        jmp     UpdateResourceA
                        retn


public my_UpdateResourceW
my_UpdateResourceW:
                        jmp     UpdateResourceW
                        retn


public my_VDMConsoleOperation
my_VDMConsoleOperation:
                        jmp     VDMConsoleOperation
                        retn


public my_VDMOperationStarted
my_VDMOperationStarted:
                        jmp     VDMOperationStarted
                        retn


public my_ValidateLCType
my_ValidateLCType:
                        jmp     ValidateLCType
                        retn


public my_ValidateLocale
my_ValidateLocale:
                        jmp     ValidateLocale
                        retn


public my_VerLanguageNameA
my_VerLanguageNameA:
                        jmp     VerLanguageNameA
                        retn


public my_VerLanguageNameW
my_VerLanguageNameW:
                        jmp     VerLanguageNameW
                        retn


public my_VerSetConditionMask
my_VerSetConditionMask:
                        jmp     VerSetConditionMask
                        retn


public my_VerifyConsoleIoHandle
my_VerifyConsoleIoHandle:
                        jmp     VerifyConsoleIoHandle
                        retn


public my_VerifyVersionInfoA
my_VerifyVersionInfoA:
                        jmp     VerifyVersionInfoA
                        retn


public my_VerifyVersionInfoW
my_VerifyVersionInfoW:
                        jmp     VerifyVersionInfoW
                        retn


public my_VirtualAlloc
my_VirtualAlloc:
                        jmp     VirtualAlloc
                        retn


public my_VirtualAllocEx
my_VirtualAllocEx:
                        jmp     VirtualAllocEx
                        retn


public my_VirtualBufferExceptionHandler
my_VirtualBufferExceptionHandler:
                        jmp     VirtualBufferExceptionHandler
                        retn


public my_VirtualFree
my_VirtualFree:
                        jmp     VirtualFree
                        retn


public my_VirtualFreeEx
my_VirtualFreeEx:
                        jmp     VirtualFreeEx
                        retn


public my_VirtualLock
my_VirtualLock:
                        jmp     VirtualLock
                        retn


public my_VirtualProtect
my_VirtualProtect:
                        jmp     VirtualProtect
                        retn


public my_VirtualProtectEx
my_VirtualProtectEx:
                        jmp     VirtualProtectEx
                        retn


public my_VirtualQuery
my_VirtualQuery:
                        jmp     VirtualQuery
                        retn


public my_VirtualQueryEx
my_VirtualQueryEx:
                        jmp     VirtualQueryEx
                        retn


public my_VirtualUnlock
my_VirtualUnlock:
                        jmp     VirtualUnlock
                        retn


public my_WTSGetActiveConsoleSessionId
my_WTSGetActiveConsoleSessionId:
                        jmp     WTSGetActiveConsoleSessionId
                        retn


public my_WaitCommEvent
my_WaitCommEvent:
                        jmp     WaitCommEvent
                        retn


public my_WaitForDebugEvent
my_WaitForDebugEvent:
                        jmp     WaitForDebugEvent
                        retn


public my_WaitForMultipleObjects
my_WaitForMultipleObjects:
                        jmp     WaitForMultipleObjects
                        retn


public my_WaitForMultipleObjectsEx
my_WaitForMultipleObjectsEx:
                        jmp     WaitForMultipleObjectsEx
                        retn


public my_WaitForSingleObject
my_WaitForSingleObject:
                        jmp     WaitForSingleObject
                        retn


public my_WaitForSingleObjectEx
my_WaitForSingleObjectEx:
                        jmp     WaitForSingleObjectEx
                        retn


public my_WaitNamedPipeA
my_WaitNamedPipeA:
                        jmp     WaitNamedPipeA
                        retn


public my_WaitNamedPipeW
my_WaitNamedPipeW:
                        jmp     WaitNamedPipeW
                        retn


public my_WideCharToMultiByte
my_WideCharToMultiByte:
                        jmp     WideCharToMultiByte
                        retn


public my_WinExec
my_WinExec:
                        jmp     WinExec
                        retn


public my_WriteConsoleA
my_WriteConsoleA:
                        jmp     WriteConsoleA
                        retn


public my_WriteConsoleInputA
my_WriteConsoleInputA:
                        jmp     WriteConsoleInputA
                        retn


public my_WriteConsoleInputVDMA
my_WriteConsoleInputVDMA:
                        jmp     WriteConsoleInputVDMA
                        retn


public my_WriteConsoleInputVDMW
my_WriteConsoleInputVDMW:
                        jmp     WriteConsoleInputVDMW
                        retn


public my_WriteConsoleInputW
my_WriteConsoleInputW:
                        jmp     WriteConsoleInputW
                        retn


public my_WriteConsoleOutputA
my_WriteConsoleOutputA:
                        jmp     WriteConsoleOutputA
                        retn


public my_WriteConsoleOutputAttribute
my_WriteConsoleOutputAttribute:
                        jmp     WriteConsoleOutputAttribute
                        retn


public my_WriteConsoleOutputCharacterA
my_WriteConsoleOutputCharacterA:
                        jmp     WriteConsoleOutputCharacterA
                        retn


public my_WriteConsoleOutputCharacterW
my_WriteConsoleOutputCharacterW:
                        jmp     WriteConsoleOutputCharacterW
                        retn


public my_WriteConsoleOutputW
my_WriteConsoleOutputW:
                        jmp     WriteConsoleOutputW
                        retn


public my_WriteConsoleW
my_WriteConsoleW:
                        jmp     WriteConsoleW
                        retn


public my_WriteFile
my_WriteFile:
                        jmp     WriteFile
                        retn


public my_WriteFileEx
my_WriteFileEx:
                        jmp     WriteFileEx
                        retn


public my_WriteFileGather
my_WriteFileGather:
                        jmp     WriteFileGather
                        retn


public my_WritePrivateProfileSectionA
my_WritePrivateProfileSectionA:
                        jmp     WritePrivateProfileSectionA
                        retn


public my_WritePrivateProfileSectionW
my_WritePrivateProfileSectionW:
                        jmp     WritePrivateProfileSectionW
                        retn


public my_WritePrivateProfileStringA
my_WritePrivateProfileStringA:
                        jmp     WritePrivateProfileStringA
                        retn


public my_WritePrivateProfileStringW
my_WritePrivateProfileStringW:
                        jmp     WritePrivateProfileStringW
                        retn


public my_WritePrivateProfileStructA
my_WritePrivateProfileStructA:
                        jmp     WritePrivateProfileStructA
                        retn


public my_WritePrivateProfileStructW
my_WritePrivateProfileStructW:
                        jmp     WritePrivateProfileStructW
                        retn


public my_WriteProcessMemory
my_WriteProcessMemory:
                        jmp     WriteProcessMemory
                        retn


public my_WriteProfileSectionA
my_WriteProfileSectionA:
                        jmp     WriteProfileSectionA
                        retn


public my_WriteProfileSectionW
my_WriteProfileSectionW:
                        jmp     WriteProfileSectionW
                        retn


public my_WriteProfileStringA
my_WriteProfileStringA:
                        jmp     WriteProfileStringA
                        retn


public my_WriteProfileStringW
my_WriteProfileStringW:
                        jmp     WriteProfileStringW
                        retn


public my_WriteTapemark
my_WriteTapemark:
                        jmp     WriteTapemark
                        retn


public my_ZombifyActCtx
my_ZombifyActCtx:
                        jmp     ZombifyActCtx
                        retn


public my__hread
my__hread:
                        jmp     _hread
                        retn


public my__hwrite
my__hwrite:
                        jmp     _hwrite
                        retn


public my__lclose
my__lclose:
                        jmp     _lclose
                        retn


public my__lcreat
my__lcreat:
                        jmp     _lcreat
                        retn


public my__llseek
my__llseek:
                        jmp     _llseek
                        retn


public my__lopen
my__lopen:
                        jmp     _lopen
                        retn


public my__lread
my__lread:
                        jmp     _lread
                        retn


public my__lwrite
my__lwrite:
                        jmp     _lwrite
                        retn


public my_lstrcat
my_lstrcat:
                        jmp     lstrcat
                        retn


public my_lstrcatA
my_lstrcatA:
                        jmp     lstrcatA
                        retn


public my_lstrcatW
my_lstrcatW:
                        jmp     lstrcatW
                        retn


public my_lstrcmp
my_lstrcmp:
                        jmp     lstrcmp
                        retn


public my_lstrcmpA
my_lstrcmpA:
                        jmp     lstrcmpA
                        retn


public my_lstrcmpW
my_lstrcmpW:
                        jmp     lstrcmpW
                        retn


public my_lstrcmpi
my_lstrcmpi:
                        jmp     lstrcmpi
                        retn


public my_lstrcmpiA
my_lstrcmpiA:
                        jmp     lstrcmpiA
                        retn


public my_lstrcmpiW
my_lstrcmpiW:
                        jmp     lstrcmpiW
                        retn


public my_lstrcpy
my_lstrcpy:
                        jmp     lstrcpy
                        retn


public my_lstrcpyA
my_lstrcpyA:
                        jmp     lstrcpyA
                        retn


public my_lstrcpyW
my_lstrcpyW:
                        jmp     lstrcpyW
                        retn


public my_lstrcpyn
my_lstrcpyn:
                        jmp     lstrcpyn
                        retn


public my_lstrcpynA
my_lstrcpynA:
                        jmp     lstrcpynA
                        retn


public my_lstrcpynW
my_lstrcpynW:
                        jmp     lstrcpynW
                        retn


public my_lstrlen
my_lstrlen:
                        jmp     lstrlen
                        retn


public my_lstrlenA
my_lstrlenA:
                        jmp     lstrlenA
                        retn


public my_lstrlenW
my_lstrlenW:
                        jmp     lstrlenW
                        retn
                        
end                     start


