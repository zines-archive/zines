                        .586p
                        .model  flat, stdcall
                        locals
                        jumps
                        
include                 c:\tasm32\include\shitheap.inc
include                 c:\tasm32\include\extern.inc

                        .data
pinfo                   process_information <>
sinfo                   startupinfo <>
ctx                     context <>
entrypoint              dd      ?
tls                     dd      ?
tlscallback             dd      ?

fake_k32:               unis    <fake_k32.dll>
fake_k32_size           =       $-fake_k32

k32                     db      "kernel32.dll", 0
argc                    dd      ?
argv                    dd      ?
int3h                   db      0cch
infinite                db      0ebh, 0feh
oldbyt                  dw      ?
peheader                db      1024    dup(0)
ptitle                  db      "PEB dll hook   - (c) 2006 deroko/ARTeam", 13, 10
                        db      "usage : loader [-b|-t|-h] <target_program>", 13, 10, 0
executing               db      "[*] Executing target process", 13, 10, 0
injected                db      "[*] fake_k32.dll injected in target process", 13, 10, 0
helpme                  db      13, 10
                        db      "PEB dll hook demonstrates attack using dll hooking", 13, 10
                        db      "via PEB and it is injecting fake_k32.dll in target", 13, 10
                        db      "process. Currently fake_k32.dll only hooks CreateFileA", 13, 10
                        db      "and will log access to files, make sure that DbgMon", 13, 10
                        db      "or DebugView is on", 13, 10
                        db      "usage : loader [-b|-t|-h] <target_program>", 13, 10
                        db      "options:", 13, 10
                        db      " -b  - to break in target process before EP is reached", 13, 10
                        db      "       bpint 3 or i3here on in SoftICE is required", 13, 10
                        db      " -t  - same as -b but breaks before TLS callback", 13, 10
                        db      " -h  - help", 13, 10, 0
dummy                   dd      ?
                        .code
public  C start
start:                  call    stdout, offset ptitle
                        call    GetCommandLineW
                        call    CommandLineToArgvW, eax, offset argc
                        mov     argv, eax
                        cmp     argc, 1
                        je      __help
                        
                        mov     eax, [eax+4]
                        mov     edi, eax
                        mov     eax, [eax]
                        rol     ax, 8
                        shr     eax,8
                        cmp     ax, 'h-'
                        je      __help
                        cmp     ax, 'b-'
                        jne     __cont
                        mov     byte ptr[break_ep], 0cch
                        mov     edi, argv
                        mov     edi, [edi+8]
__cont:                 cmp     ax, 't-'
                        jne     __cont1
                        mov     edi, argv
                        mov     edi, [edi+8]
                        mov     tls, 1
                        
__cont1:                call    CreateFileW, edi, GENERIC_READ, 0,0, OPEN_EXISTING, 0, 0
                        xchg    eax, esi
                        call    ReadFile, esi, o peheader, 1024, esp, 0
                        mov     ebx, offset peheader
                        add     ebx, [ebx+3ch]
                        mov     eax, [ebx.pe_imagebase]
                        add     eax, [ebx.pe_addressofentrypoint]
                        mov     entrypoint, eax
                        call    CloseHandle, esi                         
                        
                        call    stdout, offset executing                        
                        call    CreateProcessW, edi, 0, 0,0,0, CREATE_SUSPENDED, 0, 0,o sinfo, o pinfo
                        
                        mov     ctx.context_ContextFlags, CONTEXT_FULL
                        
                        call    VirtualAllocEx, pinfo.pi_hProcess, 0, 1000h, MEM_COMMIT, PAGE_EXECUTE_READWRITE
                        xchg    eax, ebx
                        
                        cmp     tls, 1
                        jne     __skip0

                        mov     ebx, offset peheader
                        add     ebx, [ebx+3ch]
                        mov     eax, [ebx.pe_imagebase]
                        add     eax, [ebx.pe_tls]
                        add     eax, 0ch 
                        
                        call    ReadProcessMemory, pinfo.pi_hProcess, eax, o tlscallback, 4, 0
                        call    ReadProcessMemory, pinfo.pi_hProcess, tlscallback, o entrypoint, 4, 0
                        mov     byte ptr[break_ep], 0cch

__skip0:                mov     eax, entrypoint
                        mov     dword ptr[my_code+1],eax
                        call    GetModuleHandleA, o k32
                        mov     kernel32, eax
                        call    WriteProcessMemory, pinfo.pi_hProcess, ebx, o my_code, size_my_code, 0
                        call    ReadProcessMemory, pinfo.pi_hProcess, entrypoint, o oldbyt, 2, 0
                        call    WriteProcessMemory, pinfo.pi_hProcess, entrypoint, o infinite, 2, 0

                        call    VirtualProtectEx, pinfo.pi_hProcess, 7C922538h, 1000h, PAGE_EXECUTE_READWRITE, o dummy
                        call    WriteProcessMemory, pinfo.pi_hProcess, 7C922538h, o fake_k32, fake_k32_size, 0

                        call    stdout, offset injected

                        call    ResumeThread, pinfo.pi_hThread
                        call    Sleep, 100
                        call    SuspendThread, pinfo.pi_hThread
                        
                        call    WriteProcessMemory, pinfo.pi_hProcess, entrypoint, o oldbyt, 2, 0
                        call    GetThreadContext, pinfo.pi_hThread, o ctx
                        mov     ctx.context_eip, ebx
                        call    SetThreadContext, pinfo.pi_hThread, o ctx
                        call    ResumeThread, pinfo.pi_hThread
                        call    ExitProcess, 0

__help:                 call    stdout, offset helpme
                        call    ExitProcess, 0

stdout:                 pusha
                        call    GetStdHandle, -11
                        mov     ebx, eax
                        mov     esi, [esp+24h]
                        mov     edi, esi
                        cld
__strlen:               lodsb
                        test    al, al
                        jnz     __strlen
                        sub     esi, [esp+24h]
                        dec     esi
                        call    WriteFile, ebx, edi, esi, esp, 0
                        popa
                        retn    4

my_code:                push    0deadc0deh
                        pusha
                        call    delta
delta:                  pop     ebp
                        sub     ebp, offset delta
                       
                        gethash <LoadLibraryA>
                        call    getprocaddress, [ebp+kernel32], hash
                        mov     [ebp+loadlibrarya], eax
                        gethash <GetModuleHandleA>
                        call    getprocaddress, [ebp+kernel32], hash
                        mov     [ebp+getmodulehandlea], eax
                        
                        x_push  ebx, <fake_k32.dll~>
                        push    esp
                        call    [ebp+loadlibrarya]
                        x_pop

                        x_push  ebx, <kernel32.dll~>
                        push    esp
                        call    [ebp+getmodulehandlea]
                        x_pop
                        ;mov     [esp+24h], eax                        
                        ;xchg    eax, ebx

                        ;mov     edi, 45e5000h
                        ;gethash <CreateFileA>
                        ;call    getprocaddress, ebx, hash
                        ;stosd
                        ;gethash <ExitProcess>
                        ;call    getprocaddress, ebx, hash
                        ;stosd
                                         
                        popa
break_ep:               nop
                        retn

kernel32                dd      ?
loadlibrarya            dd      ?
getmodulehandlea        dd      ?
include                 .\apizloader.inc
size_my_code            =       $-my_code                        
                        end     start
