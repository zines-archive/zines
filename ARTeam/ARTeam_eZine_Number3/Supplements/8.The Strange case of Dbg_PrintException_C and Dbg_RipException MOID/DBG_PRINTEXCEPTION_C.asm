;xADT plugin to check DBG_PRINTEXCEPTION_C by MOID/TSRh
;Assemble with NASM, hereby released into the public domain.

;I got the idea from dsei @ rootkit.com
;http://www.rootkit.com/board.php?thread=3360&did=edge284&disp=3360

;Basically, it checks if DBG_PRINTEXCEPTION_C goes to the SEH or not.
;See http://www.openrce.org/articles/full_view/25 for more info

;The only way I know to circumvent this is to patch ntdll (either on disk or in memory in the context of the debugger)
;You need to find "cmp ecx, 40010006h" in DbgUiConvertStateChangeStructure and patch the jnz to jmp

;Note that any attempt to output a debug string will raise exception 40010006 after this patch.
;So it's best to disable all debug strings by patching OutputDebugStringA or using HideOD.

;You should patch the next one (40010007) too, because this will throw a RIP_EVENT.
;This exception is swallowed too, but because Olly breaks on RIP_EVENT it isn't very sneaky.

%macro callW 1		;easy extern declaration
extern %1
call %1
%endmacro

%macro dll_export 1
GLOBAL %1
EXPORT %1
%1:
%endmacro

%define UNKNOWN 0
%define NEGATIVE 1
%define WARNING 2
%define POSITIVE 3

%define DBG_PRINTEXCEPTION_C 0x40010006

[SECTION MOIDTSRh USE32 READABLE WRITEABLE EXECUTABLE]
..start:
xor eax, eax
inc eax
ret

dll_export tst_DBG_PRINTEXCEPTION_C_description
mov eax, description
ret

dll_export tst_DBG_PRINTEXCEPTION_C_name
mov eax, name
ret

dll_export tst_DBG_PRINTEXCEPTION_C_about
mov eax, about
ret

dll_export tst_DBG_PRINTEXCEPTION_C
;First, set up a SEH frame
push seh
push dword [fs:0]
mov dword [fs:0], esp

xor eax, eax
mov dword [return_code], POSITIVE       ;If its swallowed, it is positive

push eax
push eax
push eax
push DBG_PRINTEXCEPTION_C
callW RaiseException

pop dword [fs:0]
pop eax

mov eax, [return_code]
ret

;This is the SEH handler
;int __cdecl seh(*EXCEPTION_RECORD, ERR, *CONTEXT)
;See http://www.jorgon.freeserve.co.uk/ExceptFrame.htm for more info

seh:
;Get exception code (EXCEPTION_RECORD.ExceptionCode)
mov eax, [esp+4]
mov eax, [eax]

cmp eax, DBG_PRINTEXCEPTION_C
jz right_code

;If we get here, something is wrong
mov dword [return_code], UNKNOWN
xor eax, eax
ret

right_code:
mov dword [return_code], NEGATIVE
xor eax, eax
ret

description: db "Test checking the handling of DBG_PRINTEXCEPTION_C", 0
name: db "DBG_PRINTEXCEPTION_C", 0
about: db "Test checking the handling of DBG_PRINTEXCEPTION_C by MOID/TSRh", 0

return_code: resd 1