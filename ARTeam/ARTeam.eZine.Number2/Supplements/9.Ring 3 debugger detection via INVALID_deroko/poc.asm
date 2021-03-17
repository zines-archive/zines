                        .586p
                        .model  flat, stdcall
                        locals
                        jumps
                              
include                 c:\tasm32\include\shitheap.inc

                        
                        .data
ctx                     context <0>
exception               dd      0c0000008h

;
; this code demonstrates how to detect ring3 debugger or debug loader using
; EXCEPTION_INVALID_HANDLE.
; When program is debugged using ring3 debugger and  dummy handle is passed
; to CloseHandle it will generate exception_invalid_handle, that exception
; will not occur if there is no ring3 debugger. If you are in debugger and
; this exception occurs you should pass it with DBG_CONTINUE. 
; But here comes catch, if you set your debugger to handle this exception 
; with DBG_CONTINUE, what will you do when this exception is generated
; by program intensionaly? Program expect thread exception handler to
; be called and you are not passing exception to it. 
; ** You are detected **
;
; Now imagine this small piece of code used in protection systems in 10-20
; places. How are you going to distinguish bad or good invalid_handle exception?
; You may hook ZwRaiseException but do not forget that any Native API can be
; called using sysenter or int 2eh. 
;
; Very nice trick. Isn't it :P As always only from ARTeam.
;
;                                       S verom u Boga, deroko/ARTeam
;
; ps. Next time when I give hints, let them stay private, good that software
;     developers didn't figure, yet, how this was dangerous trick :P And, yep,
;     don't use my hints to promote yourself, it wasn't discovered by you, and
;     if I want/ed hints to be public I will/would show them by myself.
;
                        .code
start:                  push    offset sehhandle1
                        push    dword ptr fs:[0]
                        mov     dword ptr fs:[0], esp
                        
                        ;fill some important values in context struct
                        
                        mov     ctx.context_ContextFlags, 10007h
                        mov     ctx.context_esp, esp
                        mov     ctx.context_eip, offset __debugged
                        mov     ctx.context_segCs, cs
                        mov     ctx.context_segDs, ds
                        mov     ctx.context_segFs, fs
                        mov     ctx.context_segEs, es
                        mov     ctx.context_segSs, ss
                        
                        push    1
                        push    offset ctx
                        push    offset exception
                        callW   NtRaiseException        ;at this point sehhandle1 should be called

__safe0:                pop     dword ptr fs:[0]
                        add     esp, 4
                        
                        push    offset sehhandle2       
                        push    dword ptr fs:[0]
                        mov     dword ptr fs:[0], esp
                        
                        push    0deadc0deh
                        callW   CloseHandle             ;at this point sehhandle2 should NOT be called

                        pop     dword ptr fs:[0]
                        add     esp, 4

                        push    40h
                        push    offset stitle
                        push    offset sabout
                        push    0
                        callW   MessageBoxA
                        
                        push    0
                        callW   ExitProcess
                        

sehhandle1:             xor     eax, eax
                        mov     ecx, [esp+0ch]
                        mov     [ecx.context_eip], offset __safe0
                        retn

sehhandle2:             xor     eax, eax
                        mov     ecx, [esp+0ch]
                        mov     [ecx.context_eip], offset __debugged
                        retn                                    


__debugged:             push    10h
                        push    offset dabout
                        push    offset dtitle
                        push    0
                        callW   MessageBoxA
                        push    0
                        callW   ExitProcess
                        
dabout                  db      "debugged", 0
dtitle                  db      "kill your ring3 debugger, and try again",0
stitle                  db      "good", 0
sabout                  db      "your are ok", 0
end     start
                        
                        
                        
                        
                        
                        
                        
                        
                        
                        
                        