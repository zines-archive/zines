.586p
.model  flat, stdcall
locals
jumps

include                 c:\tasm32\include\shitheap.inc
include                 apimacro.mac
include                 ring0.inc

public  C start

.data
driver:                 unis    <\Device\ring0>
symlink:                unis    <\??\ring0>
driver_us               unicode_string <0>
sym_us                  unicode_string <0>
pdeviceobject           dd      ?
.code
start:                  ;[ebp+8] pDriverObject [ebp+0ch] pRegPatch
                        push    ebp
                        mov     ebp, esp
                        pushad
                        
                        push    offset driver
                        push    offset driver_us
                        iWin32  RtlInitUnicodeString
                        
                        push    offset pdeviceobject
                        push    0
                        push    0
                        push    FILE_DEVICE_UNKNOWN
                        push    offset driver_us
                        push    0
                        push    dword ptr[ebp+8]
                        iWin32  IoCreateDevice
                        test    eax, eax
                        jnz     __failinit
                        
                        push    offset symlink
                        push    offset sym_us
                        iWin32  RtlInitUnicodeString
                        
                        push    offset driver_us
                        push    offset sym_us
                        iWin32  IoCreateSymbolicLink
                        test    eax, eax
                        jnz     __deletedevice
                        
                        mov     eax, [ebp+8]                    ;pDriverObject

                        mov     [eax.dro_majorfunctions.irp_mj_create], offset RequestHandler     
                        mov     [eax.dro_majorfunctions.irp_mj_close], offset RequestHandler    
                        mov     [eax.dro_majorfunctions.irp_mj_device_control], offset ServiceHandler     
                        mov     [eax.dro_DriverUnload], offset DriverUnload                           
                                                
                        xor     eax, eax
                        jmp     __exitinit                        
                        
__deletedevice:         push    pdeviceobject
                        iWin32  IoDeleteDevice      
                        
__failinit:             mov     eax, 1
                        
__exitinit:             mov     [esp.Pushad_eax], eax
                        popad
                        pop     ebp
                        ret     8
                        
RequestHandler:         ;[esp+4] pDeviceObject, [esp+8] pIrp
                        mov     ecx, [esp+8]
                        mov     [ecx.irp_iostatus.iob_status], 0
                        mov     [ecx.irp_iostatus.iob_information], 0
                        xor     edx, edx
                        iWin32  IofCompleteRequest
                        xor     eax, eax
                        ret     8

DriverUnload:           ;pDriverObject  [esp+4]
                        push    offset sym_us
                        iWin32  IoDeleteSymbolicLink

                        mov     eax, [esp+4]
                        push    [eax.dro_deviceobject]
                        iWin32  IoDeleteDevice
                        ret     4

ServiceHandler:         ;[ebp+8] pDeviceObject, [ebp+0ch] pIrp
                        push    ebp
                        mov     ebp, esp
                        pushad
                        
                        mov     ebx, [ebp+0ch]  ;pIrp
                        mov     edx, [ebx.irp_tail.t_CurrentStackLocation]  
                        mov     eax, [edx.isl_IoControlCode ]
                        
                        cmp     eax, 20h
                        jne     __sh_fail
                        mov     eax, [ebx.irp_systembuffer]
                        cmp     dword ptr[eax], 'hook'
                        je      __hook
                        cmp     dword ptr[eax], 'unho'
                        jne     __sh_fail
                        
                        call    unhook
                        jmp     __sh_oki

__hook:                 mov     eax, [eax+4]                                                                   
                                                
                        push    offset eprocess
                        push    eax
                        iWin32  PsLookupProcessByProcessId      ;get EPROCESS 
                        test    eax, eax
                        jnz     __sh_fail
                        
                        push    eprocess
                        iWin32  ObDereferenceObject             ;decrement reference count
                        
                        
                        push    offset apcstate
                        push    eprocess
                        iWin32  KeStackAttachProcess
                        
                        mov     eax, cr3
                        mov     c_cr3, eax
                        
                        mov     eax, cr0
                        and     eax, 0FFFEFFFFh
                        mov     cr0, eax
                        
                        init_ring0_seh  __safe
                        
                        mov     eax, insertint3h
                        mov     ebx, [eax]
                        mov     byte ptr[eax], 0cch

__safe:                 remove_ring0_seh
                        mov     eax, cr0
                        or      eax, 10000h
                        mov     cr0, eax
                        
                        push    offset apcstate
                        iWin32  KeUnstackDetachProcess
                                                
                        call    hook
                        
__sh_oki:               mov     ecx, [ebp+0ch]
                        xor     edx, edx
                        iWin32  IofCompleteRequest
                        xor     eax, eax
                        jmp     __sh_exit
                        
__sh_fail:              mov     ecx, [ebp+0ch]
                        xor     edx, edx
                        iWin32  IofCompleteRequest                       
                        mov     eax, 1            
                                    
__sh_exit:              mov     [esp.Pushad_eax], eax
                        popad
                        pop     ebp
                        ret     8                        


eprocess                dd              0
hooked                  dd              0
c_cr3                   dd              ?
oldint3h                dd              ?
apcstate                kapc_state      ?

hook:                   cmp     hooked, 1
                        je      __hooked
                        
                        push    esi
                        sidt    fword ptr[esp-2]
                        pop     esi
                        
                        lea     esi, [esi+3*8]
                        
                        mov     cx, word ptr[esi+6]
                        rol     ecx, 16
                        mov     cx, word ptr[esi]
                        mov     oldint3h, ecx

                        mov     ecx, offset myint3h
                        
                        mov     word ptr[esi], cx
                        rol     ecx, 16
                        mov     word ptr[esi+6], cx

                        mov     hooked, 1
__hooked:               ret

unhook:                 cmp     hooked, 0
                        je      __unhookwhat
                        
                        push    esi
                        sidt    fword ptr[esp-2]
                        pop     esi
                        
                        lea     esi, [esi+3*8]
                        
                        mov     ecx, oldint3h
                        
                        mov     word ptr[esi], cx
                        rol     ecx, 16
                        mov     word ptr[esi+6], cx
                        
                        mov     hooked, 0
__unhookwhat:           ret


myint3h:                initint
                        mov     eax, cr3
                        cmp     eax, c_cr3
                        jne     __passdown
                        
                        mov     eax, [esp.int_eip]
                        dec     eax
                        cmp     eax, insertint3h
                        jne     __passdown
                        
                        mov     eax, patchme
                        shr     eax, 22
                        test    dword ptr[eax*4+0C0300000h], 1  ;is PTE present?
                        jz      __passdown 
                        mov     eax, patchme
                        shr     eax, 12
                        test    dword ptr[eax*4+0C0000000h], 1  ;is page present
                        jz      __passdown
                        
                        mov     eax, cr0
                        and     eax, 0FFFEFFFFh
                        mov     cr0, eax
                        
                        mov     eax, patchme
                        mov     byte ptr[eax], 0ffh
                        
                        mov     eax, cr0
                        or      eax, 10000h
                        mov     cr0, eax
                        
                        mov     [esp.int_eip], 401000h
                        
                        restoreint
                        iretd
                        
__passdown:             restoreint
                        jmp     cs:[oldint3h]
insertint3h             equ     004063BFh 
patchme                 equ     0040104Ah 
end                     start