.586p
.model flat, stdcall
locals
jumps

include              c:\tasm32\include\shitheap.inc
include              scm.inc

o       equ     offset

extrn   MessageBoxA:proc
extrn   GetModuleHandleA:proc
extrn   GetProcAddress:proc
extrn   DeviceIoControl:proc

.data
sinfo           startupinfo     <0>
pinfo           process_information <0>
hscm            dd     ?
hservice        dd     ?
driverpath      db     256    dup (0)
drivername      db     "ring0.sys", 0
driverdesc      db     "ring0 code....", 0
symlink:        unis   <\\.\ring0>
hdevice         dd     ?
dummy           dd     ?
dummy1          db     100    dup(0)
mbox            db      "loader from ring0", 0
buffer          db      64      dup(0)
progy           db      "crackme.exe", 0                          
.code
start:
                push    SC_MANAGER_CREATE_SERVICE
                push    0
                push    0
                callW   OpenSCManagerA
                test    eax, eax
                jz      __exit
                
                mov     hscm, eax
                
                push    offset dummy
                push    offset driverpath
                push    256
                push    offset drivername
                callW   GetFullPathNameA
                
                push    0
                push    0
                push    0
                push    0
                push    0
                push    offset driverpath
                push    SERVICE_ERROR_IGNORE
                push    SERVICE_DEMAND_START
                push    SERVICE_KERNEL_DRIVER
                push    SERVICE_START or DELETE or SERVICE_STOP
                push    offset driverdesc
                push    offset drivername
                push    hscm
                callW   CreateServiceA                
                test    eax, eax
                jz      __try_to_openservice
                
                mov     hservice, eax
                
__try_to_start: 
                push    0
                push    0
                push    eax
                callW   StartServiceA

                push    0
                push    0
                push    OPEN_EXISTING
                push    0
                push    0
                push    GENERIC_READ + GENERIC_WRITE
                push    offset symlink
                callW   CreateFileW
                mov     hdevice, eax

                push    offset pinfo
                push    offset sinfo
                push    0
                push    0
                push    CREATE_SUSPENDED
                push    0
                push    0
                push    0
                push    0
                push    offset progy
                callW   CreateProcessA

                mov     dword ptr[dummy1], 'hook'
                push    pinfo.pi_dwProcessId
                pop     dword ptr[dummy1+4]
                         
                call    DeviceIoControl, hdevice, 20h, o dummy1, 100h, o dummy1, 100h, o dummy, 0
               
                push    pinfo.pi_hThread
                callW   ResumeThread
               
                call    MessageBoxA, 0, o mbox, 0 ,0                   

                mov     dword ptr[dummy1], 'unho'
                call    DeviceIoControl, hdevice, 20h, o dummy1, 100h, o dummy1, 100h, o dummy, 0
__done:                
                push    hdevice
                callW   CloseHandle
                     
__closeservice:
                push    offset dummy1
                push    SERVICE_CONTROL_STOP
                push    hservice
                callW   ControlService
                
                push    hservice
                callW   DeleteService
                
                push    hservice
                callW   CloseServiceHandle
                

                
__close_scm:    push    hscm
                callW   CloseServiceHandle
                
__exit:
                push    0
                callW   ExitProcess
                

   
                     
                    
__try_to_openservice:                    
                push    SC_MANAGER_ALL_ACCESS
                push    offset drivername
                push    hscm
                callW   OpenServiceA
                test    eax, eax
                jz      __close_scm
                mov     hservice, eax
                jmp     __try_to_start
end    start
                     
                     
