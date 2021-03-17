;QuickText DLL v1.0 by Gabri3l [ARTeam]
;Supplement to Adding New Functionality to Old Software
;##\
;Adds new functionality to a modified notepad. 
;Allows interception of the Message handler for WM_COMMAND.
;Compares menu ID number against new modified numbers and acts accordingly
;##/

;##\ Processor definition and includes
.586 
.model flat, stdcall 
option casemap:none 

include windows.inc
include user32.inc
include kernel32.inc
includelib user32.lib
includelib kernel32.lib
;##/


.data 										
wQuickText1 db "QuickText1",0Dh,0Ah,0			;Character String to Paste into Notepad 
wQuickText2 db "QuickText2",0Dh,0Ah,0			;Character String to Paste into Notepad 
dBytes dw 100h									;Buffer Size for Clipboard Memory

.data?						 				
hMem dd 4 dup(?) 								;Handle to Allocated Memory
pAlloc dd 4 dup(?)								;Pointer to First Byte in Allocated Memory
.code

DLLEntry proc hInstDLL:DWORD, reason:DWORD, unused:DWORD
	
	.if reason == DLL_PROCESS_ATTACH			; initialisation code for when DLL is loaded
		mov eax,TRUE							; put TRUE in EAX to continue loading the DLL
	.endif									
	Ret											;Return
	
DLLEntry Endp

QuickPaste proc
STOS WORD PTR ES:[EDI]							;Emulate replaced Notepad function
MOVZX EDI, WORD PTR SS:[EBP+0Ch]				;Emulate replaced Notepad function

.IF EDI==55									
	Mov EDI, OFFSET wQuickText1					;If Menu ID = 55 MOV offset of first Character String into EDI
.ELSEIF EDI==66
	Mov EDI, OFFSET wQuickText2					;If Menu ID = 66 MOV offset of second Character String into EDI
.ELSE
	RET											;IF Menu ID does not equal 55 or 66 Return to Notepad
.ENDIF

INVOKE GlobalAlloc,GMEM_MOVEABLE, dBytes		;Allocate dBytes of Memory to load Character String
mov hMem,EAX									;Move the Handle of the Allocated Memory into hMem

Invoke GlobalLock,EAX							;Lock the Allocated Memory
mov pAlloc,EAX									;Move Pointer to First Byte of Allocated Memory into pAlloc

MOV ECX,EDI										;Move offset of Character String into ECX
XOR EBX,EBX										;Zero Out EBX
Mov BL, BYTE Ptr DS:[ECX]						;Move First Byte of Character string into BL

.While BL!=NULL									;Loop while BL is not a Null Character
	Mov Dword Ptr DS:[EAX],EBX					;Move Character stored in BL into Allocated Memory
	INC EAX										;Increment to next Byte in Memory
	INC ECX										;Increment to next Byte in String
	Mov BL, BYTE Ptr DS:[ECX]					;Move next Character into BL
.ENDW

Mov Dword Ptr DS:[EAX],00						;Move NULL into Last Byte of Allocated Memory to end string

INVOKE OpenClipboard,NULL						;Open Clipboard for this Process

MOV EBX, Dword PTR DS:[hMem]					;Move the Handle of Allocated memory into EBX

INVOKE EmptyClipboard							;Empty old Clipboard Contents
INVOKE SetClipboardData,CF_TEXT,EBX				;Set Clipboard Data equal to Allocated Memory
INVOKE CloseClipboard							;Close clipboard
INVOKE GlobalUnlock,hMem						;Unlock the Allocated memory
MOV EDI, 302h									;Move "Paste" Menu ID number into EDI
ADD ESP,2										;Balance the Stack
RET												;Return to Notepad

QuickPaste EndP

end DLLEntry