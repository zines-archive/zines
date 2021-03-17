;NtYieldExecution v1.2 xADT plugin
;Developed by Gabri3l [ARTeam]
;MASM xADT skeleton code by deroko [ARTeam], thanks for the code optimization hints buddy. ;)
;Also thanks to Shub for information on kernel internals, and moving justclose to same folder as dll
;
;This will test for Olly by using the return value of NtYieldExecution
;This has only been tested on XP SP2 and above
;
;Part #1 of the DLL performs a CreateProcess using an invalid string for the process name
;Part #2 opens a creates a new process called justclose.exe which does nothing except close immediately.
;Part #3 performs a CreateProcess using an invalid string for the process name again
;
;This code is part of the paper "Testing for Olly Using NtYieldExecution" published in ARTeam ezine #2
;http://cracking.accessroot.com


.386 
.model flat,stdcall 
option casemap:none

include		windows.inc 
include		kernel32.inc 
include		ntdll.inc							;Include NTDLL.INC (INCLUDED IN SRC)
include		shlwapi.inc
includelib	kernel32.lib
includelib 	ntdll.lib							;Include NTDLL.LIB (INCLUDED IN SRC)
includelib	shlwapi.lib

.data
sKey 			db "justclose.exe",0					;Name of executable that is used to test yieldexecution
sInvalid 		db "invalid",0						;A nonexistant executable name that will be used in createprocess to test yieldexecution
sName			db "NtYieldExecution.dll"
processinfo 		PROCESS_INFORMATION <>					;Process Information structure
startInfo 		STARTUPINFO <>						;Startup information structute
nFoundFinal 		dd 0							;Counter for how many times Debugger is found
nNotFoundFinal 		dd 0							;Counter for how many times Debugger is not found

.data?
hInstance		HINSTANCE	?  					;Instance handle
sFileLocation		dd 100h dup(?)						;Variable for File path and location
pTemp			dd ?							;Temporary Storage
.code
start:                  mov     eax, 1						;Mov 1 into EAX to show successful load of DLL
                        ret     0ch						;Return


public  tst_NtYieldExecution                        
tst_NtYieldExecution proc

INVOKE GetModuleHandle,addr sName					;Retrieve handle for current module
INVOKE GetModuleFileName,eax,addr sFileLocation,100h			;Get full path to the module
INVOKE StrStr,addr sFileLocation,addr sName				;Search within path location for module name
cmp eax,0								;If module name not located, something is wrong
je Wrong								;So jump to wrong

compare:								
MOV pTemp, EAX								;Move the last location of the module name into pTemp 
INC EAX									;Increment EAX to search for other instances of the module name
INVOKE StrStr,EAX,addr sName						;Search again within remaining path for module name
cmp eax,0								;If no other instances occur then we have found the end of the file path
jne compare								;If another instance occured then continue to search within the file path

XOR ECX,ECX								;Zero out ECX
mov EAX, pTemp								;Move location of module name within the file path into EAX
MOV ECX, offset sKey							;Move the location of our executable file name "justclose.exe" into ECX

begin:
MOV EBX,[ECX]								;Move the first 4 characters of the file name into EBX
MOV [EAX],EBX								;Move the characters stored in EBX into the location in EAX, overwriting the module file name
INC EAX									;Move to next character in module name
INC ECX									;Move to next character in file name
cmp BL,0								;If the last character written was 0 then finish
je finish								;Jump to finish if no more characters to write
jmp begin								;Otherwise continue in the loop until all characters are written

finish:
INVOKE GetCurrentThread							;Retrieve handle to current thread
invoke SetThreadPriority,eax,THREAD_PRIORITY_TIME_CRITICAL		;Increase Thread Priority
INVOKE GetCurrentProcess						;Retrieve handle for current process
invoke SetPriorityClass,eax,REALTIME_PRIORITY_CLASS			;Increase Process Priority, This is done to help remove false positives by increasing the priority of the program we reduce the chance it may share cycles with minor programs

 		MOV nFoundFinal, 0						;ZERO OUT nFoundFinal
		MOV nNotFoundFinal, 0						;ZERO OUT nNotFoundFinal
		XOR ECX,ECX							;ZERO OUT ECX
		
										;**BEGIN PART #1** Test yieldexecution with an invalid createprocess command		
		.while ECX !=40							;The number of times to repeat test, I chose 40 to help remove false positives that occur with system load
			PUSHAD							;Store the registers
			call DebugTest1						;CALL DebugTest1
			.if EAX !=0						;If DebugTest1 returned a value in EAX then a debugger was not active
	    			INC nNotFoundFinal				;Increase the value of nNotFoundFinal
			.elseif							;If 0 was returned then system load was high or a debugger was active
				INC nFoundFinal					;Increase the value of nNotFoundFinal
	    	.endif															
	    	POPAD								;Restore registers
	    	INC ECX								;Increment ECX to continue test
	    .endw								;Loop back to beginning of test
	    
	    	MOV EAX, nFoundFinal						;Load the value of nFoundFinal into EAX (Not needed here but can be used to monitor statistics)
		MOV EBX, nNotFoundFinal						;Load the value of nNotFoundFinal into EAX
		cmp ebx,0							;If there were no occurences of a debugger being not found then it is reasonable sure a debugger was active
		
		je Debug							;If nNotFoundFinal is 0 then jump to "Debugger Active" Result, otherwise continue execution
		
 		MOV nFoundFinal, 0						;ZERO OUT nFoundFinal
		MOV nNotFoundFinal, 0						;ZERO OUT nNotFoundFinal
		XOR ECX,ECX							;ZERO OUT ECX
	    
	   									;**BEGIN PART #2** Test yieldexecution by opening the program justclose.exe 
		.while ECX !=40							;The number of times to repeat test, I chose 40 to help remove false positives that occur with system load
			PUSHAD							;Store the registers
			call DebugTest2						;CALL DebugTest2
			.if EAX !=0						;If DebugTest1 returned a value in EAX then a debugger was not active
	    			INC nNotFoundFinal				;Increase the value of nNotFoundFinal
			.elseif							;If 0 was returned then system load was high or a debugger was active
				INC nFoundFinal					;Increase the value of nNotFoundFinal
	    	.endif								
	    	POPAD								;Restore registers
	    	INC ECX								;Increment ECX to continue test
	    .endw								;Loop back to beginning of test
	    
	    	MOV EAX, nFoundFinal						;Load the value of nFoundFinal into EAX (Not needed here but can be used to monitor statistics)
		MOV EBX, nNotFoundFinal						;Load the address of nNotFoundFinal into EAX
		TEST EBX,EBX							;If there were no occurences of a debugger being not found then there is a 50/50 change a debugger was active
		jnz noDebug							;If nNotFoundFinal is greater than 0 then jump to "No Debugger" Result
		
 		MOV nFoundFinal, 0						;ZERO OUT nFoundFinal
		MOV nNotFoundFinal, 0						;ZERO OUT nNotFoundFinal
		XOR ECX,ECX							;ZERO OUT ECX
							
	    									;BEGIN PART #3; Invalid executable passed to CreateProcess again
	    									;however in this case if the program is outside a debugger if will return 0 and inside a debugger it will return a number
		.while ECX !=40							;The number of times to repeat test, I chose 40 to help remove false positives that occur with system load
			PUSHAD							;Store the registers
			call DebugTest1						;CALL DebugTest1
			.if EAX !=0						;If DebugTest1 returned a value in EAX then a debugger was not active
	    			INC nNotFoundFinal				;Increase the value of nNotFoundFinal
			.elseif							;If 0 was returned then system load was high or a debugger was active
				INC nFoundFinal					;Increase the value of nNotFoundFinal
	    	.endif															
	    	POPAD								;Restore registers
	    	INC ECX								;Increment ECX to continue test
	    .endw								;Loop back to beginning of test
	      
	    MOV EAX, nNotFoundFinal						;Load the value of nNotFoundFinal into EAX
	    cmp eax,0								;If the test consitently returned 0 then it was operating outside a debugger (counter intuitive huh?)
	    jle noDebug								;If nNotFoundFinal was 0 then jump to "No Debugger" result
		
		Debug:								;"DEBUGGER ACTIVE" Result
		MOV EAX,03							;RETURN FOUND IN EAX
		leave
		ret								;Return
		
		noDebug:							;"NO DEBUGGER" Result
		MOV eax,01							;Zero out EAX
		leave
		ret								;Return
	
		Wrong:
		MOV EAX,0
		leave
		ret                                               
 
tst_NtYieldExecution endp
         
DebugTest1 proc


INVOKE CreateProcess,addr sInvalid,NULL,NULL,NULL,TRUE,00000008h,NULL,NULL,addr startInfo,addr processinfo	;Begin a new process using an invalid name for the process name
INVOKE NtYieldExecution												;Yield Execution to running process

ret														;Return from DebugTest1
DebugTest1 endp
DebugTest2 proc



INVOKE CreateProcess,addr sFileLocation,NULL,NULL,NULL,TRUE,00000008h,NULL,NULL,addr startInfo,addr processinfo	;Begin a new process using an invalid name for the process name
INVOKE NtYieldExecution												;Yield Execution to running process

ret														;Return from DebugTest2
DebugTest2 endp         
               
public  tst_NtYieldExecution_description
tst_NtYieldExecution_description:
                        mov     eax, offset description
                        ret
description             db      "Test using NtYieldExecution", 0

public  tst_NtYieldExecution_name
tst_NtYieldExecution_name:
                        mov     eax, offset testing
                        ret
testing                 db      "NtYieldExecution", 0

end                     start