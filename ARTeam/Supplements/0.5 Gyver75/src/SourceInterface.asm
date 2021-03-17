FORMAT PE GUI 4.0
entry _start
include 'win32a.inc'
include 'routines.asm'

;define Constants for interface
  IDD_DLG1 equ 1000; Dialog template
  IDC_BTN1 equ 1001; Generate Button
  IDC_BTN2 equ 1002; Quit Button
  IDC_EDT1 equ 1003; Name Edit
  IDC_EDT2 equ 1004; Serial Edit
  ico	   equ 8001; load icon

section 'CODE' code executable writeable
 _start:
    xor eax,eax
    invoke GetModuleHandle,eax
    invoke InitCommonControls
    invoke DialogBoxParam,eax,IDD_DLG1,HWND_DESKTOP,DlgProc,0
    invoke ExitProcess,0

    proc DlgProc,HndDlg,uMsg,wParam,lParam
      push ebx
      push edi
      push esi
      cmp [uMsg],WM_INITDIALOG
      jz _InitDialog
      cmp [uMsg],WM_COMMAND
      jz _Events
      cmp [uMsg],WM_CLOSE
      jnz @f
      invoke EndDialog,[HndDlg],0
      jmp _Processed
      @@:
      xor eax,eax
      jmp _Finish

      _InitDialog:
	invoke LoadIcon,[HndDlg],ico
	invoke SendMessage,[HndDlg],WM_SETICON,ICON_SMALL,eax
	invoke SetDlgItemText,[HndDlg],IDC_EDT2,NULL
	invoke SetDlgItemText,[HndDlg],IDC_EDT1,NULL
	jmp _Processed

      _Events:
	cmp [wParam],EN_SETFOCUS shl 16 + IDC_EDT1
	jz _ResetBuffer
	cmp [wParam],BN_CLICKED shl 16 + IDC_BTN2
	jz _Quit
	cmp [wParam],BN_CLICKED shl 16 + IDC_BTN1
	Jz _GenerateRoutine
	xor eax,eax
	jmp _Finish

	_ResetBuffer:
	   invoke SetDlgItemText,[HndDlg],IDC_EDT1,NULL
	   invoke SetDlgItemText,[HndDlg],IDC_EDT2,NULL
	   jmp _Processed
	_Quit:
	   invoke PostMessage,[HndDlg],WM_CLOSE,0,0
	   jmp _Processed
	_GenerateRoutine:
	   invoke GetDlgItemText,[HndDlg],IDC_EDT1,NameBuffer,32
	   test eax,eax
	   jz @f
	   call _Generate
	   invoke SetDlgItemText,[HndDlg],IDC_EDT2,SerialBuffer
	   jmp _Processed
	   @@:
	   invoke SetDlgItemText,[HndDlg],IDC_EDT2,MessageError
	   jmp _Processed

      _Processed:
	 mov eax,1
      _Finish:
	 pop esi
	 pop edi
	 pop ebx
      ret
    endp

section 'DATA' data readable writeable

	 align 4
    NameBuffer db 32 dup (?)
 ClrNameBuffer db 32 dup (0)
  SerialBuffer db 32 dup (?)
  MessageError db 'Please,insert a name...',0
	 lpmft db '%lX',0

  GaloisDwords dd 22208241h,01022041h,21020881h
    InitDwords dd 17983DE1h,0A312B14Ch,578A43D1h

	 CDATA file 'CDATA.BIN'
    HashString db '9V4BKI6UVYQACMYEXMABTBZAUQGBWMBYELHLSO7Z50PO23LWFT3ZREDSMHN08LJI',64 dup (0)


section 'IDATA' import data readable writeable
  library Kernel,'KERNEL32.DLL',\
    User,'User32.dll',\
    ComCtl,'COMCTL32.DLL'

   import Kernel,\
     GetModuleHandle,'GetModuleHandleA',\
     GetTickCount,'GetTickCount',\
     ExitProcess,'ExitProcess'

   import User,\
     DialogBoxParam,'DialogBoxParamA',\
     EndDialog,'EndDialog',\
     LoadIcon,'LoadIconA',\
     SendMessage,'SendMessageA',\
     PostMessage,'PostMessageA',\
     SetDlgItemText,'SetDlgItemTextA',\
     GetDlgItemText,'GetDlgItemTextA',\
     WsPrintf,'wsprintfA'


   import ComCtl,\
     InitCommonControls,'InitCommonControls'

section 'RSC' resource from 'template.res' readable
