;****************************************************************************************************
;Description:
;Input:  NameBuffer
;Output: ClrNameBuffer, HashString
;A depth analysis:
;1) In HashString it appends the NameBuffer without space chars at the head, also the space chars in
;                 the 'middle' are substituted by ONE space char;
;2) In ClrNameBuffer it puts the string appended at the end of HashString without digit chars;
;****************************************************************************************************

  _CleanName:
	 xor esi,esi				; i use esi as index of NameBuffer
	 xor edi,edi				; i use edi as index of HashString
	 xor ebx,ebx				; ebx is a simply flag used to recognize space chars at the begin of NameBuffer
	 xor ecx,ecx				; ecx is a index of ClrNameBuffer
	 _Loop:
	    mov al,[NameBuffer + esi]		; al = current Char of NameBuffer
	    test al,al				; if al == 0, we arrive at the end of NameBuffer
	    je _EndProc
	    push eax
	    call _CheckRange1			 ; if al == ' ', ...
	    test al,al
	    pop eax
	    je _Next
	    inc esi
	    mov ebx,1				; ... i sets ebx and repeat the _loop until al <> ' '
	    jmp _Loop
	    _Next:				; we arrive here after the loop
	       test edi,edi			; test edi; if edi == 0, -> we are at the beginning of the scan and we don't insert...
	       jz @f				; ...' ' char in the HashStrings
	       test ebx,ebx			; test ebx; if ebx == 1 and edi > 0 we are in the middle of NameBuffer...
	       jz @f
	       mov [HashString + 40h + edi],20h ; ... then, we must put only ONE space char in a [HashString + 40h]
	       inc edi
	       @@:
	       mov [HashString + 40h + edi],al	; also, we insert the next char pointed by esi in HashString
	       push eax
	       call _IsDigitChar
	       test al,al
	       pop eax
	       jnz _Leave
	       @@:
	       mov [ClrNameBuffer + ecx],al	; here, we put the current char in ClrNameBuffer if it's not a digit
	       inc ecx
	       _Leave:
	       inc edi
	       inc esi
	       xor ebx,ebx			; reset the flag, so we are ready to recognise the next sequence of ' ' chars
	    jmp _Loop
	 _EndProc:
	   mov [HashString + 40h + edi],0
	   mov [ClrNameBuffer + ecx],0
	 ret

;****************************************************************************************************
;Description:
;Input:  esi, eax
;Output: eax
;A depth analysis:
;1) esi, the first parameter, has a UPPARCASE char;
;2) eax, the second parameter, is a DWORD value; its bits are used to know the 2' powers by multiply.
;        If a j-esim bit is setted, esi is multiplied by 2^j;
;3) eax, as result of this proc, stores: esi * ( 2^i xor 2^j xor ... ) ( Galois multiplication ).
;****************************************************************************************************

   _Galois:
      push edi
      push ecx
      xor edi,edi	 ;edi == temp value;
      mov ecx,20h	 ;init ecx, ecx is a bit counter of a dword stored in eax;
      @@:
      dec ecx
      js _GaloisEnd	 ;if ecx < 0, i jump to the end;
      shl eax,1 	 ;here i test if the most bit, stored in carry flag,...
      jnc @b		 ;... are setted; if no,i repeat the loop;
      push esi		 ; save esi on the stack;
      shl esi,cl
      xor edi,esi	 ;Galois Multiplication...
      pop esi		 ;i restore the original value of esi ( the first parameter);
      jmp @b
      _GaloisEnd:
      mov eax,edi	 ;At the end, i return the temp value in eax;
      pop ecx
      pop edi
    ret

;****************************************************************************************************
;Description:
;Input:  al;
;Output: 1 or 0 in eax;
;A depth Analysis:
;1) al, as paramater, is a simply ASCII coded byte;
;2) eax, as the return value, is a BOOlEAN; if eax = 1, then  09h < ASCII byte < 0Dh
;        or ASCII byte = space char; in the other case eax = 0;
;****************************************************************************************************

   _CheckRange1:
      cmp al,09h
      jl @f
      cmp al,0Dh
      ja @f
      mov eax,1
      ret
      @@:
      cmp al,20h	       ; NO COMMENT .... ;) ;
      jnz @f
      mov eax,1
      ret
      @@:
      xor eax,eax
      ret

;****************************************************************************************************
;Description:
;Input:  al;
;Output: 1 or 0 in eax;
;A depth Analysis:
;1) al, as paramater, is a simply ASCII coded byte;
;2) if ASCII coded byte is a literal ( in uppercase or downcase), then EAX = 1 else 0;
;****************************************************************************************************

   _CheckRange2:
      cmp al,61h
      jl @f
      cmp al,7Ah
      ja @f
      mov eax,1
      ret
      @@:
      cmp al,41h		;Very simple to understand.... ;
      jl @f
      cmp al,5Ah
      ja @f
      mov eax,1
      ret
      @@:
      xor eax,eax
      ret

;****************************************************************************************************
;Description:
;Input:  al;
;Output: 1 or 0 in eax;
;A depth Analysis:
;1) al, as paramater, is a simply ASCII coded byte;
;2) if ASCII coded byte is a digit, then EAX = 1 else 0;
;****************************************************************************************************

   _IsDigitChar:
      cmp al,30h
      jl @f
      cmp al,39h
      ja @f		       ; See above .... ;) ;
      mov eax,1
      ret
      @@:
      xor eax,eax
      ret

;****************************************************************************************************
;Description:
;Input:  al;
;Output: al;
;A depth Analysis:
;1) al, as paramater, is a simply ASCII coded byte;
;2) if ASCII coded byte is a downcase literal, this proc converts it in uppercase and return in eax
;****************************************************************************************************

   _UppercaseChar:
      cmp al,61h
      jl @f
      cmp al,7Ah
      ja @f
      add al,0E0h
      @@:
      ret

;****************************************************************************************************
;Description:
;Input:  edx;
;Output: eax;
;A depth Analysis:
;1) edx, as parameter, is the offset of the String;
;2) eax is the Lengh of String;
;****************************************************************************************************

   _StringLengh:
      push esi
      xor eax,eax	    ;eax stores the chars of a String;
      xor esi,esi	    ; esi is the counter of StringLengh;
      @@:
      mov al,[edx + esi]    ;al == current char of StringLengh;
      inc esi		    ;esi = esi + 1;
      test al,al
      jnz @b		     ;i repeat the loop until al == 0 ( end of String );
      dec esi
      mov eax,esi	    ;eax stores the counter
      pop esi
      ret

;****************************************************************************************************
;Description:
;Input:  ebx,edx,ecx;
;Output: eax;
;A depth Analysis:
;1) edx, as parameter, stores the Init Value;
;   ebx, as paramenter, is the offset of a String;
;   ecx, as parameter, is 0 or 1 or 2; i use it to select a different hash calculation
;2) eax, as result of this proc, is the Hash index;
;****************************************************************************************************

   _HashIndex:
      push esi
      push edi				;i save esi edi on the stack;
      xor edi,edi			;init edi; edi is the index of string buffer;
      _HashIndexLoop:
      mov al,[ebx + edi]		;al = current ascii coded byte of String buffer;
      test al,al			;if we arrive at the end of the String,...
      jz _HashIndexEnd			;...we jump!
      call _UppercaseChar		;we begin the hash calc...
      movzx esi,al
      mov eax,[GaloisDwords + 4*ecx]	;by ecx, i select a different Dword to calculate a Hash value!
      call _Galois
      or ecx,ecx
      jne _HashIndexs23
      ;HashIndex1
      xor eax,edx
      mov edx,eax
      shl eax,1
      shr edx,1fh
      test edx,edx
      jz @f
      or eax,1
      @@:
      mov edx,eax
      inc edi
      jmp _HashIndexLoop
      _HashIndexs23:
      cmp ecx,1
      je _HashIndex2
      ;HashIndex3
      imul edx,13h
      add edx,eax
      inc edi
      jmp _HashIndexLoop
      _HashIndex2:
      imul edx,25h
      add edx,eax
      inc edi
      jmp _HashIndexLoop
      _HashIndexEnd:
      mov eax,edx
      pop esi
      pop edi
      ret
;****************************************************************************************************
;Description:
;Input:  ecx,eax
;Output: eax
;A depth analysis:
;1) ecx, the first parameter, is a simply counter;
;2) eax, the second parameter, is a String's offset
;3) eax, as result of this proc, stores the Hash value that depends by CDATA.bin file
;****************************************************************************************************

   _CDATAHash:
      push edx				  ;well... i simply rip the original code... ;)
      push edi
      push esi
      push ebx
      xor edi,edi
      mov edx,eax
      or esi,0ffffffffh
      @@:
      mov ebx,esi
      shr ebx,8
      mov al,[edx + edi]
      call _UppercaseChar
      and eax,0ffh
      and esi,0ffh
      xor eax,esi
      mov esi,dword [CDATA + 4*eax]
      xor esi,ebx
      inc edi
      dec ecx
      jnz @b
      not esi
      mov eax,esi			  ;EAX = final result;
      pop ebx
      pop esi
      pop edi
      pop edx
      ret

;****************************************************************************************************
;Description:
;Input:  cl,edx
;Output: edx
;A depth analysis:
;1) cl, the first parameter, is a simply UPPERCASE char;
;2) edx, the second parameter, is a String's offset;
;3) edx, as result of this proc, stores the even position that char has in the String;
;****************************************************************************************************

   _EvenIndex:
      push eax
      xor eax,eax
      @@:
      cmp byte [edx],cl
      je _EvenIndexEnd
      add edx,2
      inc eax
      jmp @b
      _EvenIndexEnd:
      mov edx,eax
      pop eax
      ret

;****************************************************************************************************
;Description:
;Input:  SerialBuffer,HashString
;Output: eax
;A depth analysis:
;  This proc generates a CRCHash from SerialBuffer[15h:10h] and stores the DWORD in eax
;****************************************************************************************************

   _CRCHash:
      xor esi,esi		       ;esi is a counter; its step is 4 units;
      xor eax,eax		       ;eax is the temp register;
      mov edi,10h		       ;edi is the index of Serial Buffer;
      @@:
      mov cl,[SerialBuffer + edi]
      mov edx,HashString
      call _EvenIndex
      mov ecx,esi
      add esi,4
      shl edx,cl
      or  eax,edx
      inc edi
      cmp esi,18h
      jb @b
      mov ecx,6
      mov edx,987AC16Bh
      @@:
      mov esi,edx			;save edx in esi;
      shl esi,5
      sub esi,edx			;esi == edx * 1Fh;
      mov edx,eax			;save eax in edx;
      and edx,0Fh			;take the last nibble of edx;
      xor edx,esi			;edx = {esi[31:04],(dl xor esi[3:0])};
      shr eax,4 			;after the last calc., the first nibble of eax is superflous;
      dec ecx
      jnz @b
      mov eax,edx
      ret

;****************************************************************************************************
;Description:
;Input:  SerialBuffer,HashString
;Output: SerialBuffer[15h:10h]
;A depth analysis:
;  This proc generates a pseudorandom chars stored in SerialBuffer[15h:10h];
;****************************************************************************************************
   _InitSerialBuffer:
      mov ecx,6 			;ecx is a counter's loop;
      mov esi,10h			;esi is the SerialBuffer's index;
      xor eax,eax			;eax is the index of HashString;
      invoke GetTickCount
      and eax,1Fh
      shl eax,1
      @@:
      xor edx,edx			;i use edx as data store;
      mov dl,byte [HashString + eax]
      mov [SerialBuffer + esi],dl
      add eax,2
      and eax,1Fh
      inc esi
      dec ecx
      jnz @b
      ret

;****************************************************************************************************
;                            MAIN PROCEDURE
;****************************************************************************************************
   _Generate:
      call _CleanName
      ;i set SerialBuffer[15h:10h];
      call _InitSerialBuffer
      ;i calculate the SerialBuffer[18h:16h];
      call _CRCHash
      xor ecx,ecx
      mov edx,eax
      and edx,1Fh
      mov cl,[HashString + 2*edx]
      mov [SerialBuffer + 16h],cl
      mov edx,eax
      shr edx,5
      and edx,1Fh
      mov cl,[HashString + 2*edx]
      mov [SerialBuffer + 17h],cl
      shr eax,0Ah
      and eax,1Fh
      mov cl,[HashString + 2*eax]
      mov [SerialBuffer + 18h],cl
      ;i calculate the SerialBuffer[08h] and SerialBuffer[0Eh];
      xor ecx,ecx
      mov edx,[InitDwords + 4*ecx]
      mov ebx,ClrNameBuffer
      call _HashIndex
      xor ecx,ecx
      mov edx,eax
      and edx,1Fh
      mov cl,[HashString + 2*edx]
      mov [SerialBuffer + 08h],cl
      shr eax,5
      and eax,1Fh
      mov cl,[HashString + 2*eax]
      mov [SerialBuffer +0Eh],cl
      ;i calculate the SerialBuffer[0Fh],SerialBuffer[0Bh] and SerialBuffer[03h];
      mov ecx,1
      mov edx,[InitDwords + 4*ecx]
      mov ebx,ClrNameBuffer
      call _HashIndex
      xor ecx,ecx
      mov edx,eax
      and edx,1Fh
      mov cl,[HashString + 2*edx]
      mov [SerialBuffer + 0Fh],cl
      mov edx,eax
      shr edx,5
      and edx,1Fh
      mov cl,[HashString + 2*edx]
      mov [SerialBuffer + 0Bh],cl
      shr eax,0Ah
      and eax,1Fh
      mov cl,[HashString + 2*eax]
      mov [SerialBuffer + 03h],cl
      ;i calculate the SerialBuffer[09h],SerialBuffer[01h],SerialBuffer[0Ah] and SerialBuffer[0Ch];
      mov ecx,2
      mov edx,[InitDwords + 4*ecx]
      mov ebx,ClrNameBuffer
      call _HashIndex
      xor ecx,ecx
      mov edx,eax
      and edx,1Fh
      mov cl,[HashString + 2*edx]
      mov [SerialBuffer + 09h],cl
      mov edx,eax
      shr edx,5
      and edx,1Fh
      mov cl,[HashString + 2*edx]
      mov [SerialBuffer + 01h],cl
      mov edx,eax
      shr edx,0Ah
      and edx,1Fh
      mov cl,[HashString + 2*edx]
      mov [SerialBuffer + 0Ah],cl
      shr eax,0Fh
      and eax,1Fh
      mov cl,[HashString + 2*eax]
      mov [SerialBuffer + 0Ch],cl
      ;i calculate the SerialBuffer[00h],SerialBuffer[04h],SerialBuffer[06h],SerialBuffer[02h],
      ;                SerialBuffer[07h],SerialBuffer[0Dh] and SerialBuffer[05h];
      mov edx,ClrNameBuffer
      call _StringLengh
      mov ecx,eax
      mov eax,ClrNameBuffer
      call _CDATAHash
      xor eax,0A29DC94Dh
      xor ecx,ecx
      mov edx,eax
      and edx,1Fh
      mov cl,[HashString + 2*edx]
      mov [SerialBuffer],cl
      mov edx,eax
      shr edx,5
      and edx,1Fh
      mov cl,[HashString + 2*edx]
      mov [SerialBuffer + 04h],cl
      mov edx,eax
      shr edx,0Ah
      and edx,1Fh
      mov cl,[HashString + 2*edx]
      mov [SerialBuffer + 06h],cl
      mov edx,eax
      shr edx,0Fh
      and edx,1Fh
      mov cl,[HashString + 2*edx]
      mov [SerialBuffer + 02h],cl
      mov edx,eax
      shr edx,14h
      and edx,1Fh
      mov cl,[HashString + 2*edx]
      mov [SerialBuffer + 07h],cl
      mov edx,eax
      shr edx,19h
      and edx,1Fh
      mov cl,[HashString + 2*edx]
      mov [SerialBuffer + 0Dh],cl
      shr eax,1Eh
      mov cl,[HashString + 2*eax]
      mov [SerialBuffer + 05h],cl
      ;i finally calculate the SerialBuffer[1Dh:19h];
      mov ecx,19h
      mov eax,SerialBuffer
      call _CDATAHash
      xor eax,1982D18Ch
      xor ecx,ecx
      mov edx,eax
      and edx,1Fh
      mov cl,[HashString + 2*edx]
      mov [SerialBuffer + 19h],cl
      mov edx,eax
      shr edx,5
      and edx,1Fh
      mov cl,[HashString + 2*edx]
      mov [SerialBuffer + 1Ah],cl
      mov edx,eax
      shr edx,0Ah
      and edx,1Fh
      mov cl,[HashString + 2*edx]
      mov [SerialBuffer + 1Bh],cl
      mov edx,eax
      shr edx,0Fh
      and edx,1Fh
      mov cl,[HashString + 2*edx]
      mov [SerialBuffer + 1Ch],cl
      shr eax,14h
      and eax,1Fh
      mov cl,[HashString + 2*eax]
      mov [SerialBuffer + 1Dh],cl
      mov [SerialBuffer + 1Eh],0
   retn








