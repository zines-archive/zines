def Reanalyze_Cross_References():
	func_iter = func_tail_iterator_t(get_func(ScreenEA()))
	status = func_iter.main()
	while status:
		chunk = func_iter.chunk()
		status = func_iter.next()
		code = Heads(chunk.startEA, chunk.endEA)
		last_instruction = code[len(code)-1]
		next_instruction = last_instruction + 5
		if (GetMnem(last_instruction) == 'mov') and (GetOpnd(last_instruction,0) == 'ebx')\
		and ((GetOperandValue(last_instruction,1) & 0xFF000000) == 0x8000000) and (GetMnem(next_instruction) == 'retn'):
			AddressFrom = last_instruction
			AddressTo = GetOperandValue(last_instruction,1)
			AddCodeXref(AddressFrom,AddressTo,fl_JF)
			SetManualInsn(last_instruction,'jump' + ' loc_%x' %(GetOperandValue(last_instruction,1)))
			MakeComm(last_instruction,"")
		if (GetMnem(last_instruction) == 'mov') and (GetMnem(last_instruction-1) == 'push')\
		and ((GetOperandValue(last_instruction,1) & 0xFF000000) == 0x8000000) and (GetMnem(next_instruction) == 'call'):
			AddressFrom = last_instruction
			AddressTo = GetOperandValue(last_instruction,1)
			AddCodeXref(AddressFrom,AddressTo,fl_JF)
			SetManualInsn(last_instruction,'jump' + ' loc_%x' %(GetOperandValue(last_instruction,1)))
			SetManualInsn(last_instruction-1,'nop')
			DestAddress = GetOperandValue(last_instruction,1)
			SetManualInsn(DestAddress,'nop')
			SetManualInsn(DestAddress+1,'nop')
			MakeComm(last_instruction,"")
		'''
		for code in Heads(chunk.startEA, chunk.endEA):
			if isCode(GetFlags(code)):
				mnem = GetMnem(code)
				print mnem
		print "\n"
		'''

Choice = AskLong(5,'1 : reanalyze, 2 : remove tail, 3 : delete function\n\
 4 : append tail generic, 5: append tail custom, 6 : Add Cross Reference\n\
 7 : Add Cross Reference custom, 8 : testing functions')
if Choice == 1:
	reanalyze_function(get_func(ScreenEA()))
	
if Choice == 2:
	remove_func_tail(get_func(ScreenEA()),ScreenEA())
	
if Choice == 3:
	del_func(ScreenEA())
	
if Choice == 4:
	TailStart = AskAddr(0,'Enter the tail start :');
	TailEnd = AskAddr(0,'Enter the tail end :');
	append_func_tail(get_func(ScreenEA()),TailStart,TailEnd)
	
if Choice == 5:
	OriginalPosition = ScreenEA()
	AddressFrom = ScreenEA()
	AddressTo = GetOperandValue(ScreenEA(),0)
	if AddressTo == 0:
		AddressTo = GetOperandValue(ScreenEA(),1)
	
	Previous_Mnemonic = GetMnem(ScreenEA()-1)
	Current_Mnemonic = GetMnem(ScreenEA())
	Next_Mnemonic = GetMnem(ScreenEA()+5)
	if (((Current_Mnemonic == 'push') and ((GetOperandValue(ScreenEA(),0) & 0xFF000000) == 0x8000000))\
	or ((Current_Mnemonic == 'mov') and ((GetOperandValue(ScreenEA(),1) & 0xFF000000) == 0x8000000)))\
	and (Next_Mnemonic == 'retn'):
		func_setend(ScreenEA(),ScreenEA()+5)
		PatchByte(ScreenEA(),0xBB)
	if (Current_Mnemonic == 'mov') and (Previous_Mnemonic == 'push')\
	and ((GetOperandValue(ScreenEA(),1) & 0xFF000000) == 0x8000000) and (Next_Mnemonic == 'call'):
		func_setend(ScreenEA(),ScreenEA()+5)
	autoWait()
	if (get_func_num(AddressTo) != get_func_num(AddressFrom)) and (get_func_num(AddressFrom) != -1):
		temp = get_item_end(AddressTo)
		temp = prev_head(temp,temp-1000)
		if temp != AddressTo:
			MakeUnkn(temp,0)
			autoWait()
			MakeCode(AddressTo)
			autoWait()
		if get_func_num(AddressTo) == -1:
			add_func(AddressTo,AddressTo+10)
			temp = get_item_end(AddressTo+10)
			temp = prev_head(temp,temp-1000)
			MakeComm(temp,'Warning! This might not\nbe the end of the block\nUse "e" to set end')
		add_func(AddressTo,BADADDR)
		fchunk = get_fchunk(AddressTo)
		StartAddress = fchunk.startEA
		EndAddress = fchunk.endEA
		del_func(get_func(AddressTo).startEA)
		append_func_tail(get_func(ScreenEA()),StartAddress,EndAddress)
		autoWait()
	AddCodeXref(AddressFrom,AddressTo,fl_JF)
	autoWait()
	Reanalyze_Cross_References()
	Jump(OriginalPosition)
	
if Choice == 6:
	AddressFrom = ScreenEA()
	AddressTo = GetOperandValue(ScreenEA(),1)
	AddCodeXref(AddressFrom,AddressTo,fl_JF)
	
if Choice == 7:
	OriginalPosition = ScreenEA()
	Reanalyze_Cross_References()
	Jump(OriginalPosition)
	
if Choice == 8:
	func_setend(ScreenEA(),ScreenEA())