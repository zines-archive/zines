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

def AddCodeRef(from_ea,to_ea):
	if (get_func_num(to_ea) != -1) and (get_func_num(from_ea) == get_func_num(to_ea)):
		AddCodeXref(from_ea,to_ea,fl_JF)
		return 0
	else:
		if get_func_num(to_ea) != -1:
			remove_func_tail(get_func(to_ea),to_ea)
			del_func(get_func(to_ea).startEA)
		temp = get_item_end(to_ea)
		temp = prev_head(temp,temp-1000)
		print "%x\n" %temp
		MakeUnkn(temp,0)
		autoWait()
		MakeCode(to_ea)
		autoWait()
		add_func(to_ea,BADADDR)
		fchunk = get_fchunk(to_ea)
		start_ea = fchunk.startEA
		end_ea = fchunk.endEA
		del_func(get_func(to_ea).startEA)
		append_func_tail(get_func(from_ea),start_ea,end_ea)
		autoWait()
		AddCodeXref(from_ea,to_ea,fl_JF)
		autoWait()
		return 1

def FindMagic(chunk):
	index_ea = chunk.startEA
	print "%x\n" %index_ea
	prev_ea = 0
	retval = 0
	current_mnem = GetMnem(index_ea)
	while (index_ea < chunk.endEA):
		current_ea = index_ea
		if (current_mnem == 'push') and (GetOperandValue(current_ea,0) & 0xFF000000 == 0x8000000):
			current_ea = next_head(current_ea,current_ea+10)
			current_mnem = GetMnem(current_ea)
			if current_mnem == 'retn':
				prev_ea = prev_head(current_ea,current_ea-10)
				current_ea = GetOperandValue(prev_ea,0)
				PatchByte(prev_ea,0xBB)
				func_setend(prev_ea,next_head(prev_ea,prev_ea+10))
				retval = AddCodeRef(prev_ea,current_ea)
				print "%x\n" %current_ea
		elif current_mnem == 'pushf':
			current_ea = next_head(current_ea,current_ea+10)
			current_mnem = GetMnem(current_ea)
			if current_mnem == 'stc':
				current_ea = next_head(current_ea,current_ea+10)
				current_mnem = GetMnem(current_ea)
				if current_mnem == 'jb':
					prev_ea = current_ea
					current_ea = GetOperandValue(current_ea,0)
					func_setend(prev_ea,next_head(prev_ea,prev_ea+10))
					print "%x\n" %current_ea
					retval = AddCodeRef(prev_ea,current_ea)
		elif (current_mnem == 'mov') and (GetOpType(current_ea,0) == 1) and (GetOperandValue(current_ea,1) & 0xFF000000 == 0x8000000):
			temp = GetOperandValue(current_ea,1)
			current_ea = next_head(current_ea,current_ea+10)
			current_mnem = GetMnem(current_ea)
			if (current_mnem == 'call') and (GetOpType(current_ea,0) == 1):
				prev_ea = prev_head(current_ea,current_ea-10)
				current_ea = temp
				func_setend(prev_ea,next_head(prev_ea,prev_ea+10))
				retval = AddCodeRef(prev_ea,current_ea)
				print "%x\n" %current_ea
		elif current_mnem[0] == 'j':
			prev_ea = current_ea
			current_ea = GetOperandValue(current_ea,0)
			AddCodeRef(prev_ea,current_ea)
		else:
			current_ea = current_ea + get_item_size(current_ea)
		MakeCode(current_ea)
		autoWait()
		index_ea = next_head(index_ea,index_ea+10)
		current_mnem = GetMnem(index_ea)
		print current_mnem

def Build():
	func_iter = func_tail_iterator_t(get_func(ScreenEA()))
	status = func_iter.main()
	while status:
		chunk = func_iter.chunk()
		status = func_iter.next()
		#if chunk.startEA == 0x804C4CA:
		FindMagic(chunk)
		Reanalyze_Cross_References()
		
def Reanalyze():
	print 'hehe'

Choice = AskLong(1,'1 : Build, 2 : Reanalyze')
if Choice == 1:
	Build()
if Choice == 2:
	Reanalyze_Cross_References()
if Choice == 3:
	print 'damn'