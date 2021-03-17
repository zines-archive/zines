int GetBiggest_FaddResult_Index(Allocated2_Struct* Allocated2Array);
void FillAllocated2(SpecialStructPointers SSP,Allocated2_Struct* Allocated2Array,DWORD Calc3,DWORD Calc2);
double CalcHash(Allocated2_Struct Allocated2,SpecialStructPointers SSP,DWORD Calc3,DWORD Calc2);
SpecialStructPointers* AllocateAndCopy(SpecialStructPointers SSP);
void FillSS2(SpecialStructPointers* Allocated3,DWORD Allocated2_Counter_Plus_C8);
int ReturnIndex(SpecialStructPointers* Allocated3);

struct SpecialStruct1
{
	DWORD	StructSize;
	WORD	Counter_Updater;
	DWORD	fdiv_divisor;
	WORD	Calc1_Div_Const;
};

struct SpecialStruct2
{
	DWORD ArraySize;
	WORD Array[?];
	//Array is a variable size array with the size of ArraySize
};

struct SpecialStructPointers
{
	SpecialStruct1* SpecialStruct1Pointer;
	SpecialStruct2* SpecialStruct2Pointer;
};

struct Allocated2_Struct
{
	int Counter_Plus_C8;
	double fadd_result;
	SpecialStructPointers* Allocated3;
};


extern SpecialStruct1 SS1;		// We have complete control over SpecialStruct1 Members
extern SpecialStruct2 SS2;		// We also have complete control over SpecialStruct2
DWORD Calc1 = SS2.ArraySize / SS1.Calc1_Div_Const;
// Some conditions exist.
// 1 : Calc1 >= 2000
// 2 : SS2.Arraysize <= 25000
// 3 : 4000 <= SS1.fdiv_divisor <= 8000



void main()
{
	int MainCounter = 0;
	DWORD FinalCompareBuffer[5];
	DWORD Calc2 = Calc1 / 20;
	Allocated2_Struct Allocated2Array[0x320];
	SpecialStructPointers SSP;
	SSP.SpecialStruct1Pointer = &SS1;
	SSP.SpecialStruct2Pointer = &SS2;
	
	for(int i=0; i<0x320; i++)
	{
		Allocated2Array[i].Counter_Plus_C8 = i+0xC8;
	}
	
	while(MainCounter < 5)
	{
		int Counter1 = 0;
		int index;
		DWORD Calc3 = Calc2 * MainCounter;
		
		FillAllocated2(SSP,Allocated2Array,Calc3,Calc2);
		index = GetBiggest_FaddResult_Index(Allocated2Array);
		
		FinalCompareBuffer[MainCounter] = Allocated2Array[index].Counter_Plus_C8;
	}

	// At this point, FinalCompareBuffer is compared with RandomNumberStorage,
	// and if both are the same, then the keyfile will be sent.
}


// Returns the index of the biggest Fadd_Result among the 0x320 stored Fadd_Results.
int GetBiggest_FaddResult_Index(Allocated2_Struct* Allocated2Array)
{
	int counter = 0,index = 0;
	double biggest_fadd_result = Allocated2Array[0].fadd_result;
	
	while(counter < 0x320)
	{
		Allocated2_Struct Allocated2 = Allocated2Array[counter];
		if(Allocated2.fadd_result > biggest_fadd_result)
		{
			biggest_fadd_result = Allocated2.fadd_result;
			index = counter;
		}
		counter++;
	}
	return index;
}

// Fill the Allocated2 Array.
void FillAllocated2(SpecialStructPointers SSP,Allocated2_Struct* Allocated2Array,DWORD Calc3,DWORD Calc2)
{
	int counter = 0;
	double current_fadd_result = 0;
	double smallest_fadd_result = 0;
	
	while(counter < 0x320)
	{
		current_fadd_result = CalcHash(&Allocated2Array[counter],SSP,Calc3,Calc2);
		// Calculating the fadd_result member of Allocated2Array.
		Allocated2Array[counter].fadd_result = current_fadd_result;
		// Storing 0x320 fadd_result member values.

		if(counter = 0)
			smallest_fadd_result = current_fadd_result;
		if(smallest_fadd_result > current_fadd_result)
			smallest_fadd_result = current_fadd_result;

		counter++;
	}
	
	counter = 0;
	while(counter < 0x320)
	{
		Allocated2Array[counter].fadd_result -= smallest_fadd_result;
		// This doesn't really effect the final results.
		counter++;
	}
}

// Calculate Fadd_Result values to be stored in Allocated2.
double CalcHash(Allocated2_Struct& Allocated2,SpecialStructPointers SSP,DWORD Calc3,DWORD Calc2)
{
	SpecialStructPointers* Allocated3;
	double fadd_result = 0; // QWORD
	int Index = 0;
	
	if(Calc2 == 0)	// Calc2 is obviously not 0
		Calc2 = Calc1;
	
	if(Allocated2->Allocated3 == 0)
	{
		Allocated3 = AllocateAndCopy(SSP);
		// Allocating, and filling in data of Allocated3.
		Allocated2->Allocated3 = Allocated3;
		// Saving the Allocated3 member of Allocated2Array.
		FillSS2(Allocated3,Allocated2->Counter_Plus_C8);
		// Filling in the newly allocated SpecialStruct2 Array belonging to Allocated3.
	}
	
	SpecialStruct1 SS1 = *(Allocated3->SpecialStruct1Pointer);
	SpecialStruct2 Current_SS2 = *(Allocated3->SpecialStruct2Pointer);
	SpecialStruct2 Original_SS2 = SSP.SpecialStruct2Pointer;
	Index = ReturnIndex(Allocated3);
	// Returns a strange index. 99.99% of the time, this index is a non-zero value.

	if(Index != 0)
	{
		int counter;
		DWORD imul_result = 0;

		while(counter < Calc2)
		{
			imul_result = (DWORD)Current_SS2.Array[counter] * (DWORD)Original_SS2.Array[Calc3 + counter];
			// takes only eax from edx:eax, but edx is always 0 anway.
			fadd_result += (double)imul_result;
			// Multiplies the user supplied input with the currently generated discretional sin wave, and adds all the values.
			// Looks like it's calculating some integral value.
			counter += SS1.Counter_Updater;
			// This counter is later on revealed as 1.
		}
		if(fadd_result < 0)
			fadd_result = fadd_result * (double)-1;
			// making fadd_result a positive value.
	}
	else
	{
		fadd_result = 0;
	}

	return fadd_result;
	// The returned values will be stored in the 0x320 fadd_result members of Allocated2.
	// Since this value will directly affect the FinalCompareBuffer, we must have complete control over this value.
}

// Allocates some space for Allocated3. Allocate space for SpecialStruct1, SpecialStruct2, copy the contents, and store the pointers in Allocated3.
SpecialStructPointers* AllocateAndCopy(SpecialStructPointers SSP)
{
	SpecialStructPointers* Allocated3 = calloc(1,8);
	Allocated3->SpecialStruct1Pointer = calloc(1,0x18);
	Allocated3->SpecialStruct2Pointer = calloc(1,SSP.SpecialStruct2Pointer->ArraySize + 8);
	// Storing the pointers of the newly allocated SpecialStruct1, SpecialStruct2
	memcpy(Allocated3->SpecialStruct1Pointer,SSP.SpecialStruct1Pointer,0x18);
	memcpy(Allocated3->SpecialStruct2Pointer,SSP.SpecialStruct2Pointer,SSP.SpecialStruct2Pointer->ArraySize + 8);
	// Copying the original SpecialStruct1, SpecialStruct2 data into the allocated one.
	return Allocated3;	// This will later be stored in Allocated2.
}

// Fill the SpecialStruct2 Array.
void FillSS2(SpecialStructPointers* Allocated3,DWORD Allocated2_Counter_Plus_C8)
{
	int counter = 0;
	SpecialStruct1 SS1 = *(Allocated3->SpecialStruct1Pointer);
	SpecialStruct2 SS2 = *(Allocated3->SpecialStruct2Pointer);
	double fmul_result = (double)Allocated2_Counter_Plus_C8 * 6.283185307179586; // = 2 * PI
	
	while(counter < Calc1);
	{
		double fdiv_result = (double)counter / (double)SS1.fdiv_divisor;
		double fsin_result = sin(fmul_result * fdiv_result);
		SS2.Array[counter] = (int)(fsin_result * (double)32767);
		// Creating a discretional sin wave and storing it into the allocated SpecialStruct2.
		//The range of a signed short value = -32767 ~ 32768, and considering the result of the sin operation is between -1/+1,
		//this operation is to generate an integer that fits in a WORD.
		counter += SS1.Counter_Updater;
	}
	return;
}

// Return the index of the 3rd value with the same sign as the initial value. Dunno the exact meaning of this function. :/
int ReturnIndex(SpecialStructPointers* Allocated3)
{
	int counter = 1;
	int old_counter = 0;
	int SignEqualCounter = 0;
	SpecialStruct1 SS1 = *(Allocated3->SpecialStruct1Pointer);
	SpecialStruct2 SS2 = *(Allocated3->SpecialStruct2Pointer);
	
	while(counter < Calc1)
	{
		if(SS2.Array[counter] & 0x8000 == SS2.Array[old_counter] & 0x8000)
		// Check if both words have the same sign.
		{
			SignEqualCounter++;
			old_counter = counter;
		}
		if(SignEqualCounter == 2)
			break;
		counter += SS1.Counter_Updater;
		// counter started out as 1, and old_counter as 0, so this indicates that Counter_Updater must be 1.
		// Otherwise, there will be no value to compare to.
	}
	if(counter != Calc1)
		return counter;
	return 0;
}
