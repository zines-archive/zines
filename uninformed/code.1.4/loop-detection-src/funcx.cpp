// funcx.cpp: implementation of the funcx class.
//
//////////////////////////////////////////////////////////////////////
#include <ida.hpp>
#include <idp.hpp>
#include <idd.hpp>
#include <bytes.hpp>
#include <expr.hpp>
#include <struct.hpp>
#include <frame.hpp>
#include <kernwin.hpp>
#include <loader.hpp>
#include <name.hpp>
#include <funcs.hpp>
#include <offset.hpp>




#include <gdl.hpp>
#include <md5.h>

#include <ua.hpp>

#include "funcx.h"

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////
// funcx()
//
// Intializes variables to a known state
//
// arguments: func_t func_ - the already initilized func structure
//			  
// returns:   none
//
funcx::funcx(func_t * func_)
{
	func = func_;//copy over our parameter into our private variable
	struc = get_frame(func);//get the frame incase we need it for later use

}

funcx::funcx(int fid)
{
	func = getn_func(fid);//copy over our parameter into our private variable
	struc = get_frame(func);//get the frame incase we need it for later use

}


funcx::funcx(ea_t ea)
{
	func = get_func(ea);//copy over our parameter into our private variable
	struc = get_frame(func);//get the frame incase we need it for later use

}


funcx::~funcx()
{

}
/////////////////////////////////////////////////////////////////////////////////////////
// GetLocalVariableSize()
//
// Get's the size of the local variables
//
// arguments: none
//			  
// returns:   an integer containing the size of the local variables
//
int funcx::GetLocalVariableSize()
{
	/* the frsize member of func contains the size of the local variable(s) */
	return func->frsize;
}
/////////////////////////////////////////////////////////////////////////////////////////
// GetStackOffset()
//
// Get's the offset within the frame of a given variable
//
// arguments: ea_t ea - ea of variable
//			  operand - operand 1 or 0
//			  
// returns:   returns ea_t with the offset into the frame
//
ea_t funcx::GetStackOffset(ea_t ea, int operand)
{

	/* essentially we are just wrapping this function might be easier later */
	return calc_stkvar_struc_offset(func,ea,operand);

}
/////////////////////////////////////////////////////////////////////////////////////////
// GetReturnAddressSize()
//
// Gets the size of the return address
//
// arguments: none
//			  
// returns:   an integer containing the size of the return address
//
int funcx::GetReturnAddressSize()
{
	/* return the size of the return address */
	return get_frame_retsize(func);
}
/////////////////////////////////////////////////////////////////////////////////////////
// HasArguements()
//
// Checks the function to see if accepts any parameters if it does it returns true
//
// arguments: none
//			  
// returns:   true or false
//
int funcx::HasArguments()
{
/* a reminder to ourselves of what the frame contains */

	//includes:
	// Return Address
	// Local Variables
	// Saved Registers
	// Size of Function Arguements
/* do our own calculations to determine the size of the frame without 
** arguements. If there are arguements for the function then the frame size
** will not equal our calculated size 
**/
int size = GetReturnAddressSize() + GetLocalVariableSize() + GetSavedRegsSize();

	if(size == GetFrameSize() )
		return 0;
	else
	{
		
		return 1;
	}
}
/////////////////////////////////////////////////////////////////////////////////////////
// GetSavedRegsSize()
//
// Get's the size of the saved registers
//
// arguments: none
//			  
// returns:   size of saved regs
//
int funcx::GetSavedRegsSize()
{
	/* the frregs member of func_t contains the saved size of the registers */
	return func->frregs;
}
/////////////////////////////////////////////////////////////////////////////////////////
// GetFrameSize()
//
// Get's the frame size of a function
//
// arguments: none
//			  
// returns: the total frame size
//
int funcx::GetFrameSize()
{
	/* get our frame size */
	return get_frame_size(func);
}
/////////////////////////////////////////////////////////////////////////////////////////
// GetNumberOfParameters()
//
// Get's the total number of parameters the function takes
//
// arguments: none
//			  
// returns:   an integer containing the number of parameters
//
int funcx::GetNumberOfArguments()
{

/* do our custom frame size calculation */
int size = GetReturnAddressSize() + GetLocalVariableSize() + GetSavedRegsSize();
struc_t * struc; 

/* first check if there are even arguements in the function */
if(!HasArguments() ) return 0;

struc = get_frame(func);
return struc->memqty - ( get_next_member_idx(struc,size) - 1 );


}

/////////////////////////////////////////////////////////////////////////////////////////
// IsStackVariableAParameter()
//
// takes a given ea and operand and checks that variable to see if it is an arguement
// to the given function
//
// arguments: ea_t ea		- the EA of our stack variable
//			  int opernad	- the operand being 0 or 1 
// returns:   true or false
//
int funcx::IsStackVariableAParameter(ea_t ea, int operand)
{
ea_t ea_offset;
int size; 
/* get the offset of our variable within the frame */
ea_offset = calc_stkvar_struc_offset(func, ea, operand);
/* custom calculations once again */ 
size = GetSavedRegsSize() + GetReturnAddressSize() + GetLocalVariableSize();


if( ea_offset == -1) return 0;

/* no see if our offset is greater than our custom frame size we have an arguement */
if( ea_offset >= size)
{

	return 1;
}
else 
	return 0;


}
/////////////////////////////////////////////////////////////////////////////////////////
// GetOrderOfVariable()
//
// looks through the functions frame and figures out the order of the parameters so that one
// could then search for three pushes if they were looking for the third variable 
//
// arguments: ea_t ea		- the EA of our stack variable
//			  int opernad	- the operand being 0 or 1 
// returns:   
int funcx::GetOrderOfVariable(ea_t ea, int operand)
{
int size = GetSavedRegsSize() + GetReturnAddressSize() + GetLocalVariableSize();
ea_t ea_offset = calc_stkvar_struc_offset(func, ea, operand);
int diffrence = GetFrameSize() - size;
int i = size;
int count = 1;

while(i <= GetFrameSize() )
{

	if(i == ea_offset)
		break;
	i+=4;
	count++;
}//end while
return count;
}

/////////////////////////////////////////////////////////////////////////////////////////
// IsStackVariableALocalVariable()
//
// This function looks at the operand and basically checks the functions frame to see
// if it has arguements. If the function has arguements it then check the offset if the 
// offset of the variable is > local variable offsets then it is an arguement
//
// arguments: ea_t ea		- the EA of our stack variable
//			  int opernad	- the operand being 0 or 1 
// returns: true 1 or false 0 
int funcx::IsStackVariableALocalVariable(ea_t ea, int operand)
{
ea_t ea_offset;
int size; 
/* get the offset of our variable within the frame */
ea_offset = calc_stkvar_struc_offset(func, ea, operand);
/* custom calculations once again */ 
size = GetSavedRegsSize() + GetReturnAddressSize() + GetLocalVariableSize();
/* no see if our offset is greater than our custom frame size we have an arguement */
if( ea_offset <= size)
	return 1;
else 
	return 0;

}

/////////////////////////////////////////////////////////////////////////////////////////
// GetStackVariableName()
//
// function was taken from desquirr project. It gets the name of a variable.
//
// arguments: ea_t ea		- the EA of our stack variable
//			  int opernad	- the operand being 0 or 1 
// returns: name

char * funcx::GetStackVariableName(ea_t ea, int operand)
{
func_t * func;
bool first = true;
member_t* member;  
char* name;
if(ea == BADADDR) return NULL;

func = get_func(ea);


	if (func)
	{
		ulong offset = calc_stkvar_struc_offset(func, ea, operand);

		struc_t* struc = get_frame(func);
		

		while (struc)
		{
			member = get_member(struc, offset);
			if (member)
			{
				if (first)
					first = false;
				

				name = get_member_name(member->id);
				return name;
				

				
			}
			else
			{
				struc = NULL;
			}
		}//end while


	}//end if
	return NULL;
}
/////////////////////////////////////////////////////////////////////////////////////////
// GetBufferSize()
//
// Get the buffer size
//
// arguments: ea_t ea		- the EA of our stack variable
//			  int opernad	- the operand being 0 or 1 
// returns: size	
int funcx::GetBufferSize(ea_t ea, int operand)
{
ea_t varOffset;
struc_t * struc = get_frame(func);
member_t* member;
int origMemberId = 0;
int endOffset = 0; 
int beginOffset = 0;
int i = 0;	
int idx = 0;
	varOffset = GetStackOffset(ea,operand);


	if(varOffset == BADADDR) return -1;

	member = get_member(struc, varOffset);
	endOffset = member->soff;

	idx = get_next_member_idx(struc, varOffset);

	if(idx == -1)
	{
		beginOffset = member->eoff;
	}
	else
		beginOffset = struc->members[ get_next_member_idx(struc, varOffset) ].soff;

	return beginOffset - endOffset;



	
}
/////////////////////////////////////////////////////////////////////////////////////////
// OverflowReturnAddressSize()
//
// Approximates the length of the buffer need to hit a return address.
//
// arguments: ea_t ea		- the EA of our stack variable
//			  int opernad	- the operand being 0 or 1 
// returns: size	
int funcx::OverflowReturnAddressSize(ea_t ea, int operand)
{

ea_t varOffset;
struc_t * struc = get_frame(func);
member_t* member;
int startOffset = 0; 
int beginOffset = 0;
int argSize = 0;
int i = 0;	
int frameWithoutArg = 0;
int idx = 0;
	varOffset = GetStackOffset(ea,operand);
	if(varOffset == BADADDR) return -1;

	member = get_member(struc, varOffset);
	startOffset = member->soff;

	idx = get_next_member_idx(struc, varOffset);

	if(idx == -1)
	{
		beginOffset = member->eoff;
	}
	else
		beginOffset = struc->members[ get_next_member_idx(struc, varOffset) ].soff;

	
	argSize = GetArgumentsSize();
	frameWithoutArg = GetFrameSize() - argSize;
	return frameWithoutArg - startOffset; 

}
/////////////////////////////////////////////////////////////////////////////////////////
// GetArguementsSize()
//
// Gets the size of the arguements
//
// arguments: none
//
// returns: size
int funcx::GetArgumentsSize()
{
int size = GetReturnAddressSize() + GetLocalVariableSize() + GetSavedRegsSize();
return GetFrameSize() - size;

	
}

int funcx::GetFirstArgument()
{
int size = GetSavedRegsSize() + GetReturnAddressSize() + GetLocalVariableSize();
struc_t * struc = get_frame(func);
member_t * member;
	
	
	member = get_member(struc, size);
	return size;
}
