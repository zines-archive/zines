////
//
// This plugin is designed to collect extra information from x64 binaries.
// It currently supports collecting the following information:
//
// - Detection of non-leaf functions
//
// By taking advantage of the information stored in the Exception Directory of
// x64 PE images, it's possible to detect all non-leaf functions (functions that
// use stack or call other functions) within a binary.
//
// - Extraction of function information from unwind information
//
// The unwind information associated with non-leaf functions can be used to
// determine the location of saved registers, the offset and use of a frame base
// pointer, and other such information.  This plugin takes this information and
// updates function stack frames with the location of saved registers and also
// determines the frame pointer delta if a frame pointer is used for a function.
//
// - Linking functions to their exception handlers
//
// In x64 binaries, exception dispatching is done by defining which exception
// handlers are executed for specific portions of a given function.  This
// information is static and is not generated at runtime.  This is quite
// different from x86 where exception handler information is stored on the stack
// and accessed relative to fs:[0].  By enumerating the exception handler
// information associated with a function's unwind information, it is possible
// to define a relationship between function and exception handler(s).
//
// - Register parameter area annotation
//
// Annotates a function's register parameter area on the stack of both its
// caller and of itself.
//
// skape
// mmiller@hick.org
// 04/2006
//
////
#include <ida.hpp>
#include <idp.hpp>
#include <dbg.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <bytes.hpp>
#include <name.hpp>
#include <ua.hpp>
#include <struct.hpp>
#include <typeinf.hpp>
#include <frame.hpp>

#include <vector>
#include <list>

#include "../../ldr/pe/pe.h"

#define add_dword_struc_member(struc, name) \
		add_struc_member(struc, name, BADADDR, dwrdflag(), NULL, 4)

////
//
// Constants
//
////

#define X64AUTO_MSG "x64: "

#define SIZEOF_IMAGE_RUNTIME_FUNCTION_ENTRY 12

#define UNWIND_INFO_MAX_CODES   256
#define UNWIND_INFO_HEADER_SIZE 4 

#define UNW_FLAG_EHANDLER  0x01
#define UNW_FLAG_UHANDLER  0x02
#define UNW_FLAG_CHAININFO 0x04

#define REG_RAX   0
#define REG_RCX   1
#define REG_RDX   2
#define REG_RBX   3
#define REG_RSP   4
#define REG_RBP   5
#define REG_RSI   6
#define REG_RDI   7
#define REG_R8    8
#define REG_R9    9
#define REG_R10   10
#define REG_R11   11
#define REG_R12   12
#define REG_R13   13
#define REG_R14   14
#define REG_R15   15
#define REG_XMM0  0
#define REG_XMM1  1
#define REG_XMM2  2
#define REG_XMM3  3
#define REG_XMM4  4
#define REG_XMM5  5
#define REG_XMM6  6
#define REG_XMM7  7
#define REG_XMM8  8
#define REG_XMM9  9
#define REG_XMM10 10
#define REG_XMM11 11
#define REG_XMM12 12
#define REG_XMM13 13
#define REG_XMM14 14
#define REG_XMM15 15

typedef enum _UNWIND_OP_CODES {
	UWOP_PUSH_NONVOL      = 0,
	UWOP_ALLOC_LARGE      = 1,
	UWOP_ALLOC_SMALL      = 2,
	UWOP_SET_FPREG        = 3,
	UWOP_SAVE_NONVOL      = 4,
	UWOP_SAVE_NONVOL_FAR  = 5,
	UWOP_SAVE_XMM128      = 8,
	UWOP_SAVE_XMM128_FAR  = 9,
	UWOP_PUSH_MACHFRAME   = 10
} UNWIND_CODE_OPS;

////
//
// Structure definitions
//
////

typedef struct _runtime_function_entry
{
	ea_t begin_address;
	ea_t end_address;
	ea_t unwind_info_address;

	//
	// Internal, the address that the runtime function entry was read from
	//
	ea_t self_ea;

} runtime_function_entry_t;

typedef union _unwind_code 
{
	struct
	{
		uchar  code_offset;
		uchar  unwind_op : 4;
		uchar  op_info   : 4;
	};
	ushort frame_offset;
} unwind_code_t;

typedef struct _vc_scope_table_entry
{
	ea_t begin;
	ea_t end;
	ea_t handler;
	ea_t target;
} vc_scope_table_entry_t;

#define MAX_SCOPE_TABLE_ENTRIES 16

typedef struct _exception_data_vc
{
	ulong num_entries;
	vc_scope_table_entry_t table[MAX_SCOPE_TABLE_ENTRIES];
} exception_data_vc_t;

typedef struct _unwind_info
{
	//
	// Do not move -- expected to be at the beginning of the structure.
	//
	uchar version : 3;
	uchar flags : 5;
	uchar size_of_prolog;
	uchar count_of_codes;
	uchar frame_register : 4;
	uchar frame_register_offset : 4;
	unwind_code_t codes[UNWIND_INFO_MAX_CODES];

	//
	// Not part of the actual unwind_info_t structure.  These fields are
	// associated with the runtime function entry to which this unwind
	// information corresponds with.
	//
	ea_t begin_address;
	ea_t end_address;
	ea_t unwind_info_address;
	ulong size;

	//
	// Extended information that is set depending on unwind info flags.
	//
	union
	{
		ea_t exception_handler;       // iif UNW_FLAG_EHANDLER
		ea_t unwind_handler;          // iif UNW_FLAG_UHANDLER
		runtime_function_entry_t rte; // iif UNW_FLAG_CHAINFINO
	};

	//
	// Exception data for specific languages.
	//
	union
	{
		exception_data_vc_t vc;
	} exdata;

	_unwind_info(ea_t begin, ea_t end, ea_t unwind) 
		: begin_address(begin), end_address(end), unwind_info_address(unwind)
	{
		memset(&exdata, 0, sizeof(exdata));
	
		exception_handler = 0;
	}

} unwind_info_t;

typedef struct _unwind_entry
{
	unwind_info_t *info;
	unwind_code_t *code;
} unwind_entry_t;

typedef struct _unwind_walk_data
{
	ulong last_frame_alloc;
	long current_frame_sp;
	long frame_register;
	long frame_register_offset;
	long frame_relative_sp;
} unwind_walk_data_t;

////
//
// Globals
//
////

//
// The structure identifier associated with IMAGE_RUNTIME_FUNCTION_ENTRY.
//
static tid_t runtime_func_tid = 0;

////
//
// El code
//
////

static bool wrap_add_func(ea_t begin, ea_t end)
{
	//
	// If the ea that marks the start of the language handler is not
	// code, then undefine it and mark it as such.
	//
	if (!isCode(getFlags(begin)))
	{
		do_unknown(begin, true);
		ua_code(begin);
	}

	return add_func(begin, end);
}

//
// Reads the runtime function entry at the specified address and populates the
// output structure.
//
static bool get_runtime_function_entry(ea_t ea, runtime_function_entry_t *rte,
		ea_t image_base = 0)
{
	ulong unwind_rva = get_long(ea + 8);

	rte->begin_address       = image_base + get_long(ea);
	rte->end_address         = image_base + get_long(ea + 4);
	rte->unwind_info_address = (unwind_rva) ? image_base + unwind_rva : 0;
	rte->self_ea             = ea;

	//
	// If this is directly chained unwind information with no extra information,
	// then that chaining will be indicated by the least significant bit being
	// set on the unwind info address.  Return the information associated with
	// the unwind information at the chained location.
	//
	// We cap the nesting depth at 32 to prevent a denial of service.
	//
	int max_depth = 32;

	while ((rte->unwind_info_address & 1) &&
	       (max_depth-- > 0))
	{
		ea_t chain_rte_address   = rte->unwind_info_address & (~1);

		rte->begin_address       = image_base + get_long(chain_rte_address);
		rte->end_address         = image_base + get_long(chain_rte_address + 4);
		rte->unwind_info_address = image_base + get_long(chain_rte_address + 8);
	}

	return (max_depth > 0) ? true : false;
}

//
// Gets exception information associated with the unwind information instance
// passed in.
//
void get_uinfo_exception_data(unwind_info_t *uinfo, ea_t image_base)
{
	ea_t exdata_ea = uinfo->unwind_info_address + uinfo->size + 4;

	uinfo->exception_handler = image_base + get_long(uinfo->unwind_info_address + uinfo->size);

	//
	// Extract exception data specific to language this image was compiled
	// with.
	//
	switch (inf.cc.id)
	{
		//
		// If this was detected as having been compiled with Visual C++, then
		// we at least know something about it.  For MSVC++, we walk the
		// scope table all pimp like.
		//
		case COMP_MS:
			{
				ulong idx;

				uinfo->exdata.vc.num_entries = qmin(get_long(exdata_ea), MAX_SCOPE_TABLE_ENTRIES);

				for (idx = 0, exdata_ea += 4; 
				     idx < uinfo->exdata.vc.num_entries; 
				     idx++, exdata_ea += 16)
				{
					ulong handler;

					uinfo->exdata.vc.table[idx].begin = image_base + get_long(exdata_ea);
					uinfo->exdata.vc.table[idx].end   = image_base + get_long(exdata_ea + 4);

					handler = get_long(exdata_ea + 8);

					uinfo->exdata.vc.table[idx].handler = (handler == 1) ? 0 : (image_base + handler);
					uinfo->exdata.vc.table[idx].target  = image_base + get_long(exdata_ea + 12);
				}
			}
			break;

		//
		// Unsupported compiler...
		//
		default:
			memset(&uinfo->exdata, 0, sizeof(uinfo->exdata));
			break;
	}
}

//
// Populates the supplied unwind information structure from the supplied ea.
// The correct number of unwind codes are read according to the count_of_codes
// attribute found at the address.
//
static bool get_unwind_info(ea_t image_base, unwind_info_t *uinfo)
{
	uchar count;
	bool res;

	count = get_byte(uinfo->unwind_info_address + 2);

	//
	// Cache the size associated with this unwind info (header + codes)
	//
	uinfo->size = UNWIND_INFO_HEADER_SIZE + (sizeof(unwind_code_t) * (((count + 1) & ~1)));

	res = get_many_bytes(uinfo->unwind_info_address, uinfo, uinfo->size);

	if (uinfo->version != 1)
	{
		msg(X64AUTO_MSG "Unwind information for function begin %016LX has unsupported version: %d\n",
				uinfo->begin_address, uinfo->version);
		return false;
	}

	if (res)
	{
		//
		// If this unwind information has chaining information, grab it.
		//
		if (uinfo->flags & UNW_FLAG_CHAININFO)
			get_runtime_function_entry(uinfo->unwind_info_address + uinfo->size, 
					&uinfo->rte, image_base);
		//
		// If this unwind information instance has an exception handler, extract
		// it.
		//
		else if ((uinfo->flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER)))
			get_uinfo_exception_data(uinfo, image_base);
	}

	return res;
}

//
// Returns the name SavedXXX where XXX is the name of the register being saved.
//
static const char *reg_to_save_name(uchar reg)
{
	switch (reg)
	{
		case REG_RAX: return "SavedRAX";   break;
		case REG_RCX: return "SavedRCX";   break;
		case REG_RDX: return "SavedRDX";   break;
		case REG_RBX: return "SavedRBX";   break;
		case REG_RSP: return "SavedRSP";   break;
		case REG_RBP: return "SavedRBP";   break;
		case REG_RSI: return "SavedRSI";   break;
		case REG_RDI: return "SavedRDI";   break;
		case REG_R8:  return "SavedR8";    break;
		case REG_R9:  return "SavedR9";    break;
		case REG_R10: return "SavedR10";   break;
		case REG_R11: return "SavedR11";   break;
		case REG_R12: return "SavedR12";   break;
		case REG_R13: return "SavedR13";   break;
		case REG_R14: return "SavedR14";   break;
		case REG_R15: return "SavedR15";   break;
		default:     return "UnknownREG"; break;
	}
}

static const char *xmmreg_to_save_name(uchar reg)
{
	switch (reg)
	{
		case REG_XMM0:  return "SavedXMM0";  break;
		case REG_XMM1:  return "SavedXMM1";  break;
		case REG_XMM2:  return "SavedXMM2";  break;
		case REG_XMM3:  return "SavedXMM3";  break;
		case REG_XMM4:  return "SavedXMM4";  break;
		case REG_XMM5:  return "SavedXMM5";  break;
		case REG_XMM6:  return "SavedXMM6";  break;
		case REG_XMM7:  return "SavedXMM7";  break;
		case REG_XMM8:  return "SavedXMM8";  break;
		case REG_XMM9:  return "SavedXMM9";  break;
		case REG_XMM10: return "SavedXMM10"; break;
		case REG_XMM11: return "SavedXMM11"; break;
		case REG_XMM12: return "SavedXMM12"; break;
		case REG_XMM13: return "SavedXMM13"; break;
		case REG_XMM14: return "SavedXMM14"; break;
		case REG_XMM15: return "SavedXMM15"; break;
		default:        return "UnknownXMM"; break;
	}
}

//
// Builds a vector of unwind codes in the order in which they are executed (the
// opposite order that they would be unwound).  If the supplied unwind
// information structure is chained, all of the chains will be walked and
// prepended to the reverse order vector.
//
bool build_reverse_unwind_codes(std::vector<unwind_entry_t> &reverse_codes,
		std::list<unwind_info_t *> &chain_uinfo_list, ea_t image_base,
		unwind_info_t *uinfo)
{
	unwind_info_t *chain_uinfo;
	ulong op_idx;
	bool walking = true;

	//
	// We start with the current unwind information as the first chain entry.
	//
	chain_uinfo = uinfo;

	do
	{
		op_idx = 0;

		//
		// Walk through all of the codes in the current chain entry.
		//
		while (op_idx < chain_uinfo->count_of_codes)
		{
			unwind_code_t *ucode = &chain_uinfo->codes[op_idx];

			switch (chain_uinfo->codes[op_idx].unwind_op)
			{
				case UWOP_PUSH_NONVOL:     break;
				case UWOP_ALLOC_LARGE:     
					(chain_uinfo->codes[op_idx].op_info == 0) ? op_idx++ : op_idx += 2; break;
				case UWOP_ALLOC_SMALL:     break;
				case UWOP_SAVE_NONVOL:     op_idx++;    break;
				case UWOP_SAVE_NONVOL_FAR: op_idx += 2; break;
				case UWOP_SAVE_XMM128:     op_idx++;    break;
				case UWOP_SAVE_XMM128_FAR: op_idx += 2; break;
				case UWOP_PUSH_MACHFRAME:  break;
				case UWOP_SET_FPREG:       break;
				default: break;
			}
		
			//
			// Insert the unwind entry into the front of the vector.
			//
			unwind_entry_t entry;

			entry.info = chain_uinfo;
			entry.code = ucode;

			reverse_codes.insert(reverse_codes.begin(), entry);

			//
			// Proceed to the next unwind code.
			//
			op_idx++;
		}

		//
		// Proceed to the next entry in the chain if the flags indicate that
		// there's another one.
		//
		if (chain_uinfo->flags & UNW_FLAG_CHAININFO)
		{
			//
			// Create an unwind information instance that's going to be associated
			// with the supplied runtime function entry addresses.
			//
			chain_uinfo = new unwind_info_t(chain_uinfo->rte.begin_address,
					chain_uinfo->rte.end_address, 
					chain_uinfo->rte.unwind_info_address);

			//
			// Read the unwind information associated with this item in the
			// chain.  If we fail, then bail out of the chain walk.
			//
			if (!get_unwind_info(image_base, chain_uinfo))
			{
				delete chain_uinfo;

				break;
			}

			//
			// Insert this unwind information instance into the list so that we
			// can deallocate it later.
			//
			chain_uinfo_list.push_back(chain_uinfo);
		}
		else
			walking = false;

	} while (walking);

	//
	// If we're done walking, then we succeed.  Otherwise, we fail.
	//
	return !walking;
}

//
// Walks the list of execution order unwind codes and processes them in relation
// to a given function.
//
void walk_reverse_unwind_codes(std::vector<unwind_entry_t> &reverse_codes,
		func_t *func, unwind_walk_data_t &uwd)
{
	//
	// Initialize the unwind walk data context.
	//
	memset(&uwd, 0, sizeof(uwd));

	for (std::vector<unwind_entry_t>::const_iterator it = reverse_codes.begin();
		  it != reverse_codes.end();
		  it++)
	{
		unwind_code_t *curr_code = (*it).code;
		
		//
		// Does anyone know a better way to get the previous ea other than using
		// decode_prev_insn?  prev_visea doesn't quite work right all the time.
		//
		ea_t inst_ea = decode_prev_insn((*it).info->begin_address + curr_code->code_offset);

		switch (curr_code->unwind_op)
		{
			//
			// For non-volatile push operations, we set the comment of the ea
			// that does the push operation to indicate that it's doing so to
			// save a register.
			//
			case UWOP_PUSH_NONVOL:
				set_cmt(inst_ea, reg_to_save_name(curr_code->op_info), false);

				uwd.current_frame_sp -= 8;
				break;

			//
			// For large stack allocations, we adjust the current allocation
			// frame by the number indicated in the additional unwind code
			// slots.
			//
			case UWOP_ALLOC_LARGE:
				if (curr_code->op_info == 0)
					uwd.last_frame_alloc = (curr_code[1].frame_offset * 8);
				else
					uwd.last_frame_alloc = *(ulong *)(curr_code + 1);

				uwd.current_frame_sp -= uwd.last_frame_alloc;
				break;

			//
			// For small stack allocations, we adjust the current allocation
			// frame accordingly.
			//
			case UWOP_ALLOC_SMALL:
				uwd.last_frame_alloc = (curr_code->op_info * 8) + 8;

				uwd.current_frame_sp -= uwd.last_frame_alloc;
				break;

			//
			// Define the stack frame register that will be used for subsequent
			// references.
			//
			case UWOP_SET_FPREG:
				uwd.frame_register_offset  = (*it).info->frame_register_offset * 16;
				uwd.frame_relative_sp      = uwd.current_frame_sp;
				break;

			//
			// For non-volatile register saves using MOV, we define a stack
			// variable at the location that the saved register will reside and
			// indicate which register it's saving.
			//
			case UWOP_SAVE_NONVOL:
			case UWOP_SAVE_NONVOL_FAR:
				{
					ulong frame_offset;
				
					//
					// Calculate the offset into the frame for the non-volatile
					// save.
					//
					if (curr_code->unwind_op == UWOP_SAVE_NONVOL_FAR)
						frame_offset = *(ulong *)(curr_code + 1);
					else
						frame_offset = curr_code[1].frame_offset * 8;

					//
					// Add a stack variable using the name associated with the
					// register that's being saved and the offset relative to the
					// current frame stack pointer plus the offset into the frame.
					//
					add_stkvar2(func, reg_to_save_name(curr_code->op_info), 
							(long)(uwd.current_frame_sp + frame_offset), qwrdflag(), NULL, 8);

					//
					// Set the comment indicating that this instruction is a
					// register saving instruction.
					//
					set_cmt(inst_ea, reg_to_save_name(curr_code->op_info), false);
				}
				break;

			//
			// Define the stack variable location and comment the instruction that
			// saves the XMM register.
			//
			case UWOP_SAVE_XMM128:
			case UWOP_SAVE_XMM128_FAR:
				{
					ulong frame_offset;

					if (curr_code->unwind_op == UWOP_SAVE_XMM128_FAR)
						frame_offset = *(ulong *)(curr_code + 1);
					else
						frame_offset = curr_code[1].frame_offset * 16;

					//
					// Add the oword (128-bit) stack variable definition at the
					// location we've determined.
					//
					add_stkvar2(func, xmmreg_to_save_name(curr_code->op_info),
							(long)(uwd.current_frame_sp + frame_offset), owrdflag(), NULL, 16);

					set_cmt(inst_ea, xmmreg_to_save_name(curr_code->op_info), false);
				}
				break;

			//
			// Just annotate this function as expecting a machine frame.
			//
			case UWOP_PUSH_MACHFRAME:
				set_func_cmt(func, "Expects a machine frame (hardware interrupt or exception)", false);
				break;

			default:
				msg(X64AUTO_MSG "Unknown unwind op encountered: %d\n", 
						curr_code->unwind_op);
				break;
		}
	}
}

//
// Processes the unwind codes associated with the supplied unwind information
// context and does any necessary annotations for the function it's associated
// with.
//
static void process_unwind_codes(func_t *func, unwind_info_t *uinfo,
		ea_t image_base, unwind_walk_data_t &uwd)
{
	//
	// Build the reverse-order list of unwind codes for this unwind
	// information (and any unwind information it's chained with).
	//
	std::vector<unwind_entry_t> reverse_codes;
	std::list<unwind_info_t *> chain_uinfo_list;

	if (!build_reverse_unwind_codes(reverse_codes, chain_uinfo_list, image_base,
			uinfo))
		return;

	//
	// Now that we have the reverse order vector of unwind codes, let's process
	// them.  Since the vector is in reverse order, we'll be processing them
	// in the order that they are executed rather than in the order in which
	// they would be unwound.  This is done because we need to keep track of
	// state in the execution direction, such as stack pointer offsets and so
	// on.
	//
	walk_reverse_unwind_codes(reverse_codes, func, uwd);

	//
	// Reanalyze the function now that we've made changes such that stack
	// variable references can be updated accordingly.
	//
	reanalyze_function(func);

	//
	// If we had a valid frame register defined for this function, then set
	// the function as being bp-based function and update the function bp
	// delta relative to the last frame alloc.  We have to reanalyze again
	// because IDA gets angry if we don't -- IDA bug or me being stupid?
	// Probably the latter.
	//
	if (uwd.frame_register_offset)
	{
		func->flags = FUNC_FRAME;

		update_fpd(func, abs(uwd.frame_relative_sp + uwd.frame_register_offset));
	
		reanalyze_function(func);
	}

	//
	// Flush the chain unwind information list now that we're through with it.
	//
	while (!chain_uinfo_list.empty())
	{
		delete *chain_uinfo_list.begin();

		chain_uinfo_list.pop_front();
	}
}

//
// Processes a runtime function entry from the exception directory, enumerating
// the unwind information codes and annotating the function associated with the
// entry with all of the meta data that's found.
//
static void process_runtime_function_entry(ea_t image_base,
		runtime_function_entry_t &rte)
{
	unwind_walk_data_t uwd;
	unwind_info_t uinfo(rte.begin_address, rte.end_address, rte.unwind_info_address);
	func_t *func = get_func(rte.begin_address);
	bool function_entry = false;

	do
	{
		//
		// No unwind information?  Then there's not much for us to do.
		//
		if ((!rte.unwind_info_address) ||
		    (!get_unwind_info(image_base, &uinfo)))
			break;
	
		//
		// If this is not chained unwind information, then it's probably
		// associated with the start of a function.
		//
		if ((uinfo.flags & UNW_FLAG_CHAININFO) == 0)
			function_entry = true;

		//
		// If we were unable to define or find a function at this location, then
		// let's do that now, but only if this unwind information is associated
		// with a function entry.
		//
		if ((function_entry) &&
		    (!func))
		{
			wrap_add_func(rte.begin_address, rte.end_address);

			func = get_func(rte.begin_address);

			//
			// If we failed to add the function, then what may have happened is
			// that IDA improperly detected the start address of the function in
			// question (such as is the case when a function has a nop for hot
			// patching purposes).  Let's check for that case.
			//
			if (!func)
			{
				if (get_func(rte.begin_address + 2))
					func_setstart(rte.begin_address + 2, rte.begin_address);

				func = get_func(rte.begin_address);

				if (!func)
				{
					msg(X64AUTO_MSG "Failed to define function at %016LX.\n", rte.begin_address);
					break;
				}
			}
		}

		//
		// Process the unwind codes associated with the unwind information for
		// this runtime function entry.
		//
		process_unwind_codes(func, &uinfo, image_base, uwd);

		//
		// If this unwind information has an exception handler associated with it,
		// then grab it.
		//
		if (uinfo.flags & UNW_FLAG_EHANDLER)
		{
			char exception_handler_name[MAXSTR], msg_string[MAXSTR];
			int off;

			//
			// If IDA hasn't detected this function, then let's be nice and define
			// it for it.
			//
			if (!get_func(uinfo.exception_handler))
				wrap_add_func(uinfo.exception_handler, BADADDR);

			//
			// Get the name of the function...
			//
			get_func_name(uinfo.exception_handler, exception_handler_name,
					sizeof(exception_handler_name));
			exception_handler_name[sizeof(exception_handler_name) - 1] = 0;

			//
			// Append our comment.
			//
			off = qsnprintf(msg_string, sizeof(msg_string), 
					"Exception handler: %s (ea=%016LX)",
					exception_handler_name, uinfo.exception_handler);

			//
			// If we're using an MS VC++ compiler, dump the scope table for this
			// function...
			//
			if ((inf.cc.id == COMP_MS) &&
			    (off > 0))
			{
				ulong idx;

				for (idx = 0;
				     idx < uinfo.exdata.vc.num_entries;
				     idx++)
				{
					ea_t lang_handler = uinfo.exdata.vc.table[idx].handler;

					if (!lang_handler)
						continue;

					//
					// Define the language specific handler function if it hasn't
					// been defined yet.
					//
					if (!get_func(lang_handler))
						wrap_add_func(lang_handler, BADADDR);

					get_func_name(lang_handler, exception_handler_name,
							sizeof(exception_handler_name));
					exception_handler_name[sizeof(exception_handler_name) - 1] = 0;

					if (off < 0)
						continue;

					//
					// Append to the string that we'll be using for the function
					// comment.
					//
					off = qsnprintf(msg_string + off, sizeof(msg_string) - off,
							"\nLanguage specific handler: %s (ea=%016LX, from %016LX->%016LX, transfer to %016LX)",
							exception_handler_name, lang_handler,
							uinfo.exdata.vc.table[idx].begin,
							uinfo.exdata.vc.table[idx].end,
							uinfo.exdata.vc.table[idx].target);
				}
			}
			
			msg_string[sizeof(msg_string) - 1] = 0;

			//
			// FIXME: This will clobber anyone's function level comments at this
			// point.  Maybe we should handle this more gracefully?
			//
			set_func_cmt(func, msg_string, false);
		}

		//
		// If this is a function entry, add some extra annotation to the stack
		// frame to indicate the locations of the caller's argument home locations
		// on the stack and the callee's argument home locations.
		//
		if (function_entry)
		{
			//
			// Add stack variables to the base of the stack frame that will be used
			// by called functions as the home location for rcx, rdx, r8 and r9.
			//
			add_stkvar2(func, "OurRCX", uwd.current_frame_sp, qwrdflag(), NULL, 8);
			add_stkvar2(func, "OurRDX", uwd.current_frame_sp + 0x8, qwrdflag(), NULL, 8);
			add_stkvar2(func, "OurR8",  uwd.current_frame_sp + 0x10, qwrdflag(), NULL, 8);
			add_stkvar2(func, "OurR9",  uwd.current_frame_sp + 0x18, qwrdflag(), NULL, 8);
			
		
			//
			// Add stack variables for the caller's home locations for preserving
			// rcx, rdx, r8, and r9 in the context of a called function.
			//
			add_stkvar2(func, "CallerRCX", 0x8, qwrdflag(), NULL, 8);
			add_stkvar2(func, "CallerRDX", 0x10, qwrdflag(), NULL, 8);
			add_stkvar2(func, "CallerR8",  0x18, qwrdflag(), NULL, 8);
			add_stkvar2(func, "CallerR9",  0x20, qwrdflag(), NULL, 8);
		}

	} while (0);
}

static void define_function_structures()
{
	struc_t *curr_struct;

	//
	// Create the IMAGE_RUNTIME_FUNCTION_ENTRY structure if it's not already
	// defined.
	//
	runtime_func_tid = get_struc_id("IMAGE_RUNTIME_FUNCTION_ENTRY");

	if (runtime_func_tid == BADADDR)
	{
		curr_struct = get_struc(
				runtime_func_tid = add_struc(BADADDR, "IMAGE_RUNTIME_FUNCTION_ENTRY"));

		if (curr_struct)
		{
			add_dword_struc_member(curr_struct, "BeginAddress");
			add_dword_struc_member(curr_struct, "EndAddress");
			add_dword_struc_member(curr_struct, "UnwindInfoAddress");
		}
	}
}

static void process_exception_directory(netnode *penode, peheader64_t *pe)
{
	ulong num_functions, idx;
	ea_t  image_base = penode->altval(PE_ALT_IMAGEBASE);
	ea_t  curr_ea;

	do
	{
		segment_t *seg = get_segm_by_name(".pdata");

		if (!seg)
		{
			msg(X64AUTO_MSG "Failed to locate exception directory segment.\n");
			break;
		}
	
		//
		// Define runtime function & unwind structures.
		//
		define_function_structures();

		num_functions = (ulong)(seg->size() / SIZEOF_IMAGE_RUNTIME_FUNCTION_ENTRY);
		curr_ea       = seg->startEA;

		msg(X64AUTO_MSG "Processing exception directory... %lu non-leaf functions.\n",
				num_functions);

		for (idx = 0;
		     idx < num_functions;
		     idx++, curr_ea += SIZEOF_IMAGE_RUNTIME_FUNCTION_ENTRY)
		{
			runtime_function_entry_t rte;
			char name[32];

			// 
			// Invalid function begin address?
			//
			if (!get_long(curr_ea))
				continue;

			//
			// Set the name of the runtime function entry to rte_XXX.
			//
			qsnprintf(name, sizeof(name), "rte_%d", idx);

			name[sizeof(name) - 1] = 0;

			set_name(curr_ea, name);

			//
			// First, mark this range as unknown, just in case IDA detected it as
			// code (due to an incorrect cref).
			//
			do_unknown_range(curr_ea, 12, false);

			//
			// Define this location as a structure.
			//
			doStruct(curr_ea, SIZEOF_IMAGE_RUNTIME_FUNCTION_ENTRY, runtime_func_tid);

			//
			// Process the runtime function entry for this location.
			//
			if (!get_runtime_function_entry(curr_ea, &rte, image_base))
				continue;

			process_runtime_function_entry(
					image_base,
					rte);
		}

		msg(X64AUTO_MSG "Exception directory processing completed.\n");

	} while (0);
}

static void idaapi run(int arg)
{
	peheader64_t pe;
	netnode penode(PE_NODE);

	if (!penode.valobj(&pe, sizeof(pe)))
	{
		msg(X64AUTO_MSG "Failed to create pe node...\n");
		return;
	}

	//
	// First, this plugin processes the exception directory (.pdata)
	// associated with the binary if any exists (which it should).  In doing
	// this, it extracts useful information about stack frame layout, register
	// saves, and the location and relationship of non-leaf functions.
	//
	process_exception_directory(&penode, &pe);
}

static int idaapi init(void)
{
	int res = PLUGIN_SKIP;

	do
	{
		//
		// Not a PE image?
		//
		if (inf.filetype != f_PE)
			break;

		//
		// Grab the PE header.
		//
		peheader64_t pe;
		netnode penode(PE_NODE);

		if (!penode.valobj(&pe, sizeof(pe)))
		{
			msg(X64AUTO_MSG "Could not locate PE header in image.\n");
			break;
		}

		//
		// Check to make sure that this PE header is built to run on AMD64.
		//
		if (pe.machine != PECPU_AMD64)
		{
			msg(X64AUTO_MSG "Unsupported PE machine: %d\n", pe.machine);
			break;
		}

		res = PLUGIN_OK;

	} while (0);

	return res;
}

static void idaapi term(void)
{
}

static char plugin_short_name[] = "AMD64 Analysis Plugin";
static char plugin_comment[]    = "Performs extra analysis on x64 binary images";
static char plugin_hotkey[]     = "Alt-F7";
static char plugin_multiline[]  = "This plugin extracts useful information from x64 binary images.";

plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,
	PLUGIN_UNL,
	init,
	term,
	run,
	plugin_comment,
	plugin_multiline,
	plugin_short_name,
	plugin_hotkey
};
