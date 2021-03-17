//
// Very simple (and not very efficient) implementation of a runtime data flow
// analysis tool that monitors reads and writes to memory.  The output is
// intended to be analyzed in relation to static binary images such that
// relationships between read and write instructions can be determined.  After
// these determinations have been made, logic can be written to track how memory
// could propagate through the address space in a given scenario.
//
// TODO
//
//   - Support stack push/pop instructions as memory reads/writes.
//
// skape
// mmiller@hick.org
// 2/2006
//
#include "dynamorio.h"

#ifdef LINUX
# define EXPORT
#else
# define EXPORT __declspec(dllexport)
#endif

#define LOG_PREFIX "MEMALYZE: "

typedef void (*mem_read_callback)(uint va, uint ea, int size);
typedef void (*mem_write_callback)(uint va, uint ea, int size);

//
// The global memory log descriptor that will be used to log memory read and
// write operations for the duration of the program's execution.
//
static File memlog = NULL;

//
// Creates a callback into the supplied callback routine relative to the
// supplied instruction.  This callback is designed to be called prior to a
// memory read or write operation being performed.
//
static void memalyze_setup_callback(void *drcontext, InstrList *ilist, 
		Instr *inst, uint va, Instr *lea_ea, Instr *push_ea, Instr *adj_ea,
		int size, void *cb)
{
	Instr *call  = INSTR_CREATE_call(drcontext, opnd_create_pc((app_pc)cb));
	Instr *push_va = INSTR_CREATE_push_imm(drcontext, OPND_CREATE_INT32(va));
	Instr *push_sz = INSTR_CREATE_push_imm(drcontext, OPND_CREATE_INT32(size));

	//
	// Prepare for a call operation (save GP register state, flags, and thread
	// error state).
	//
	dr_prepare_for_call(drcontext, ilist, inst);

	//
	// Restore eax from the saved eax since dynamorio saves GetLastError by
	// issuing a call to it (inefficient), should directly obtain last error, but
	// that's another story).
	//
	instrlist_meta_preinsert(ilist, inst, 
			INSTR_CREATE_mov_ld(drcontext, 
				opnd_create_reg(REG_EAX),
				opnd_create_base_disp(
					REG_ESP, REG_NULL, 1, 0x24, SIZE_d)));

	//
	// Push the size, in bytes, of the read or write operation.
	//
	instrlist_meta_preinsert(ilist, inst, push_sz);

	//
	// Push the effective address being written to or read from. 
	//
	instrlist_meta_preinsert(ilist, inst, lea_ea);

	if (adj_ea)
		instrlist_meta_preinsert(ilist, inst, adj_ea);

	instrlist_meta_preinsert(ilist, inst, push_ea);

	//
	// Push the virtual address that is doing the reading or writing.
	//
	instrlist_meta_preinsert(ilist, inst, push_va);

	//
	// Push the call into the memalyze callback.
	//
	instrlist_meta_preinsert(ilist, inst, call);

	dr_cleanup_after_call(drcontext, ilist, inst, 12);
}

//
// Called when a memory write operation is about to occur.  This callback
// determines the target address of the write and the value that will be written
// and logs the information to the appropriate log file for subsequent analysis.
//
static void on_memory_write(uint va, uint ea, int size)
{
	dr_fprintf(memlog, "WRITE: VA=0x%p EA=0x%p LENGTH=%d\n",
			va, ea, size);
}

//
// Called when a memory read operation is about to occur.  This callback
// determines the address that memory is being read from.
//
static void on_memory_read(uint va, uint ea, int size)
{
	dr_fprintf(memlog, "READ : VA=0x%p EA=0x%p LENGTH=%d\n",
			va, ea, size);
}

//
// Creates the load and push instructions that are used to access the address
// that is being accessed by a given memory access operation.
//
static void create_ea_push(void *drcontext, Opnd op, Instr **lea_out,
		Instr **push_out, Instr **adj_out)
{
	int reg = REG_EAX;
	int seg = 0;

	//
	// If the operand is referencing relative to ESP, then we need to first load
	// the original ESP address into eax and adjust it accordingly via a
	// subsequent lea instruction.
	//
	if ((opnd_is_reg(op)) && (opnd_get_reg(op) == REG_ESP))
	{
		*lea_out = INSTR_CREATE_mov_ld(drcontext,
				opnd_create_reg(reg),
				opnd_create_base_disp(
					REG_ESP, REG_NULL, 
					1, 0x18, 
					SIZE_d));

		*adj_out = INSTR_CREATE_lea(drcontext,
				opnd_create_reg(reg),
				opnd_create_base_disp(
					reg, opnd_get_index(op), 
					opnd_get_scale(op), opnd_get_disp(op),
					SIZE_m));
	}
	//
	// Otherwise, just handle this as a normal memory operand.
	//
	else
	{
		if (opnd_is_far_base_disp(op) || opnd_is_far_pc(op))
			seg = opnd_get_segment(op);
	
		*lea_out = INSTR_CREATE_lea(drcontext, 
				opnd_create_reg(reg), 
				opnd_create_base_disp(
					opnd_get_base(op), opnd_get_index(op),
					opnd_get_scale(op), opnd_get_disp(op),
					SIZE_m));

		//
		// The lea instruction doesn't support segment-relative effective address
		// translations.  We must manual adjust this as necessary by extracting the
		// thread's TEB base address via fs:0x18 and adding it to whatever was being
		// referenced relative to FS.
		//
		if (seg == SEG_FS)
		{
#ifndef WIN32
#error "fs-relative lea not supported"
#else
			*adj_out = INSTR_CREATE_add(drcontext,
					opnd_create_reg(reg),
					opnd_create_far_base_disp(
						SEG_FS,
						REG_NULL,
						0,
						1,
						0x18,
						SIZE_d));
#endif
		}
	}

	//
	// Generate the push for the result of the load/adjust.
	//
	*push_out = INSTR_CREATE_push(drcontext, opnd_create_reg(reg));
}

//
// Analyzes a memory accessing instruction and creates a callback routine as
// necessary to monitor its execution.
//
static void analyze_memory(void *drcontext, InstrList *ilist,
		Instr *inst, uint va, bool read)
{
	Instr *lea = NULL, *push = NULL, *adj = NULL;
	void * cb;
	Opnd   op;
	int    size = 0;

	//
	// If this is a read operation, extract the operand that references a memory
	// address for reading.  This may not necessarily be the first operand if the
	// instruction has more than one implicit operand.
	//
	if (read)
	{
		if (!instr_num_srcs(inst))
			return;
	
		op = instr_get_src(inst, 0);
	
		if ((!opnd_is_memory_reference(op)) &&
		    (instr_num_srcs(inst) > 1))
			op = instr_get_src(inst, 1);

		cb = (void *)on_memory_read;
	}
	//
	// If this is a write operand, extract the destination operand that
	// references memory.  We assume this to be the first destination operand.
	//
	else
	{
		if (!instr_num_dsts(inst))
			return;

		op = instr_get_dst(inst, 0);
		cb = (void *)on_memory_write;
	}

	//
	// If the oeprand references memory (as we should always expect), then we
	// generate the load and push instructions (as well as an optional adjustment
	// instruction) that will be used to construct the callback code whenever the
	// memory read/write occurs.
	//
	if (opnd_is_memory_reference(op))
		create_ea_push(drcontext, op, &lea, &push, &adj);

	//
	// If we've yet to determine a size...
	//
	if (!size)
	{
		//
		// Is the size not applicable?  Well, we'll default to 4 bytes then.
		//
		if ((size = opnd_get_size(op)) != SIZE_NA)
			size = opnd_size_in_bytes(size, instr_get_prefixes(inst));
		else
			size = 4;
	}

	//
	// If we have valid instructions that will be used to determine the effective
	// address, then create the callback for this instruction.
	//
	if (lea && push)
		memalyze_setup_callback(drcontext, ilist, 
				inst, va, lea, push, adj, size, cb);
}

////
//
// Dynamo interface
//
////

//
// Initializes the log file that reads/writes will be logged to.
//
EXPORT void dynamorio_init()
{
	dr_log(NULL, LOG_ALL, 1, LOG_PREFIX " Initialized.\n");

	memlog = dr_open_log_file("memalyze");
}

//
// Close the log file we opened to track reads/writes.
//
EXPORT void dynamorio_exit()
{
	if (memlog)
		dr_close_file(memlog);
}

//
// Whenever a new basic block is created, this routine checks to see which nodes
// make references to memory and sets up the appropriate callbacks such that the
// read and write operations can be intercepted prior to them actually
// happening.
//
EXPORT void dynamorio_basic_block(void *drcontext, app_pc tag, InstrList *ilist)
{
	Instr *curr;
	uint   va = (uint)tag;

	for (curr = instrlist_first_expanded(drcontext, ilist);
	     curr;
	     curr = instr_get_next_expanded(drcontext, ilist, curr))
	{
		if (instr_reads_memory(curr))
			analyze_memory(drcontext, ilist, curr, va, true);
		if (instr_writes_memory(curr))
			analyze_memory(drcontext, ilist, curr, va, false);

		va += instr_length(drcontext, curr);
	}
}
