//
// Memalyze - runtime data flow analysis
//
// Description
// ===========
//
// Very simple implementation of a runtime data flow analysis tool that monitors
// reads and writes to memory and attempts to analyze their dependencies in an
// effort to show data propagation.
//
// Dependency analysis
// ===================
//
// When doing runtime data flow analysis on memory transactions, it is important
// to identify how memory reads and writes can be associated in terms of their
// dependencies on one another.
//
// Value Dependencies (Implemented)
// ==================
//
// When an instruction reads memory, it is inherently dependent on the
// instruction that previously wrote to the address that it is reading from in
// terms of order of operations.  This type of dependency will be referred to as
// a "value" dependency, since the read instruction depends on the value that
// was written by the write instruction.  In simpler terms, the read instruction
// is value dependent on the write instruction.  During the course of execution,
// writes will constantly invalidated previous read dependencies as the contents
// of the address space changes.  This means that whenever a write occurs to an
// address that previously had dependencies on another writer, those
// dependencies can be aggressively invalidated because they are no longer valid
// (since the value that they readers were dependent on has now changed).
//
// Address Dependencies (TODO)
// ====================
//
// The other type of dependency is known as an "address" dependency.  This
// dependency is a way of showing that one memory read instruction depends on
// another memory read instruction in terms of order of operations.  This can be
// the case when the address that memory is read from is derived from the
// contents of another memory read operation in some fashion.  For instance, if
// one has an array of pointers, the act of reading the array and then
// dereferencing a pointer stored as an element shows an inherent address
// dependency in the first order on the array that contains the pointer.  This
// association can be useful in showing how data is propagated.  In order to
// identify address dependencies, instruction state analysis must be done in
// order to determine how a given instruction derives the address from which it
// will read (in terms of what populates certain registers, for instance).
//
// TODO
// ====
//
//   - Support stack push/pop instructions as memory reads/writes.
//
// skape
// mmiller@hick.org
// 3/2006
//
#include "dynamorio.h"

#ifdef LINUX
# define EXPORT
#else
# define EXPORT __declspec(dllexport)
#endif

//
// These defines filter read tracking to a specific virtual address range if
// RFILTER_RANGE is defined to 1.  This can be used to limit the number of
// dependencies calculated.
//
#define RFILTER_RANGE 1
#define RFILTER_START 0x00400000
#define RFILTER_STOP  0x00410000

//
// These defines filter write tracking to a specific virtual address range if
// WFILTER_RANGE is defined to 1.  
//
#define WFILTER_RANGE 0
#define WFILTER_START 0x00400000
#define WFILTER_STOP  0x00410000

//
// If this is uncommented, verbose logging is enabled.
//
//#define VERBOSE

#define LOG_PREFIX "MEMALYZE: "

typedef void (*mem_read_callback)(uint va, uint ea, int size);
typedef void (*mem_write_callback)(uint va, uint ea, int size);
 
#define EA_WRITER_HASH_BUCKETS  0x40000
#define EA_WRITER_HASH_MASK(ea) ((ea >> 12) & (EA_WRITER_HASH_BUCKETS-1))

typedef struct _EaWriter
{
	struct _EaWriter *next; // replace with avl tree for perf
	uint ea;
	uint wva;
	uint size;
	uint *vdep;
	uint num_vdep;
} EaWriter;

//
// The global memory log descriptor that will be used to log memory read and
// write operations for the duration of the program's execution.
//
static File memlog = NULL;

//
// Mutex that protects the ea_writer_hash.
//
static int ea_writer_hash_mutex;

//
// Hash table that enables quick lookups of effective write addresses.  Right
// now each bucket in the table is just a linked list.  In reality, this should
// be transitioned to a balanced binary tree (AVL tree) for better performance
// O(log n) vs O(n) after hashing.  Maximum linear search depth is 4096.
// Maximum AVL depth would be 17.
//
static EaWriter *ea_writer_hash[EA_WRITER_HASH_BUCKETS];

////
//
// Dependency tracking
//
////

//
// Allocates storage for an ea writer context.
//
static EaWriter *allocate_ea_writer(uint ea, uint wva, uint size)
{
	EaWriter *writer = (EaWriter *)dr_global_alloc(sizeof(EaWriter));

	memset(writer, 0, sizeof(EaWriter));

	writer->ea   = ea;
	writer->wva  = wva;
	writer->size = size;

	return writer;
}

//
// Creates a value dependency in the direction of the read va (rva) dependening
// on the write va (wva) due to a read from ea.
//
static void create_value_dependency(uint ea, uint rva, uint size)
{
	EaWriter *curr;
	
	dr_mutex_lock(&ea_writer_hash_mutex);

	//
	// Keep enumerating until we account for all the bytes read by the reader in
	// terms of writer dependencies.
	//
	do
	{
		curr = ea_writer_hash[EA_WRITER_HASH_MASK(ea)];
	
		while (curr)
		{
			//
			// If this address being written to is within this ea writer, then add
			// the provided read va as being dependent on this writer for its value.
			//
			if ((ea >= curr->ea) &&
			    (ea < curr->ea + curr->size))
			{
				uint *vdeps;
				uint bsize;

				//
				// If a value dependency has already been determined for this
				// combination, then track it.
				//
				for (bsize = 0; bsize < curr->num_vdep; bsize++)
				{
					if (curr->vdep[bsize] == rva)
					{
						dr_mutex_unlock(&ea_writer_hash_mutex);
						return;
					}
				}

				//
				// Grow the value dependency array by one (dr doesn't expose
				// realloc, so we do it ourselves in a lame way).
				//
				vdeps = (uint *)dr_global_alloc((curr->num_vdep + 1) * sizeof(uint));
				vdeps[curr->num_vdep] = rva;

				//
				// Copy existing value dependencies.
				//
				if (curr->num_vdep)
				{
					memcpy(vdeps, curr->vdep, curr->num_vdep * sizeof(uint));
					dr_global_free(curr->vdep, curr->num_vdep * sizeof(uint));
				}

				dr_fprintf(memlog, "VDEP : RVA=0x%p depends on WVA=0x%p for write to EA=0x%p LENGTH=%d\n",
						rva, curr->wva, ea, size);

				//
				// Update the value dependency array.
				//
				curr->vdep      = vdeps;
				curr->num_vdep += 1;

				bsize = curr->size - (ea - curr->ea);
				size -= (bsize > size) ? size : bsize;

				break;
			}
	
			curr = curr->next;
		}

	} while ((size > 0) && (curr));
	
	dr_mutex_unlock(&ea_writer_hash_mutex);
}

//
// Invalidates the last instruction to write to the supplied ea and removes all
// dependent read va's.
//
static void invalidate_ea_writer(uint ea, uint size)
{
	EaWriter *prev = NULL, *curr;

	dr_mutex_lock(&ea_writer_hash_mutex);

	//
	// Keep looping until we invalidate all writers based on the total number of
	// bytes written.
	//
	do
	{
		curr = ea_writer_hash[EA_WRITER_HASH_MASK(ea)];
	
		while (curr)
		{
			//
			// If the current write address is within this ea writer, invalidate it
			// and move on by removing it from the chain.
			//
			if ((ea >= curr->ea) &&
			    (ea < curr->ea + curr->size))
			{
				uint bsize;

				if (prev)
					prev->next = curr->next;
				else
					ea_writer_hash[EA_WRITER_HASH_MASK(ea)] = curr->next;

				bsize = curr->size - (ea - curr->ea);
				size -= (bsize > size) ? size : bsize;

				break;
			}
	
			prev = curr;
			curr = curr->next;
		}

		//
		// If we invalidated a node, now's the time to free it's value dependency
		// array and free the node itself.
		//
		if (curr)
		{
			if (curr->vdep)
				dr_global_free(curr->vdep, curr->num_vdep * sizeof(uint));
			dr_global_free(curr, sizeof(EaWriter));
		}

	} while ((size > 0) && (curr));
	
	dr_mutex_unlock(&ea_writer_hash_mutex);
}

//
// Sets the va of the writer to the supplied address.
//
static void set_ea_writer(uint ea, uint wva, uint size)
{
	EaWriter *chain;

	//
	// First, invalidate all previous writers to this address.
	//
	invalidate_ea_writer(ea, size);

	dr_mutex_lock(&ea_writer_hash_mutex);

	//
	// Next, create our ea writer for this address and chain ourselves in.
	//
	chain = allocate_ea_writer(ea, wva, size);
	chain->next = ea_writer_hash[EA_WRITER_HASH_MASK(ea)];
	ea_writer_hash[EA_WRITER_HASH_MASK(ea)] = chain;

	dr_mutex_unlock(&ea_writer_hash_mutex);	
}


////
//
// DynamoRIO internal code for intercepting reads/writes.
//
////

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
#ifdef VERBOSE
	dr_fprintf(memlog, "WRITE: VA=0x%p EA=0x%p LENGTH=%d\n",
			va, ea, size);
#endif

	//
	// Set the writer of this effective address.
	//
	set_ea_writer(ea, va, size);
}

//
// Called when a memory read operation is about to occur.  This callback
// determines the address that memory is being read from.
//
static void on_memory_read(uint va, uint ea, int size)
{
#ifdef VERBOSE
	dr_fprintf(memlog, "READ : VA=0x%p EA=0x%p LENGTH=%d\n",
			va, ea, size);
#endif

	//
	// Create a value dependency for this reader on whoever was last to write to
	// the supplied effective address.
	//
	create_value_dependency(ea, va, size);
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
	// If the operand references memory (as we should always expect), then we
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

	dr_fprintf(memlog, 
			"\n"
			"  Memalyze Key\n"
			"  ============\n\n"
			" VDEP = value dependency (the RVA depends on the value that was written by the WVA)\n"
			" RVA  = read virtual address (the address of the instruction reading from memory)\n"
			" WVA  = write virtual address (the address of the instruction writing to memory)\n"
			" EA   = the address being written to/read from\n\n");

	dr_mutex_init(&ea_writer_hash_mutex);

	memset(ea_writer_hash, 0, sizeof(ea_writer_hash));
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
		{
#if RFILTER_RANGE
			if (va < RFILTER_STOP && va >= RFILTER_START)
#endif
			analyze_memory(drcontext, ilist, curr, va, true);
		}
		if (instr_writes_memory(curr))
		{
#if WFILTER_RANGE
			if (va < WFILTER_STOP && va >= WFILTER_START)
#endif
			analyze_memory(drcontext, ilist, curr, va, false);
		}

		va += instr_length(drcontext, curr);
	}
}
