#ifndef _MEMALYZE_DLL_MIRROR_H
#define _MEMALYZE_DLL_MIRROR_H

#define MAX_MEMORY_MONITOR_CALLBACKS 16

//
// Checks to see if the supplied address is within the original (non-accessible)
// region
//
#define IsInsideRegion(MM, A) \
	(((A) >= (MM)->Region.BaseAddress.Ul) && \
	 ((A)  < (MM)->Region.EndAddress.Ul))

//
// A simple union that describes an address
//
typedef union _ADDRESS
{
	PVOID     Pv;
	ULONG_PTR Ul;
} ADDRESS, *PADDRESS;

//
// An address region
//
typedef struct _REGION
{
	ADDRESS BaseAddress;
	ADDRESS EndAddress;
	SIZE_T  Length;
} REGION, *PREGION;

//
// Structure used to represent the monitor control dword that is stored in TLS.
//
typedef union _MIRROR_CONTROL
{
	struct
	{
		ULONG RestoreRegister : 1;
		ULONG RegisterName    : 4;
		ULONG Reserved        : 27;
	};
	ULONG Ul;
} MIRROR_CONTROL, *PMIRROR_CONTROL;

//
// Memory monitor context flags
//
typedef union _MIRROR_FLAGS
{
	struct
	{
		ULONG DisableRestore     : 1;
		ULONG DisableAutogrowWss : 1;
		ULONG Reserved           : 30;
	};
	ULONG Ul;
} MIRROR_FLAGS, *PMIRROR_FLAGS;

//
// Callback context, containing an opaque pointer and a callback function.
//
typedef struct _MEMORY_MONITOR_CALLBACK_CONTEXT
{
	PVOID                   Context;
	MEMORY_MONITOR_CALLBACK Callback;
} MEMORY_MONITOR_CALLBACK_CONTEXT, *PMEMORY_MONITOR_CALLBACK_CONTEXT;

struct _MEMORY_MONITOR_CONTEXT;

//
// A monitor engine is responsible for providing an implementation for handling
// trapped memory references
//
typedef struct _MEMORY_MONITOR_ENGINE
{
	//
	// Initializes the engine for operation
	//
	BOOL (*Initialize)(
			__in struct _MEMORY_MONITOR_CONTEXT *MonitorContext);

	//
	// Allows the engine to perform any cleanup it needs
	//
	VOID (*Cleanup)(
			__in struct _MEMORY_MONITOR_CONTEXT *MonitorContext);

	//
	// Start monitoring the region
	//
	BOOL (*Start)(
			__in struct _MEMORY_MONITOR_CONTEXT *MonitorContext);

	//
	// Stop monitoring the region
	//
	VOID (*Stop)(
			__in struct _MEMORY_MONITOR_CONTEXT *MonitorContext);

	//
	// Initializes the calling thread to be monitored by the engine as necessary
	//
	BOOL (*InitializeThread)(
			__in struct _MEMORY_MONITOR_CONTEXT *MonitorContext);

	//
	// Resolves an access violation that occurred because the fault address was
	// within the region that we're monitoring
	//
	BOOL (*ResolveAV)(
			__in struct _MEMORY_MONITOR_CONTEXT *MonitorContext,
			__in ULONG_PTR FaultAddress,
			__in PEXCEPTION_RECORD ExceptionRecord,
			__in PCONTEXT ContextRecord,
			__inout PMEMORY_ACCESS Access);

	//
	// Resolves an access violation that occurred because the fault address was
	// outside of the region that we're monitoring
	//
	BOOL (*ResolveExternalAV)(
			__in struct _MEMORY_MONITOR_CONTEXT *MonitorContext,
			__in ULONG_PTR FaultAddress,
			__in PEXCEPTION_RECORD ExceptionRecord,
			__in PCONTEXT ContextRecord);

	//
	// Resolves a single step exception that occurred because of some action the
	// engine previously took
	//
	BOOL (*ResolveSingleStep)(
			__in struct _MEMORY_MONITOR_CONTEXT *MonitorContext,
			__in PCONTEXT ContextRecord);

} MEMORY_MONITOR_ENGINE, *PMEMORY_MONITOR_ENGINE;

//
// Engine-specific contextual information
//
typedef union _MEMORY_MONITOR_ENGINE_CONTEXT
{
	//
	// page mirror specific engine context information
	//
	struct
	{
		//
		// The user-mode accessible region that mirrors the region being
		// monitored.
		//
		REGION    Mirrored;

		//
		// The displacement between the original base address and the monitored base
		// address.
		//
		ULONG_PTR Displacement;

	} PageMirror;

	//
	// segment specific engine context information
	//
	struct
	{
		//
		// Set to TRUE if stacks should also be monitored.  This is controlled by
		// the MEMORY_MONITOR_FLAG_SEGMENT_STACKS flag.
		//
		ULONG MonitorStacks : 1;

	} Segment;

} MEMORY_MONITOR_ENGINE_CONTEXT, *PMEMORY_MONITOR_ENGINE_CONTEXT;

//
// Context structure for an individual memory monitor.
//
typedef struct _MEMORY_MONITOR_CONTEXT
{
	//
	// Linked list entry
	//
	LIST_ENTRY                      ListEntry;

	//
	// Context-specific lock
	//
	CRITICAL_SECTION                Lock;

	//
	// Flags that control the behavior of the monitor
	//
	MIRROR_FLAGS                    Flags;

	//
	// Current monitor context reference count
	//
	LONG                            References;

	//
	// The region that is being monitored
	//
	REGION                          Region;

	//
	// The underlying engine that should be used to monitor this region
	//
	MEMORY_MONITOR_ENGINE           Engine;

	//
	// Engine-specific storage
	//
	MEMORY_MONITOR_ENGINE_CONTEXT   EngineContext;

	//
	// Array of callbacks to notify upon memory access
	//
	MEMORY_MONITOR_CALLBACK_CONTEXT Callbacks[MAX_MEMORY_MONITOR_CALLBACKS];

	//
	// The number of registered callbacks
	//
	ULONG                           NumberOfCallbacks;

} MEMORY_MONITOR_CONTEXT, *PMEMORY_MONITOR_CONTEXT;

BOOL IsHandlingException();
BOOL InitializeMemoryMonitor();
BOOL NotifyMonitorInitializeThread();

VOID SetTlsControl(
		PVOID Value);
VOID SetTlsRestore(
		PVOID Value);
VOID SetTlsMonitor(
		PMEMORY_MONITOR_CONTEXT MonitorContext);

#define SetTlsTriple(__Control, __Restore, __Monitor) \
	SetTlsControl((PVOID)__Control); \
	SetTlsRestore((PVOID)__Restore); \
	SetTlsMonitor(__Monitor)

PVOID GetTlsControl();
PVOID GetTlsRestore();
PMEMORY_MONITOR_CONTEXT GetTlsMonitor();

#endif
