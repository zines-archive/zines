//
// This driver implements the kernel-mode code that facilitates mirroring of
// address references in user-mode.  This driver exposes a device object that
// allows processes to clear and set the Owner bit in the PTEs associated with a
// range of a region.  This makes it possible for exceptions to be generated and
// then handled in user-mode when a reference to a specific page occurs.
//
// Be aware that a potential security issue exists if you boot with /3GB or are
// on 64-bit at this point.  A malicious process could modify the PTE attributes
// associated with SharedUserData causing all processes to crash (DoS).  I'll
// address this shortly.
//
// This driver needs more work to get the PTE modifications working on all 
// operating systems.
//
// skape
// mmiller@hick.org
// 04/2007
//
#include <ntddk.h>
#include "..\common\common.h"

//
// Debugging stuff.
//
#define DRIVER         "mirror: "
#define ALLOC_TAG      'rrim'
#define DebugPrint(x)  \
	KdPrint((DRIVER));  \
	KdPrint(x);         \
	KdPrint(("\n"))

//
// The device name.
//
#define NT_DEV_NAME  L"\\Device\\MemoryMirror"
#define DOS_DEV_NAME L"\\??\\MemoryMirror"

//
// PTE modification -- this should be right, but it doesn't work on XPSP2 at the
// moment.
//
//#define GetPteAddress(Va) &((PMMPTE_HARDWARE)(0xc0000000))[(((ULONG_PTR)Va) >> 12)]

//
// This works on Vista...need to figure out why shift is 11.
//
#define GetPteAddress(Va) &((PMMPTE_HARDWARE)(0xc0000000))[(((ULONG_PTR)Va) >> 11)]

#define ClearPteOwnerBit(Pte) \
	Pte->Owner = FALSE, Pte->Accessed = TRUE
#define SetPteOwnerBit(Pte) \
	Pte->Owner = TRUE, Pte->Accessed = TRUE

typedef struct _MMPTE_HARDWARE
{
	ULONG Present      : 1;    // 0x00000001
	ULONG Write        : 1;    // 0x00000002
	ULONG Owner        : 1;    // 0x00000004
	ULONG WriteThrough : 1;    // 0x00000008
	ULONG CacheDisable : 1;    // 0x00000010
	ULONG Accessed     : 1;    // 0x00000020
	ULONG Dirty        : 1;    // 0x00000040
	ULONG LargePage    : 1;    // 0x00000080
	ULONG Global       : 1;    // 0x00000100
	ULONG CopyOnWrite  : 1;    // 0x00000200
	ULONG Prototype    : 1;    // 0x00000400
	ULONG Reserved     : 1;    // 0x00000800
	ULONG Pfn          : 20;
} MMPTE_HARDWARE, *PMMPTE_HARDWARE;

//
// The file descriptor mapping device object.
//
static PDEVICE_OBJECT MirrorDeviceObject = NULL;

//
// Handle device open requests so that the extension can be initialized and
// prepared.
//
NTSTATUS MirrorCreate(
		IN PDEVICE_OBJECT DeviceObject,
		IN PIRP Irp)
{
	Irp->IoStatus.Status      = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(
			Irp,
			IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

//
// Handle device close so that we can get all cleaned up.
//
NTSTATUS MirrorClose(
		IN PDEVICE_OBJECT DeviceObject,
		IN PIRP Irp)
{
	Irp->IoStatus.Status      = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(
			Irp,
			IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS MirrorDeviceControl(
		IN PDEVICE_OBJECT DeviceObject,
		IN PIRP Irp)
{
	PIO_STACK_LOCATION Stack;
	BOOLEAN            ClearOwner = FALSE;
	NTSTATUS           Status;
	PVOID              InBuffer;
	PVOID              OutBuffer;
	ULONG              InBufferLength;
	ULONG              OutBufferLength;
	ULONG              IoControl;
	PMDL               Mdl = NULL;

	//
	// Initialize information to zero
	//
	Irp->IoStatus.Information = 0;

	Stack = IoGetCurrentIrpStackLocation(Irp);

	//
	// If the major function for the calling IRP is not DeviceControl, simply
	// return status success.
	//
	if (Stack->MajorFunction != IRP_MJ_DEVICE_CONTROL)
	{
		Irp->IoStatus.Status      = STATUS_SUCCESS;
		Irp->IoStatus.Information = 0;

		IoCompleteRequest(Irp, IO_NO_INCREMENT);

		return STATUS_SUCCESS;
	}
	
	//
	// Grab shorter pointers to work with
	//
	InBuffer        = Stack->Parameters.DeviceIoControl.Type3InputBuffer;
	OutBuffer       = Irp->UserBuffer;
	InBufferLength  = Stack->Parameters.DeviceIoControl.InputBufferLength;
	OutBufferLength = Stack->Parameters.DeviceIoControl.OutputBufferLength;
	IoControl       = Stack->Parameters.DeviceIoControl.IoControlCode;

	switch (IoControl)
	{
		//
		// Create a dupliate mapping of the supplied region in the calling
		// process.  This duplicate mapping
		//
		case IOCTL_MIRROR_CREATE_MIRROR:
			do
			{
				ULONG_PTR BaseAddress = (ULONG_PTR)InBuffer;
				PVOID     MappingAddress = NULL;
				ULONG     Length = InBufferLength;

				if (OutBufferLength < sizeof(ULONG_PTR))
				{
					Status = STATUS_INVALID_PARAMETER;
					break;
				}

				//
				// These values must be page-aligned
				//
				if ((BaseAddress & 0xfff) ||
				    (Length & 0xfff))
				{
					Status = STATUS_MAPPED_ALIGNMENT;
					break;
				}

				try
				{
					//
					// Probe the address region, making sure that it's a valid user-mode
					// mapping.
					//
					ProbeForRead(
							(PVOID)BaseAddress,
							Length,
							1);

					ProbeForWrite(
							(PVOID)OutBuffer,
							OutBufferLength,
							1);

					//
					// Allocate an MDL to describe this region
					//
					Mdl = IoAllocateMdl(
							(PVOID)BaseAddress,
							Length,
							FALSE,
							TRUE,
							NULL);

					//
					// Probe & lock
					//
					MmProbeAndLockPages(
							Mdl,
							UserMode,
							IoModifyAccess);

					//
					// Finally, we map the locked pages into the user-mode process at
					// a different base address.
					//
					MappingAddress = MmMapLockedPages(
							Mdl,
							UserMode);

					DebugPrint(("CREATE: Mapped region %p to %p.",
							BaseAddress,
							MappingAddress));

					//
					// If we get here, then we've succeeded.  Set the output buffer
					// to the mapping address and return.
					//
					*(PULONG_PTR)OutBuffer = (ULONG_PTR)MappingAddress;

					//
					// FIXME: This isn't entirely safe.
					//
					MmUnlockPages(
							Mdl);

					//
					// Success!
					//
					Status = STATUS_SUCCESS;

				} except(EXCEPTION_EXECUTE_HANDLER)
				{
					Status = GetExceptionCode();
					
					DebugPrint(("CREATE: Exception caught: %.8x.", Status));
					break;
				}

			} while (0);

			if (Mdl)
				IoFreeMdl(Mdl);
			break;
		//
		// Toggle the supervisor bit on each of the PTEs associated with the
		// supplied region.
		//
		case IOCTL_MIRROR_START_MIRROR:
			ClearOwner = TRUE;
			__fallthrough;

		//
		// Restore the supervisor bit on each of the PTEs associated with the
		// supplied region.
		//
		case IOCTL_MIRROR_STOP_MIRROR:
			do
			{
				ULONG_PTR BaseAddress = (ULONG_PTR)InBuffer;
				ULONG_PTR EndAddress = BaseAddress + InBufferLength;
				ULONG_PTR CurrentAddress;
				PVOID     MappingAddress = NULL;
				ULONG     Length = InBufferLength;

				//
				// These values must be page-aligned
				//
				if ((BaseAddress & 0xfff) ||
				    (Length & 0xfff) ||
				    (EndAddress <= BaseAddress))
				{
					Status = STATUS_MAPPED_ALIGNMENT;
					break;
				}

				try
				{
					//
					// Sanity check
					//
					ProbeForRead(
							(PVOID)BaseAddress,
							Length,
							1);

					DebugPrint(("STARTSTOP: BaseAddress=%p Length=%.8x.",
							BaseAddress, Length));

					//
					// Walk through each page, setting or clearing the supervisor bit
					// on the respective PTEs
					//
					for (CurrentAddress = BaseAddress;
					     CurrentAddress < EndAddress;
					     CurrentAddress += PAGE_SIZE)
					{
						PMMPTE_HARDWARE Pte = GetPteAddress(CurrentAddress);

						DebugPrint(("STARTSTOP: Toggling Owner on PTE=%p for Address=%p.",
								Pte, CurrentAddress));

						if (Pte->Present)
						{
							if (ClearOwner)
							{
								ClearPteOwnerBit(Pte);
							}
							else
							{
								SetPteOwnerBit(Pte);
							}
						}
						else
						{
							DebugPrint(("STARTSTOP: %p isn't present (PTE=%p, *PTE=%p).", CurrentAddress, Pte, *(PULONG)Pte));
							DbgBreakPoint();
						}
					}

					DebugPrint(("STARTSTOP: Completed %s the owner bit on region %p.",
							(ClearOwner) ? "clearing" : "setting",
							BaseAddress));

					//
					// Victory!
					//
					Status = STATUS_SUCCESS;

				} except(EXCEPTION_EXECUTE_HANDLER)
				{
					Status = GetExceptionCode();
					
					DebugPrint(("STARTSTOP: Exception caught: %.8x.", Status));
					break;
				}

			} while (0);
			break;

		default:
			Status = STATUS_INVALID_PARAMETER;
			break;
	}

	//
	// Complete the IRP
	//
	Irp->IoStatus.Status = Status;

	IoCompleteRequest(
			Irp,
			IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

//
// Unload the driver object associated with the fdmap streams.
//
VOID MirrorUnload(
		IN PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING DosName;

	//
	// Delete the symbolic device name.
	//
	RtlInitUnicodeString(
			&DosName,
			DOS_DEV_NAME);

	IoDeleteSymbolicLink(
			&DosName);

	//
	// Delete the device itself.
	//
	IoDeleteDevice(
			MirrorDeviceObject);
}

#pragma code_seg("INIT")

NTSTATUS DriverEntry(
		IN PDRIVER_OBJECT DriverObject,
		IN PUNICODE_STRING RegistryPath)
{
	UNICODE_STRING NtName;
	UNICODE_STRING DosName;
	NTSTATUS       Status = STATUS_SUCCESS;

	//
	// Initialize the name of the device we're about to create and link.
	//
	RtlInitUnicodeString(
			&NtName,
			NT_DEV_NAME);

	RtlInitUnicodeString(
			&DosName,
			DOS_DEV_NAME);

	do
	{
		//
		// Create the device that will be opened for reading/writing.
		//
		if (!NT_SUCCESS(Status = IoCreateDevice(
				DriverObject,
				0,
				&NtName,
				FILE_DEVICE_UNKNOWN,
				0,
				FALSE,
				&MirrorDeviceObject)))
		{
			DebugPrint(("DriverEntry(): IoCreateDevice failed, %.8x.",
					Status));
			break;
		}

		//
		// Initialize the specific dispatch entries that we'll handle, such as
		// open, read, and write.
		//
		DriverObject->MajorFunction[IRP_MJ_CREATE]         = MirrorCreate;
		DriverObject->MajorFunction[IRP_MJ_CLOSE]          = MirrorClose;
		DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = MirrorDeviceControl;
		DriverObject->DriverUnload                         = MirrorUnload;

		//
		// Create a DosDevices alias for the device name.
		//
		if (!NT_SUCCESS(Status = IoCreateSymbolicLink(
				&DosName,
				&NtName)))
		{
			DebugPrint(("DriverEntry(): IoCreateSymbolicLink failed, %.8x.",
					Status));
			break;
		}

		//
		// We're ready to go.
		//
		MirrorDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

		DebugPrint(("DriverEntry(): Mirror driver started."));

	} while (0);

	//
	// If we fail to succeed, clean up the device object.
	//
	if (!NT_SUCCESS(Status))
	{
		if (MirrorDeviceObject)
			IoDeleteDevice(
					MirrorDeviceObject);
	}

	return Status;
}

#pragma code_seg()
