//
// Memalyze: runtime memory access interception
//
// Pre-compiled header file
//
// skape
// mmiller@hick.org
// 04/2007
//
#ifndef _MEMALYZE_DLL_PRECOMP_H
#define _MEMALYZE_DLL_PRECOMP_H

#include <windows.h>
#include <winioctl.h>
#include <assert.h>
#include <specstrings.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE 0x1000
#endif

#if DBG
#define DebugPrint(x)                       \
	DbgPrint("memalyze[%lu.%lu]: ",          \
			GetCurrentProcessId(),             \
			GetCurrentThreadId());             \
	DbgPrint x;                              \
	DbgPrint("\n")


#define DebugBreakPoint() __asm int 3
#else
#define DebugPrint(x)
#define DebugBreakPoint()
#endif

#include "..\..\common\memalyze.h"
#include "ntapi.h"
#include "libdasm.h"
#include "alloc.h"
#include "monitor.h"

#endif
