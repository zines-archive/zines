//
// Memalyze: runtime memory access interception 
//
// Manages creation and interaction with the private heap used by memalyze.
//
// skape
// mmiller@hick.org
// 04/2007
//
#ifndef _MEMALYZE_DLL_ALLOC_H
#define _MEMALYZE_DLL_ALLOC_H

BOOL InitializePrivateHeap();

#define SafeFreeMemory(P) \
	FreeMemory(P), P = NULL

#endif
