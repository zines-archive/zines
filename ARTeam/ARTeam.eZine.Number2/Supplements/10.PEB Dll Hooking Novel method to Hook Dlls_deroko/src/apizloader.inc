getkernelbase:
                     pushad
                     xor           edx, edx
                     mov           esi, dword ptr FS:[edx]
__seh:               lodsd
                     cmp           eax, 0FFFFFFFFh
                     je            __kernel
                     mov           esi, eax
                     jmp           __seh  
__kernel:            mov           edi, dword ptr[esi + 4]          
                     and           edi, 0FFFF0000h     
__spin:              cmp           word ptr[edi], 'ZM'      
                     jz            __test_pe
                     sub           edi, 10000h
                     jmp           __spin  
__test_pe:           mov           ebx, edi
                     add           ebx, [ebx.MZ_lfanew]
                     cmp           word ptr[ebx],'EP'
                     je            __exit_k32
                     sub           edi, 10000h
                     jmp           __spin   
__exit_k32:          mov           [esp.Pushad_eax], edi
                     popad
                     ret

getprocaddress:
                     pushad                   
                     mov           ebx, dword ptr[esp+8*4+4]
                     mov           ecx, ebx
                     add           ebx, [ebx.MZ_lfanew]			
                     mov           ebx, [ebx.NT_OptionalHeader.OH_DirectoryEntries.DE_Export.DD_VirtualAddress]
                     add           ebx, ecx
                     mov           edi, [ebx.ED_AddressOfNames]
                     add           edi, ecx
                     xor           esi, esi                           ;esi counter                  				
__find_api:          lea           edx, dword ptr[edi+esi*4]
                     mov           edx, dword ptr[edx]			
                     add           edx, ecx				
                     xor           eax, eax				
__1:                 rol           eax, 7					;hash algo  (x) by z0mbie
                     xor           al, byte ptr [edx]
                     inc           edx					
                     cmp           byte ptr [edx], 0			
                     jnz           __1					
                     cmp           eax, dword ptr[esp+8+8*4]             	       
                     je            __find_ordinal				    
                     inc           esi					
                     cmp           esi, [ebx.ED_NumberOfNames]		
                     jb            __find_api                    
__find_ordinal:      mov           edx, [ebx.ED_AddressOfOrdinals]	
                     add           edx, ecx				
                     movzx         edx, word ptr [edx+esi*2]		
                     mov           eax, [ebx.ED_AddressOfFunctions]	
                     add           eax, ecx				
                     mov           eax, [eax+edx*4]			
                     add           eax, ecx
                     mov           [esp.Pushad_eax], eax
                     popad				
__end:	       	     ret           8 