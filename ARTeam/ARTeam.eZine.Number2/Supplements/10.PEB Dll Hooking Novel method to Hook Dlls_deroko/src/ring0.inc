io_status_block struct
        iob_status              dd      ?
        iob_information         dd      ?
io_status_block ends


object_attributes       struct
       oa_length        dd     ?      ;len of struct
       oa_rootdir       dd     ?      ;Handle to root dir 
       oa_objectname    dd     ?      ;pointer to UNICODE_STRING
       oa_attributes    dd     ?      ;heh not sure how to explain
       oa_securitydesc  dd     ?      ;Set to null for default SecurityDescriptor
       oa_secqualityofs dd     ?      ;Set to 0 InitializeObjectAttributes so it is 0 always
object_attributes       ends

unicode_string  struct
       us_len        dw   ?
       us_maxlen     dw   ?
       us_buff       dd   ?
unicode_string  ends


list_entry      struct
        le_flink                dd      ?
        le_blink                dd      ?
list_entry      ends

dispatcher_header       struct
        dth_type                db      ?
        dth_Absolute            db      ?
        dth_Size                db      ?
        dth_Inserted            db      ?
        dth_SignalState         dd      ?
        dth_WaitListHead        list_entry      ?
dispatcher_header       ends

system_module_information       struct
                smi_reserved    dd      2       dup(?)
                smi_base        dd      ?
                smi_size        dd      ?
                smi_flags       dd      ?
                smi_index       dw      ?
                smi_unknown     dw      ?
                smi_loadcount   dw      ?
                smi_modulenameoffset    dw      ?
                smi_imagename   db      256     dup(?)
system_module_information       ends

kservice_table_descriptor       struct
                ktd_base        dd       ?      ;base of table
                ktd_count       dd       ?      ;not used
                ktd_limit       dd       ?      ;number of entries
                ktd_argnum      dd       ?      ;pointer to array of arg num
kservice_table_descriptor       ends


kevent                  struct
        kevent_header   dispatcher_header       ?
kevent                  ends

mdl             struct
                mdl_next        dd      ?
                mdl_size        dw      ?
                mdl_mdlflags    dw      ?
                mdl_process     dd      ?       ;ptr to EPROCESS
                mdl_mappedsystemva      dd      ?
                mdl_startva     dd      ?
                mdl_bytecount   dd      ?
                mdl_byteoffset  dd      ?
mdl             ends

kdevice_queue_entry     struct
                kqe_DeviceListEntry     list_entry ?
                kqe_SortKey             dd      ?
                kqe_Inserted            db      ?
                                        db      3 dup(?)
kdevice_queue_entry     ends

kapc            struct
                kapc_type       dw      ?
                kapc_size       dw      ?
                kapc_Spare0     dd      ?
                kapc_thread     dd      ?
                kapc_ApcListEntry       list_entry ?
                kapc_KernelRoutine      dd      ?
                kapc_RundownRoutine     dd      ?
                kapc_NormalRoutine      dd      ?
                kapc_NormalContext      dd      ?
                kapc_SystemArgumment1   dd      ?
                kapc_SystemArgumment2   dd      ?
                kapc_ApcStateIndex      db      ?
                kapc_ApcMode            db      ?
                kapc_Inserted           db      ?
                                        db      ?
kapc            ends
            
tail            struct
                t_drivercontext         dd      4       dup(?)
                t_thread                dd      ?
                t_AuxiliaryBuffer       dd      ?
                t_ListEntry             list_entry      ?
                t_CurrentStackLocation  dd      ?       ;may be also PacketType
                t_OriginalFileObject    dd      ?
tail            ends    

;this struct is not complete, just args for DeviceIoControl->IoControlCode...
io_stack_location               struct
        isl_MajorFunction       db      ?
        isl_MinorFunction       db      ?
        isl_Flags               db      ?
        isl_Control             db      ?
        isl_OutputBufferLength  dd      ?
        isl_InputBufferLength   dd      ?
        isl_IoControlCode       dd      ?                
        isl_Type3InputBuffer    dd      ?
io_stack_location               ends

        
irp_struct     struct
        irp_type                dw      ?       ;+0
        irp_size                dw      ?       ;+2
        irp_MdlAddress          dd      ?       ;+4
        irp_flags               dd      ?       ;+8
        irp_systembuffer        dd      ?       ;+0c
        irp_ThreadListEntry     list_entry      ? ;+10h
        irp_iostatus            io_status_block ? ;+18h
        irp_RequestMode         db      ?       ;20h
        irp_PendingReturned     db      ?       ;21h
        irp_StackCount          db      ?       ;22h
        irp_CurrentLocation     db      ?       ;23h
        irp_cancel              db      ?
        irp_cancelIrql          db      ?
        irp_ApcEnvironment      db      ?
        irp_AllocationFlags     db      ?
        irp_UserIosb            dd      ?
        irp_UserEvent           dd      ?
        irp_AllocationSize      dq      ?               ;may be UserApcRoutine and UserApcContext (UNION)
        irp_CancelRountine      dd      ?
        irp_UserBuffer          dd      ?
        irp_tail                tail    ?
        irp_Apc                 kapc    ?
        irp_CompletionKey       dd      ?
irp_struct     ends

majorfunction           struct
                irp_mj_create                   dd      ?
                irp_mj_create_named_pipe        dd      ?
                irp_mj_close                    dd      ?
                irp_mj_read                     dd      ?
                irp_mj_write                    dd      ?
                irp_mj_query_information        dd      ?
                irp_mj_set_information          dd      ?
                irp_mj_query_ea                 dd      ?
                irp_mj_set_ea                   dd      ?
                irp_mj_flush_buffers            dd      ?
                irp_mj_query_volume_information dd      ?
                irp_mj_set_volume_information   dd      ?
                irp_mj_directory_control        dd      ?
                irp_mj_file_system_control      dd      ?
                irp_mj_device_control           dd      ?
                irp_mj_internal_device_control  dd      ?
                irp_mj_shutdown                 dd      ?
                irp_mj_lock_control             dd      ?
                irp_mj_cleanup                  dd      ?
                irp_mj_create_mailslot          dd      ?
                irp_mj_query_security           dd      ?
                irp_mj_set_security             dd      ?
                irp_mj_power                    dd      ?
                irp_mj_system_sontrol           dd      ?
                irp_mj_device_change            dd      ?
                irp_mj_query_quota              dd      ?
                irp_mj_set_quota                dd      ?
                irp_mj_pnp                      dd      ?
majorfunction           ends   
        
driver_object   struct
        dro_type                dw      ?
        dro_size                dw      ?
        dro_deviceobject        dd      ?
        dro_flags               dd      ?
        dro_driverstart         dd      ?
        dro_driverend           dd      ?
        dro_driversection       dd      ?
        dro_driverextension     dd      ?
        dro_drivername          unicode_string  ?
        dro_HardwareDatabse     dd      ?       ;ptr to UNICODE_STRING
        dro_FastIoDispatch      dd      ?
        dro_DriverInit          dd      ?
        dro_DriverStartIo       dd      ?
        dro_DriverUnload        dd      ?
                                UNION
        dro_MajorFunctionsNum   dd      1ch     dup (?) ; (IRP_MJ_MAXIMUM_FUNCTION + 1) dup(?) where 1b+1
        dro_majorfunctions       majorfunction   ?
                                ENDS
driver_object   ends        

driver_extension        struct
        de_DriverObject         dd      ?
        de_AddDevice            dd      ?
        de_Count                dd      ?
        de_ServiceKeyNum        unicode_string  ?
driver_extension        ends

file_object             struct
        fo_typeq                dw      ?
        fo_size                 dw      ?
        fo_deviceobject         dd      ?
        fo_Vpb                  dd      ?
        fo_FsContext            dd      ?
        fo_FsContext2           dd      ?
        fo_SectionObjectPointer dd      ?
        fo_PrivateCacheMap      dd      ?
        fo_FinalStatus          dd      ?
        fo_RelatedFileObject    dd      ?
        fo_LockOperation        db      ?
        fo_DeletePending        db      ?
        fo_ReadAccess           db      ?
        fo_WriteAccess          db      ?
        fo_DeleteAccess         db      ?
        fo_SharedRead           db      ?
        fo_SharedWrite          db      ?
        fo_SharedDelete         db      ?
        fo_flags                dd      ?
        fo_FileName             unicode_string  ?
        fo_CurrentByteOffset    dq      ?
        fo_Waiters              dd      ?
        fo_Busy                 dd      ?
        fo_LastLock             dd      ?
        fo_Lock                 kevent  ?
        fo_Event                kevent  ?
        fo_CompletionContext    dd      ?
file_object     ends

kgdtentry               struct
        kgdt_LimitLow            dw      ?
        kgdt_BaseLow             dw      ?
        kgdt_HighWord            dw      ?
                                dw      ?
kgdtentry               ends 

kidtentry              struct
        union
        kidt_offset             dw      ?
        kidt_lowword            dw      ?
        ends
        kidt_selector           dw      ?
        kidt_access             dw      ?
        union
        kidt_extendedoffset     dw      ?    
        kidt_highword           dw      ?
        ends
kidtentry               ends
kprocess                struct
        kp_header       dispatcher_header       ?
        kp_ProfileListHead      list_entry      ?
        kp_DirectoryTableBase   dd      2       dup(?)               ;array of 2
        kp_LdtDescriptor        kgdtentry       ?
        kp_Int21Descriptor      kidtentry       ?
        kp_IopmOffset           dw      ?
        kp_Iopl                 db      ?
        kp_Unused               db      ?
        kp_ActiveProcessor      dd      ?
        kp_KernelTime           dd      ?
        kp_UserTime             dd      ?
        kp_ReadyListHead        list_entry      ?
        kp_SwapListEntry        dd      ?
        kp_VdmTrapcHandler      dd      ?
        kp_ThreadListHead       list_entry      ?
        kp_ProcessLock          dd      ?
        kp_Affinity             dd      ?
        kp_StackCount           dw      ?
        kp_BasePriority         db      ?
        kp_ThreadQuantum        db      ?
        kp_AutoAlignment        db      ?
        kp_State                db      ?
        kp_ThreadSeed           db      ?
        kp_DisableBoost         db      ?
        kp_PowerState           db      ?
        kp_DisableQuantum       db      ?
        kp_IdealNode            db      ?
        union
        kp_Flags                db      ?
        kp_ExecuteOptions       db      ?
        ends
kprocess                ends


kapc_state              struct
        kapcs_ApcListHead1      list_entry      ?       ;0
        kapcs_ApcListHead2      list_entry      ?       ;8
        kapcs_Process           dd      ?       ;ptr to KPROCESS 10
        kapcs_KernelApcInProgress       db      ?                ;14
        kapcs_KernelApcPending  db      ?                        ;15
        kacps_UserApcPending    db      ?                        ;16
                                db      ?                        ;17
kapc_state              ends

fast_mutex              struct
        fm_Count        dd      ?
        fm_Owner        dd      ?       ;ptr to KTHREAD
        fm_Contention   dd      ?
        fm_Event        kevent  ?
        fm_OldIrql      dd      ?
fast_mutex              ends

mmsupport               struct
        mms_LastTrimTime        dq      ?
        mms_Flags               dd      ?
        mms_PageFaultCount      dd      ?
        mms_PeakWorkingSetSize  dd      ?
        mms_WorkingSetSize      dd      ?
        mms_MinimumWorkingSetSize       dd      ?
        mms_MaximumWorkingSetSize       dd      ?
        mms_VmWorkingSetList    dd      ?       ;ptr __MMWSL
        mms_WorkingSetExpansionLinks    list_entry      ?
        mms_Claim               dd      ?
        mms_NextEstimationSlot  dd      ?
        mms_NextAgindSlot       dd      ?
        mms_EstimatedAvailable  dd      ?
        mms_GrowthSinceLastEstimate     dd      ?
mmsupport               ends
        
eprocess_struct                 struct
        ep_pcb          kprocess        <>
        ep_ProcessLock  dd      ?
        ep_CreateTime   dq      ?
        ep_ExitTime     dq      ?
        ep_RundownProtect       dd      ?
        ep_UniqueProcessId      dd      ?
        ep_ActiveProcessLink    list_entry      ?
        ep_QuotaUsage           dd      3       dup(?)
        ep_QuotaPeak            dd      3       dup(?)
        ep_CommitCharge         dd      ?
        ep_PeakVirtualSize      dd      ?
        ep_VirtualSize          dd      ?
        ep_SessionProcessLinks  list_entry      ?
        ep_DebugPort            dd      ?
        ep_ExceptionPort        dd      ?
        ep_ObjectTable          dd      ?       ;ptr to _HANDLE_TABLE
        ep_Token                dd      ?
        ep_WorkingSetLock       fast_mutex      ?
        ep_WorkingSetPage       dd      ?
        ep_AddressCreationLock  fast_mutex      ?
        ep_HyperSpaceLock       dd      ?
        ep_ForkInProgress       dd      ?       ;ptr to ETHREAD
        ep_HardwareTrigger      dd      ?
        ep_VadRoot              dd      ?
        ep_VadHint              dd      ?
        ep_CloneRoot            dd      ?
        ep_NumberOfPrivatePages dd      ?
        ep_NumberOfLockedPages  dd      ?
        ep_Win32Process         dd      ?
        ep_Job                  dd      ?       ;ptr to EJOB
        ep_SectionObject        dd      ?
        ep_SectionBaseAddress   dd      ?
        ep_QuotaBlock           dd      ?       ;ptr EProceSS_QUOTA_BLOCK
        ep_WorkingSetWatch      dd      ?       ;ptr PAGEFAULT_HISTORY
        ep_Win32WindowStation   dd      ?
        ep_InheritedFromUniqueProcessId dd      ?
        ep_LdtInformation       dd      ?
        ep_VadFreeHint          dd      ?
        ep_VdmObjects           dd      ?
        ep_DeviceMap            dd      ?
        ep_PhysicalVadList      list_entry      ?
        union
        ep_PageDirectoryPte     dd      ?
        ep_Filter               dq      ?
        ends
        ep_Session              dd      ?
        ep_ImageFileName        db      16      dup(?)
        ep_JobLinks             list_entry      ?
        ep_LockedPageList       dd      ?
        ep_ThreadListHead       list_entry      ?
        ep_SecurityPort         dd      ?
        ep_PaeTop               dd      ?
        ep_ActiveThreads        dd      ?
        ep_GrantedAccess        dd      ?
        ep_DefaultHardErrorProcessing   dd      ?
        ep_LastThreadExitStatus dd      ?
        ep_peb                  dd      ? ;ptr to _PEB
        ep_PrefetchTrace        dd      ?
        ep_ReadOperationCount   dq      ?
        ep_WriteOperationCount  dq      ?
        ep_ReadTransferCount    dq      ?
        ep_WriteTransferCount   dq      ?
        ep_OtherTransferCount   dq      ?
        ep_CommitChargeLimit    dd      ?
        ep_CommitChargePeak     dd      ?
        ep_AweInfo              dd      ?
        ep_SeAuditProcessCreationInfo   dd      ?
        ep_Vm                   mmsupport       ?
        ep_LastFaultCount       dd      ?
        ep_ModifiedPageCount    dd      ?
        ep_NumberOfVads         dd      ?
        ep_JobStatus            dd      ?
        ep_Flags                dd      ?
        ep_ExitStatus           dd      ?
        ep_NextPageColor        dw      ?
        ep_SubSystemMinorVersion        db      ?
        ep_SubSystemMajorVersion        db      ?
        ep_SubSystemVersion     dw      ?
        ep_PriorityClass        db      ?
        ep_WorkingSetAcquiredUnsafe     db      ?
        ep_Cookie               dd      ?
eprocess_struct                ends

object_name     struct
        obname_directory        dd      ?
        obname_name             unicode_string  ?
        obname_reserved         dd      ?
object_name     ends

object_header   struct
        ob_PointerCount         dd      ?       ;+00
        ob_HandleCount          dd      ?       ;+04
        ob_type                 dd      ?       ;+08
        union
        ob_NameInfoOffet        db      ?       ;+0C
        ob_nameoffset           db      ?
        ob_objectname           db      ?
        ends
        
        ob_HandleInfoOffset     db      ?       ;+0D
        ob_QuotaInfoOffset      db      ?       ;+0E
        ob_flags                db      ?       ;+0F
        union
        ob_ObjectCreateInfo     dd      ?       ;+10
        ob_QuotaBlockCharged    dd      ?
        ends
        ob_SecurityDescriptor   dd      ?       ;+14
        ob_Body                 dd      ?       ;only references to object body
object_header   ends                            


ldr_module                      struct
        lm_inloadordermodulelist        list_entry      ?
        lm_inmemoryordermodulelist      list_entry      ?
        lm_ininitializationordermodulelist list_entry   ?
        lm_baseaddress          dd      ?
        lm_entrypoint           dd      ?
        lm_sizeofimage          dd      ?
        lm_fulldllname          unicode_string  ?
        lm_basedllname          unicode_string  ?
        lm_flags                dd      ?
        lm_loadcount            dw      ?
        lm_tlsindex             dw      ?
        lm_hashtableentry       list_entry      ?
        union
        lm_timedatastamp        dd      ?
        lm_loadedimports        dd      ?
        ends
        lm_entrypointactivationcontext  dd      ?
        lm_patchinformation     dd      ?
ldr_module                      ends        
;this two structs are used with initint and restoreint macros
;to access regs saved on stack w/o many effort in int hooking
pushad_int_struct               struct
                                int_es          dd      ?
                                int_ds          dd      ?
                                int_fs          dd      ?
                                int_edi         dd      ?
                                int_esi         dd      ?
                                int_ebp         dd      ?
                                int_esp         dd      ?
                                int_ebx         dd      ?
                                int_edx         dd      ?
                                int_ecx         dd      ?
                                int_eax         dd      ?
                                int_eip         dd      ?
                                int_cs          dd      ?
                                int_eflags      dd      ?
                                int_espr3       dd      ?
                                int_ss          dd      ?
pushad_int_struct               ends

pushad_int1_struct              struct
                                inte_es          dd      ?
                                inte_ds          dd      ?
                                inte_fs          dd      ?                                
                                inte_edi         dd      ?
                                inte_esi         dd      ?
                                inte_ebp         dd      ?
                                inte_esp         dd      ?
                                inte_ebx         dd      ?
                                inte_edx         dd      ?
                                inte_ecx         dd      ?
                                inte_eax         dd      ?
                                inte_errorcode   dd      ?
                                inte_eip         dd      ?
                                inte_cs          dd      ?
                                inte_eflags      dd      ?
pushad_int1_struct              ends

;this 2 macros are prepared to be used with pushad_int and pushad_int1 struct
initint                         macro
                                pushad
                                push    fs
                                push    ds
                                push    es
                                mov     eax, 30h
                                mov     fs, ax
                                mov     eax, 23h
                                mov     ds, ax
                                mov     es, ax
                                endm

restoreint                      macro
                                pop     es
                                pop     ds
                                pop     fs
                                popad
                                endm

init_ring0_seh                  macro   _xxx
                                local   __handle
                                call    __handle
                                mov     ecx, [esp+0ch]
                                mov     [ecx.context_eip], offset _xxx
                                push    dword ptr[esp+8]
                                pop     [ecx.context_esp]
                                xor     eax, eax
                                ret
__handle:                       push    dword ptr fs:[0]
                                mov     dword ptr fs:[0], esp
                                endm
                                
remove_ring0_seh                macro
                                pop     dword ptr fs:[0]                                
                                add     esp, 4
                                endm
                                
IRP_MJ_CREATE                   equ 0
IRP_MJ_CREATE_NAMED_PIPE        equ 1
IRP_MJ_CLOSE                    equ 2
IRP_MJ_READ                     equ 3
IRP_MJ_WRITE                    equ 4
IRP_MJ_QUERY_INFORMATION        equ 5
IRP_MJ_SET_INFORMATION          equ 6
IRP_MJ_QUERY_EA                 equ 7
IRP_MJ_SET_EA                   equ 8
IRP_MJ_FLUSH_BUFFERS            equ 9
IRP_MJ_QUERY_VOLUME_INFORMATION equ 0Ah
IRP_MJ_SET_VOLUME_INFORMATION   equ 0Bh
IRP_MJ_DIRECTORY_CONTROL        equ 0Ch
IRP_MJ_FILE_SYSTEM_CONTROL      equ 0Dh
IRP_MJ_DEVICE_CONTROL           equ 0Eh
IRP_MJ_INTERNAL_DEVICE_CONTROL  equ 0Fh
IRP_MJ_SHUTDOWN                 equ 10h
IRP_MJ_LOCK_CONTROL             equ 11h
IRP_MJ_CLEANUP                  equ 12h
IRP_MJ_CREATE_MAILSLOT          equ 13h
IRP_MJ_QUERY_SECURITY           equ 14h
IRP_MJ_SET_SECURITY             equ 15h
IRP_MJ_POWER                    equ 16h
IRP_MJ_SYSTEM_CONTROL           equ 17h
IRP_MJ_DEVICE_CHANGE            equ 18h
IRP_MJ_QUERY_QUOTA              equ 19h
IRP_MJ_SET_QUOTA                equ 1Ah
IRP_MJ_PNP                      equ 1Bh
IRP_MJ_PNP_POWER                equ IRP_MJ_PNP	; Obsolete....
IRP_MJ_MAXIMUM_FUNCTION         equ 1Bh

;typedef enum _POOL_TYPE {
NonPagedPool                            equ     0
PagedPool                               equ     1
NonPagedPoolMustSucceed                 equ     2
DontUseThisType                         equ     3
NonPagedPoolCacheAligned                equ     4
PagedPoolCacheAligned                   equ     5
NonPagedPoolCacheAlignedMustS           equ     6
MaxPoolType                             equ     7
NonPagedPoolSession                     equ     32
PagedPoolSession                        equ     33
NonPagedPoolMustSucceedSession          equ     34
DontUseThisTypeSession                  equ     35
NonPagedPoolCacheAlignedSession         equ     36
PagedPoolCacheAlignedSession            equ     37
NonPagedPoolCacheAlignedMustSSession    equ     38
    
KernelMode                              equ     0
UserMode                                equ     1
MaximumMode                             equ     2

PASSIVE_LEVEL                           equ     0                       ; Passive release level
LOW_LEVEL                               equ     0                       ; Lowest interrupt level
APC_LEVEL                               equ     1                       ; APC interrupt level
DISPATCH_LEVEL                          equ     2                       ; Dispatcher level

PROFILE_LEVEL                           equ     27                      ; timer used for profiling.
CLOCK1_LEVEL                            equ     28                      ; Interval clock 1 level - Not used on x86
CLOCK2_LEVEL                            equ     28                      ; Interval clock 2 level
IPI_LEVEL                               equ     29                      ; Interprocessor interrupt level
POWER_LEVEL                             equ     30                      ; Power failure level
HIGH_LEVEL                              equ     31                      ; Highest interrupt level
SYNCH_LEVEL                             equ     IPI_LEVEL-1             ; synchronization level

FILE_DEVICE_BEEP                equ 01
FILE_DEVICE_CD_ROM              equ 02
FILE_DEVICE_CD_ROM_FILE_SYSTEM  equ 03
FILE_DEVICE_CONTROLLER          equ 04
FILE_DEVICE_DATALINK            equ 05
FILE_DEVICE_DFS                 equ 06
FILE_DEVICE_DISK                equ 07
FILE_DEVICE_DISK_FILE_SYSTEM    equ 08
FILE_DEVICE_FILE_SYSTEM         equ 09
FILE_DEVICE_INPORT_PORT         equ 0ah
FILE_DEVICE_KEYBOARD            equ 0bh
FILE_DEVICE_MAILSLOT            equ 0ch
FILE_DEVICE_MIDI_IN             equ 0dh
FILE_DEVICE_MIDI_OUT            equ 0eh
FILE_DEVICE_MOUSE               equ 0fh
FILE_DEVICE_MULTI_UNC_PROVIDER  equ 10h
FILE_DEVICE_NAMED_PIPE          equ 11h
FILE_DEVICE_NETWORK             equ 12h
FILE_DEVICE_NETWORK_BROWSER     equ 13h
FILE_DEVICE_NETWORK_FILE_SYSTEM equ 14h
FILE_DEVICE_NULL                equ 15h
FILE_DEVICE_PARALLEL_PORT       equ 16h
FILE_DEVICE_PHYSICAL_NETCARD    equ 17h
FILE_DEVICE_PRINTER             equ 18h
FILE_DEVICE_SCANNER             equ 19h
FILE_DEVICE_SERIAL_MOUSE_PORT   equ 1ah
FILE_DEVICE_SERIAL_PORT         equ 1bh
FILE_DEVICE_SCREEN              equ 1ch
FILE_DEVICE_SOUND               equ 1dh
FILE_DEVICE_STREAMS             equ 1eh
FILE_DEVICE_TAPE                equ 1fh
FILE_DEVICE_TAPE_FILE_SYSTEM    equ 20h
FILE_DEVICE_TRANSPORT           equ 21h
FILE_DEVICE_UNKNOWN             equ 22h
FILE_DEVICE_VIDEO               equ 23h
FILE_DEVICE_VIRTUAL_DISK        equ 24h
FILE_DEVICE_WAVE_IN             equ 25h
FILE_DEVICE_WAVE_OUT            equ 26h
FILE_DEVICE_8042_PORT           equ 27h
FILE_DEVICE_NETWORK_REDIRECTOR  equ 28h
FILE_DEVICE_BATTERY             equ 29h
FILE_DEVICE_BUS_EXTENDER        equ 2ah
FILE_DEVICE_MODEM               equ 2bh
FILE_DEVICE_VDM                 equ 2ch
FILE_DEVICE_MASS_STORAGE        equ 2dh
FILE_DEVICE_SMB                 equ 2eh
FILE_DEVICE_KS                  equ 2fh
FILE_DEVICE_CHANGER             equ 30h
FILE_DEVICE_SMARTCARD           equ 31h
FILE_DEVICE_ACPI                equ 32h
FILE_DEVICE_DVD                 equ 33h
FILE_DEVICE_FULLSCREEN_VIDEO    equ 34h
FILE_DEVICE_DFS_FILE_SYSTEM     equ 35h
FILE_DEVICE_DFS_VOLUME          equ 36h
FILE_DEVICE_SERENUM             equ 37h
FILE_DEVICE_TERMSRV             equ 38h
FILE_DEVICE_KSEC                equ 39h


FILE_SUPERSEDE                  equ     00000000
FILE_OPEN                       equ     00000001
FILE_CREATE                     equ     00000002
FILE_OPEN_IF                    equ     00000003
FILE_OVERWRITE                  equ     00000004
FILE_OVERWRITE_IF               equ     00000005
FILE_MAXIMUM_DISPOSITION        equ     00000005

; Define the create/open option flags

FILE_DIRECTORY_FILE                     equ 00000001h
FILE_WRITE_THROUGH                      equ 00000002h
FILE_SEQUENTIAL_ONLY                    equ 00000004h
FILE_NO_INTERMEDIATE_BUFFERING          equ 00000008h

FILE_SYNCHRONOUS_IO_ALERT               equ 00000010h
FILE_SYNCHRONOUS_IO_NONALERT            equ 00000020h
FILE_NON_DIRECTORY_FILE                 equ 00000040h
FILE_CREATE_TREE_CONNECTION             equ 00000080h

FILE_COMPLETE_IF_OPLOCKED               equ 00000100h
FILE_NO_EA_KNOWLEDGE                    equ 00000200h
FILE_OPEN_FOR_RECOVERY                  equ 00000400h
FILE_RANDOM_ACCESS                      equ 00000800h

FILE_DELETE_ON_CLOSE                    equ 00001000h
FILE_OPEN_BY_FILE_ID                    equ 00002000h
FILE_OPEN_FOR_BACKUP_INTENT             equ 00004000h
FILE_NO_COMPRESSION                     equ 00008000h

FILE_RESERVE_OPFILTER                   equ 00100000h
FILE_OPEN_REPARSE_POINT                 equ 00200000h
FILE_OPEN_NO_RECALL                     equ 00400000h
FILE_OPEN_FOR_FREE_SPACE_QUERY          equ 00800000h

FILE_COPY_STRUCTURED_STORAGE            equ 00000041h
FILE_STRUCTURED_STORAGE                 equ 00000441h

FILE_VALID_OPTION_FLAGS                 equ 00ffffffh
FILE_VALID_PIPE_OPTION_FLAGS            equ 00000032h
FILE_VALID_MAILSLOT_OPTION_FLAGS        equ 00000032h
FILE_VALID_SET_FLAGS                    equ 00000036h

; Define the I/O status information return values for NtCreateFile/NtOpenFile

FILE_SUPERSEDED                 equ 0
FILE_OPENED                     equ 1
FILE_CREATED                    equ 2
FILE_OVERWRITTEN                equ 3
FILE_EXISTS                     equ 4
FILE_DOES_NOT_EXIST             equ 5

OBJ_INHERIT                     equ     00000002h
OBJ_PERMANENT                   equ     00000010h
OBJ_EXCLUSIVE                   equ     00000020h
OBJ_CASE_INSENSITIVE            equ     00000040h
OBJ_OPENIF                      equ     00000080h
OBJ_OPENLINK                    equ     00000100h
OBJ_KERNEL_HANDLE               equ     00000200h
OBJ_VALID_ATTRIBUTES            equ     000003F2h