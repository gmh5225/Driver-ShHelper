#ifndef _SHDRVMINIFILTER_H_
#define _SHDRVMINIFILTER_H_

/**
 * @file ShDrvMiniFilter.h
 * @author Shh0ya (hunho88@gmail.com)
 * @brief Mini-filter header
 * @date 2022-12-30
 * @copyright the GNU General Public License v3
 */

/**
* @brief Mini-Filter Pre-Operation
* @author Shh0ya @date 2022-12-30
*/
namespace MiniFilterPreOperation {
	FLT_PREOP_CALLBACK_STATUS MiniFilterPreCreate(
		IN OUT PFLT_CALLBACK_DATA Data,
		IN PCFLT_RELATED_OBJECTS FltObjects,
		_Flt_CompletionContext_Outptr_ PVOID* CompletionContext);

	FLT_PREOP_CALLBACK_STATUS MiniFilterPreRead(
		IN OUT PFLT_CALLBACK_DATA Data,
		IN PCFLT_RELATED_OBJECTS FltObjects,
		_Flt_CompletionContext_Outptr_ PVOID* CompletionContext);

	FLT_PREOP_CALLBACK_STATUS MiniFilterPreWrite(
		IN OUT PFLT_CALLBACK_DATA Data,
		IN PCFLT_RELATED_OBJECTS FltObjects,
		_Flt_CompletionContext_Outptr_ PVOID* CompletionContext);

	FLT_PREOP_CALLBACK_STATUS MiniFilterPreClose(
		IN OUT PFLT_CALLBACK_DATA Data,
		IN PCFLT_RELATED_OBJECTS FltObjects,
		_Flt_CompletionContext_Outptr_ PVOID* CompletionContext);

	FLT_PREOP_CALLBACK_STATUS MiniFilterPreCleanUp(
		IN OUT PFLT_CALLBACK_DATA Data,
		IN PCFLT_RELATED_OBJECTS FltObjects,
		_Flt_CompletionContext_Outptr_ PVOID* CompletionContext);
}

/**
* @brief Mini-Filter Post-Operation
* @author Shh0ya @date 2022-12-30
*/
namespace MiniFilterPostOperation {
	FLT_POSTOP_CALLBACK_STATUS MiniFilterPostCreate(
		IN OUT PFLT_CALLBACK_DATA Data,
		IN PCFLT_RELATED_OBJECTS FltObjects,
		IN OPTIONAL PVOID CompletionContext,
		IN FLT_POST_OPERATION_FLAGS Flags);

	FLT_POSTOP_CALLBACK_STATUS MiniFilterPostRead(
		IN OUT PFLT_CALLBACK_DATA Data,
		IN PCFLT_RELATED_OBJECTS FltObjects,
		IN OPTIONAL PVOID CompletionContext,
		IN FLT_POST_OPERATION_FLAGS Flags);

	FLT_POSTOP_CALLBACK_STATUS MiniFilterPostWrite(
		IN OUT PFLT_CALLBACK_DATA Data,
		IN PCFLT_RELATED_OBJECTS FltObjects,
		IN OPTIONAL PVOID CompletionContext,
		IN FLT_POST_OPERATION_FLAGS Flags);

	FLT_POSTOP_CALLBACK_STATUS MiniFilterPostClose(
		IN OUT PFLT_CALLBACK_DATA Data,
		IN PCFLT_RELATED_OBJECTS FltObjects,
		IN OPTIONAL PVOID CompletionContext,
		IN FLT_POST_OPERATION_FLAGS Flags);

	FLT_POSTOP_CALLBACK_STATUS MiniFilterPostCleanUp(
		IN OUT PFLT_CALLBACK_DATA Data,
		IN PCFLT_RELATED_OBJECTS FltObjects,
		IN OPTIONAL PVOID CompletionContext,
		IN FLT_POST_OPERATION_FLAGS Flags);
}

/**
* @brief Mini-Filter common
* @author Shh0ya @date 2022-12-30
*/
namespace ShMiniFilter {

	NTSTATUS MiniFilterUnload(IN FLT_FILTER_UNLOAD_FLAGS Flags);

	NTSTATUS MiniFilterInstanceQueryTeardown(
		IN PCFLT_RELATED_OBJECTS FltObjects,
		IN FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags);

	NTSTATUS MiniFilterInstanceSetup(
		IN PCFLT_RELATED_OBJECTS FltObjects,
		IN FLT_INSTANCE_SETUP_FLAGS Flags,
		IN DEVICE_TYPE VolumeDeviceType,
		IN FLT_FILESYSTEM_TYPE VolumeFilesystemType);

	NTSTATUS MiniFilterConnect(
		IN PFLT_PORT ClientPort,
		IN PVOID ServerPortCookie,
		_In_reads_bytes_(SizeOfContext) PVOID ConnectionContext,
		IN ULONG SizeOfContext,
		_Flt_ConnectionCookie_Outptr_ PVOID* ConnectionCookie);

	NTSTATUS MiniFilterMessage(
		IN PVOID ConnectionCookie,
		_In_reads_bytes_opt_(InputBufferSize) PVOID InputBuffer,
		IN ULONG InputBufferSize,
		_Out_writes_bytes_to_opt_(OutBufferSize, *ReturnOutBufferLength) PVOID OutBuffer,
		IN ULONG OutBufferSize,
		OUT PULONG ReturnOutBufferLength);

	NTSTATUS SendFilterMessage(
		IN PFLT_CALLBACK_DATA Data,
		IN PCFLT_RELATED_OBJECTS FltObjects);

	VOID MiniFilterDisconnect(IN OPTIONAL PVOID ConnectionCookie);
}

const FLT_OPERATION_REGISTRATION MiniFilterCallbacks[] = {
	{ IRP_MJ_CREATE, FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
	MiniFilterPreOperation::MiniFilterPreCreate,
	MiniFilterPostOperation::MiniFilterPostCreate},

	{ IRP_MJ_READ, FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
	MiniFilterPreOperation::MiniFilterPreRead,
	MiniFilterPostOperation::MiniFilterPostRead},

	{ IRP_MJ_WRITE, FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
	MiniFilterPreOperation::MiniFilterPreWrite,
	MiniFilterPostOperation::MiniFilterPostWrite},

	{ IRP_MJ_CLEANUP, FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
	MiniFilterPreOperation::MiniFilterPreCleanUp,
	MiniFilterPostOperation::MiniFilterPostCleanUp},

	#if 0 // TODO - List all of the requests to filter.
	{ IRP_MJ_CREATE,
	  0,
	  FsFilter1PreOperation,
	  FsFilter1PostOperation },

	{ IRP_MJ_CREATE_NAMED_PIPE,
	  0,
	  FsFilter1PreOperation,
	  FsFilter1PostOperation },

	{ IRP_MJ_CLOSE,
	  0,
	  FsFilter1PreOperation,
	  FsFilter1PostOperation },

	{ IRP_MJ_READ,
	  0,
	  FsFilter1PreOperation,
	  FsFilter1PostOperation },

	{ IRP_MJ_WRITE,
	  0,
	  FsFilter1PreOperation,
	  FsFilter1PostOperation },

	{ IRP_MJ_QUERY_INFORMATION,
	  0,
	  FsFilter1PreOperation,
	  FsFilter1PostOperation },

	{ IRP_MJ_SET_INFORMATION,
	  0,
	  FsFilter1PreOperation,
	  FsFilter1PostOperation },

	{ IRP_MJ_QUERY_EA,
	  0,
	  FsFilter1PreOperation,
	  FsFilter1PostOperation },

	{ IRP_MJ_SET_EA,
	  0,
	  FsFilter1PreOperation,
	  FsFilter1PostOperation },

	{ IRP_MJ_FLUSH_BUFFERS,
	  0,
	  FsFilter1PreOperation,
	  FsFilter1PostOperation },

	{ IRP_MJ_QUERY_VOLUME_INFORMATION,
	  0,
	  FsFilter1PreOperation,
	  FsFilter1PostOperation },

	{ IRP_MJ_SET_VOLUME_INFORMATION,
	  0,
	  FsFilter1PreOperation,
	  FsFilter1PostOperation },

	{ IRP_MJ_DIRECTORY_CONTROL,
	  0,
	  FsFilter1PreOperation,
	  FsFilter1PostOperation },

	{ IRP_MJ_FILE_SYSTEM_CONTROL,
	  0,
	  FsFilter1PreOperation,
	  FsFilter1PostOperation },

	{ IRP_MJ_DEVICE_CONTROL,
	  0,
	  FsFilter1PreOperation,
	  FsFilter1PostOperation },

	{ IRP_MJ_INTERNAL_DEVICE_CONTROL,
	  0,
	  FsFilter1PreOperation,
	  FsFilter1PostOperation },

	{ IRP_MJ_SHUTDOWN,
	  0,
	  FsFilter1PreOperationNoPostOperation,
	  NULL },                               //post operations not supported

	{ IRP_MJ_LOCK_CONTROL,
	  0,
	  FsFilter1PreOperation,
	  FsFilter1PostOperation },

	{ IRP_MJ_CLEANUP,
	  0,
	  FsFilter1PreOperation,
	  FsFilter1PostOperation },

	{ IRP_MJ_CREATE_MAILSLOT,
	  0,
	  FsFilter1PreOperation,
	  FsFilter1PostOperation },

	{ IRP_MJ_QUERY_SECURITY,
	  0,
	  FsFilter1PreOperation,
	  FsFilter1PostOperation },

	{ IRP_MJ_SET_SECURITY,
	  0,
	  FsFilter1PreOperation,
	  FsFilter1PostOperation },

	{ IRP_MJ_QUERY_QUOTA,
	  0,
	  FsFilter1PreOperation,
	  FsFilter1PostOperation },

	{ IRP_MJ_SET_QUOTA,
	  0,
	  FsFilter1PreOperation,
	  FsFilter1PostOperation },

	{ IRP_MJ_PNP,
	  0,
	  FsFilter1PreOperation,
	  FsFilter1PostOperation },

	{ IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
	  0,
	  FsFilter1PreOperation,
	  FsFilter1PostOperation },

	{ IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION,
	  0,
	  FsFilter1PreOperation,
	  FsFilter1PostOperation },

	{ IRP_MJ_ACQUIRE_FOR_MOD_WRITE,
	  0,
	  FsFilter1PreOperation,
	  FsFilter1PostOperation },

	{ IRP_MJ_RELEASE_FOR_MOD_WRITE,
	  0,
	  FsFilter1PreOperation,
	  FsFilter1PostOperation },

	{ IRP_MJ_ACQUIRE_FOR_CC_FLUSH,
	  0,
	  FsFilter1PreOperation,
	  FsFilter1PostOperation },

	{ IRP_MJ_RELEASE_FOR_CC_FLUSH,
	  0,
	  FsFilter1PreOperation,
	  FsFilter1PostOperation },

	{ IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE,
	  0,
	  FsFilter1PreOperation,
	  FsFilter1PostOperation },

	{ IRP_MJ_NETWORK_QUERY_OPEN,
	  0,
	  FsFilter1PreOperation,
	  FsFilter1PostOperation },

	{ IRP_MJ_MDL_READ,
	  0,
	  FsFilter1PreOperation,
	  FsFilter1PostOperation },

	{ IRP_MJ_MDL_READ_COMPLETE,
	  0,
	  FsFilter1PreOperation,
	  FsFilter1PostOperation },

	{ IRP_MJ_PREPARE_MDL_WRITE,
	  0,
	  FsFilter1PreOperation,
	  FsFilter1PostOperation },

	{ IRP_MJ_MDL_WRITE_COMPLETE,
	  0,
	  FsFilter1PreOperation,
	  FsFilter1PostOperation },

	{ IRP_MJ_VOLUME_MOUNT,
	  0,
	  FsFilter1PreOperation,
	  FsFilter1PostOperation },

	{ IRP_MJ_VOLUME_DISMOUNT,
	  0,
	  FsFilter1PreOperation,
	  FsFilter1PostOperation },

#endif // TODO
	{IRP_MJ_OPERATION_END}
};

#endif // !_SHDRVMINIFILTER_H_
