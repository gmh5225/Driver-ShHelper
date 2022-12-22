#ifndef _SHDRVENUM_H_
#define _SHDRVENUM_H_

typedef enum _SH_POOL_TYPE {
	// global pool types
	GLOBAL_ROUTINES  = 0,
	GLOBAL_VARIABLES = 1,
	GLOBAL_OFFSETS   = 2,

	GlobalPoolTypeCount,

	// other pool types
	NONE_SPECIAL,
	ANSI_POOL,
	UNICODE_POOL,
	AllPoolTypeCount
}SH_POOL_TYPE, *PSH_POOL_TYPE;

typedef enum _SH_GET_BASE_METHOD {
	LoadedModuleList = 0,
	QueryModuleInfo,
}SH_GET_BASE_METHOD, *PSH_GET_BASE_METHOD;

#endif // !_SHDRVENUM_H_
