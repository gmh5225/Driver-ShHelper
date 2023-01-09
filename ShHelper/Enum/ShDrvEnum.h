#ifndef _SHDRVENUM_H_
#define _SHDRVENUM_H_

/**
 * @file ShDrvEnum.h
 * @author Shh0ya (hunho88@gmail.com)
 * @brief global enumeration
 * @date 2022-12-30
 * @copyright the GNU General Public License v3
 */

// https://learn.microsoft.com/ko-kr/windows/release-health/release-information
typedef enum _SH_OS_VERSION {
	WINDOWS_7       = 7600,   /**< 7600 */
	WINDOWS_7_SP1   = 7601,   /**< 7601 */
	WINDOWS_8       = 9200,   /**< 9200 */
	WINDOWS_8_1     = 9600,   /**< 9600 */
	WINDOWS_10_1507 = 10240,  /**< 10240 */
	WINDOWS_10_1511 = 10586,  /**< 10586 */
	WINDOWS_10_1607 = 14393,  /**< 14393 */
	WINDOWS_10_1703 = 15063,  /**< 15063 */
	WINDOWS_10_1709 = 16299,  /**< 16299 */
	WINDOWS_10_1803 = 17134,  /**< 17134 */
	WINDOWS_10_1809 = 17763,  /**< 17763 */
	WINDOWS_10_1903 = 18362,  /**< 18362 */
	WINDOWS_10_1909 = 18363,  /**< 18363 */
	WINDOWS_10_20H1 = 19041,  /**< 19041 */
	WINDOWS_10_20H2 = 19042,  /**< 19042 */
	WINDOWS_10_21H1 = 19043,  /**< 19043 */
	WINDOWS_10_21H2 = 19044,  /**< 19044 */
	WINDOWS_10_22H2 = 19045,  /**< 19045 */
	WINDOWS_11_21H2 = 22000,  /**< 22000 */
	WINDOWS_11_22H2 = 22621   /**< 22621 */
}SH_OS_VERSION, * PSH_OS_VERSION;

typedef enum _SH_POOL_TYPE {
	// global pool types
	GLOBAL_ROUTINES  = 0,
	GLOBAL_VARIABLES = 1,
	GLOBAL_OFFSETS   = 2,
	GLOBAL_CALLBACKS = 3,
	GLOBAL_SOCKETS   = 4,

	GlobalPoolTypeCount,

	// other pool types
	NONE_SPECIAL,
	ANSI_POOL,
	UNICODE_POOL,
	AllPoolTypeCount
}SH_POOL_TYPE, *PSH_POOL_TYPE;

typedef enum _SH_SOCKET_STATE {
	Finalized = 0,
	Finalizing,
	Initialized,
	Initializing
}SH_SOCKET_STATE, *PSH_SOCKET_STATE;

typedef enum _SH_GET_BASE_METHOD {
	LoadedModuleList = 0,
	QueryModuleInfo,
}SH_GET_BASE_METHOD, *PSH_GET_BASE_METHOD;

typedef enum _SH_RW_MEMORY_METHOD {
	RW_Normal = 0,
	RW_Physical,
	RW_MDL
}SH_RW_MEMORY_METHOD, *PSH_RW_MEMORY_METHOD;

typedef enum _SH_MEMSCAN_METHOD {
	MEMSCAN_Normal_One = 0,
	MEMSCAN_Normal_All,
	MEMSCAN_Section_One,
	MEMSCAN_Section_All
}SH_MEMSCAN_METHOD, *PSH_MEMSCAN_METHOD;

typedef enum _SH_REQUEST_METHOD {
	GET = 0,
	POST
}SH_REQUEST_METHOD,*PSH_REQUEST_METHOD;

#endif // !_SHDRVENUM_H_
