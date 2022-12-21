#ifndef _SHDRVFUNCDEF_H_
#define _SHDRVFUNCDEF_H_

namespace ShDrvFuncDef {
	namespace Ps {
		typedef PPEB(NTAPI* PsGetProcessPeb_t)(
			IN PEPROCESS Process
			);
	}
}

#endif // !_SHDRVFUNCDEF_H_
