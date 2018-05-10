; This is the global memory address we apply the hardware breakpoint on.
EXTERN StackSelector: word

; A reference to the C++ routine that will set a hardware breakpoint
; on a target memory address.
EXTERN SetDataBreakpoint: proc

.code

Execute PROC
	; Store the current (valid) SS selector.
	mov [StackSelector], ss

	; BREAKPOINT_TYPE::Access
	mov r9, 3

	; DEBUG_REGISTERS::DR0
	mov r8, 0

	; BREAKPOINT_SIZE::Four
	mov rdx, 3
	
	; Address to place a DB (HWBP) on. This is the address of the global 
	; that contains the SS selector value.
	lea rcx, StackSelector

	; Setup shadow space on the stack.
	sub rsp, 20h

	; Prime the current thread's debug registers.
	call SetDataBreakpoint

	; Restore home space.
	add rsp, 20h

	; Check to see if the routine failed.
	test rax, rax
	jz exit
	
	mov ss, [rax] ; #DB should fire here, but it's supressed.
	int 3

	; #DB is released after the INT 03 instruction executes. 
	;
	; INT 03 will branch to kernelmode, in particular, to the IDT
	; entry at nt!KiBreakpointTrap.
	;
	; nt!KiBreakpointTrap will not execute its first instruction, 
	; since it will be interrupted by the #DB that was just
	; dispatched. This will cause the processor to transition to 
	; the #DB handler at nt!KiDebugTrapOrFault.

exit:
	; This instruction shouldn't execute if we succeed.
	ret
Execute ENDP

END