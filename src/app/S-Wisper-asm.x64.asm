.code

EXTERN SW3_GetSyscallNumber: PROC

Sw3NtCreateThreadEx PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 084A94AFEh        ; Load function hash into ECX.
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
Sw3NtCreateThreadEx ENDP

end