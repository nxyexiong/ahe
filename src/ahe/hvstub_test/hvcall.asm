.code

; int hv_ping(void)
; Returns 1 if R10 == PONG after CPUID, 0 otherwise
hv_ping PROC
    push rbx
    mov r10, 041484500CAFE1337h  ; AHE_CPUID_MAGIC (64-bit)
    mov r11, 0A4E0C0DECAFE13FFh  ; AHE_CMD_MAGIC | CMD_PING
    xor eax, eax
    xor ecx, ecx
    cpuid
    xor eax, eax
    mov rcx, 0504F4E47B00B1E55h  ; AHE_CPUID_PONG (64-bit)
    cmp r10, rcx
    sete al
    pop rbx
    ret
hv_ping ENDP

; uint64_t hv_call(uint64_t cmd, uint64_t a0, uint64_t a1, uint64_t a2,
;                  uint64_t* out_r10, uint64_t* out_r12, uint64_t* out_r13)
;
; Win64: RCX=cmd, RDX=a0, R8=a1, R9=a2,
;        [rsp+28h]=out_r10, [rsp+30h]=out_r12, [rsp+38h]=out_r13
hv_call PROC
    push rbx
    push r12
    push r13
    push r14

    ; 4 pushes = +20h adjustment for stack params
    mov rax, [rsp+28h+20h]   ; out_r10
    push rax
    mov rax, [rsp+30h+28h]   ; out_r12
    push rax
    mov rax, [rsp+38h+30h]   ; out_r13
    push rax

    mov r10, 041484500CAFE1337h  ; AHE_CPUID_MAGIC (64-bit)
    ; R11 = AHE_CMD_MAGIC | cmd
    mov rax, 0A4E0C0DECAFE1300h
    or rax, rcx
    mov r11, rax
    mov r12, rdx             ; a0
    mov r13, r8              ; a1
    mov r14, r9              ; a2

    xor eax, eax
    xor ecx, ecx
    cpuid

    pop rax
    test rax, rax
    jz skip_r13
    mov [rax], r13
skip_r13:
    pop rax
    test rax, rax
    jz skip_r12
    mov [rax], r12
skip_r12:
    pop rax
    test rax, rax
    jz skip_r10
    mov [rax], r10
skip_r10:

    mov rax, r10
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
hv_call ENDP

END
