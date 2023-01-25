.code _text

    AsmGetRsp PROC
        xor rax, rax
        mov rax, rsp
        ret
    AsmGetRsp ENDP

    AsmGetCs PROC
        xor rax, rax
        mov ax, cs
        ret
    AsmGetCs ENDP

    AsmGetSs PROC
        xor rax, rax
        mov ax, ss
        ret
    AsmGetSs ENDP

    AsmGetDs PROC
        xor rax, rax
        mov ax, ds
        ret
    AsmGetDs ENDP

    AsmGetEs PROC
        xor rax, rax
        mov ax, es
        ret
    AsmGetEs ENDP

    AsmGetFs PROC
        xor rax, rax
        mov ax, fs
        ret
    AsmGetFs ENDP

    AsmGetGs PROC
        xor rax, rax
        mov ax, gs
        ret
    AsmGetGs ENDP

    AsmGetTr PROC
        xor rax, rax
        str ax
        ret
    AsmGetTr ENDP

    AsmGetLdtr PROC
        xor rax, rax
        sldt ax
        ret
    AsmGetLdtr ENDP

    AsmGetGdtr PROC
        LOCAL gdtr[10]:BYTE

        sgdt gdtr
        
        xor rax, rax
        mov ax, WORD ptr gdtr[0]
        mov WORD ptr [rcx], ax
        
        mov rax, QWORD ptr gdtr[2]
        mov QWORD ptr [rcx+2], rax

        xor rax, rax
        ret
    AsmGetGdtr ENDP

    AsmGetIdtr PROC
        LOCAL idtr[10]:BYTE

        sidt idtr
        
        xor rax, rax
        mov ax, WORD ptr idtr[0]
        mov WORD ptr [rcx], ax
        
        mov rax, QWORD ptr idtr[2]
        mov QWORD ptr [rcx+2], rax
        
        xor rax, rax
        ret
    AsmGetIdtr ENDP

    AsmGetGdtBase PROC

        LOCAL	gdtr[10]:BYTE
	    sgdt	gdtr
	    mov		rax, QWORD PTR gdtr[2]
	    ret
    AsmGetGdtBase ENDP

    AsmGetIdtBase PROC

        LOCAL	idtr[10]:BYTE
	    sidt	idtr
	    mov		rax, QWORD PTR idtr[2]
	    ret
    AsmGetIdtBase ENDP

    AsmGetGdtLimit PROC

        LOCAL	gdtr[10]:BYTE
	    sgdt	gdtr
	    mov		ax, WORD PTR gdtr[0]
	    ret
    AsmGetGdtLimit ENDP

    AsmGetIdtLimit PROC

        LOCAL	idtr[10]:BYTE
	    sidt	idtr
	    mov		ax, WORD PTR idtr[0]
	    ret
    AsmGetIdtLimit ENDP

    AsmGetRflags PROC

        pushfq
        pop rax
	    ret
    AsmGetRflags ENDP

    AsmReloadGdtr PROC
        push rcx
        shl rdx, 48
        push rdx
        lgdt fword ptr [rsp+6]
        pop rax
        pop rax
        ret
    AsmReloadGdtr ENDP
    

    AsmReloadIdtr PROC
        push rcx
        shl rdx, 48
        push rdx
        lidt fword ptr [rsp+6]
        pop rax
        pop rax
        ret
    AsmReloadIdtr ENDP


end