; TheLightOne
; Windows x64 Nasm MessageBox Shellcode
; Tested at windows 10 Pro
; By no means is this optimized. I wrote this to learn some assembly.
; I believe that this code can help someone to start in this field and write his own code.
; Thanks for the nice article that inspired me https://nytrosecurity.com/2019/06/30/writing-shellcodes-for-windows-x64/ 
; Release date: 11.28.2019


; constants
MB_DEFBUTTON2 EQU 100h                       
MEM_COMMIT equ 0x00001000
MEM_RESERVE equ 0x00002000
PAGE_EXECUTE_READWRITE equ 0x40

; externs 
extern ExitProcess                              
extern VirtualAlloc
extern RtlCopyMemory

global main

section .text                                   
; move shellcode to the rwx memory region and execute it there
; shellcode entry_point is at offset 0
main:
    sub rsp, 8                                   
    sub rsp, 32          

    xor rcx, rcx  ; LPVOID lpAddress
    mov rdx, SHELLCODE_END - SHELLCODE_START ; SIZE_T dwSize
    mov r8d, MEM_COMMIT | MEM_RESERVE ; DWORD  flAllocationType
    mov r9d, PAGE_EXECUTE_READWRITE ; DWORD  flProtect
    call VirtualAlloc
    mov r15, rax

    mov rcx, rax ; PVOID  Destination
    mov rdx, SHELLCODE_START ; VOID   *Source
    mov r8, SHELLCODE_END - SHELLCODE_START ; SIZE_T Length
    call RtlCopyMemory
    
    ; run shellcode
    call r15

    xor rcx, rcx
    call ExitProcess
    add rsp, 32

;   ----------------------------  SHELLCODE STARTS HERE ----------------------------
SHELLCODE_START:
    ; Message Box
    call GetUser32
    mov r15, rax

    ; MessageBoxA string to eax
    jmp x2
x1:
    array DB 4Dh, 65h, 73h, 73h, 61h, 67h, 65h, 42h, 6Fh, 78h, 41h, 00h
x2: 
    call GetDelta
    mov r14, rax
    add rax, x1

    mov rcx, rax
    mov rdx, r15
    call GetProcAddressEx
    mov r15, rax
    
    ; "Message from shellcode" string to eax
    jmp x4
x3:
    db "Message from shellcode", 00h
x4: 
    mov rdx, x3
    add rdx, r14 ; r14 is delta offset
    mov r14, qword [rsp]
    add rsp, 8
    xor ecx, ecx                                 
    xor r8, r8
    mov r9d, MB_DEFBUTTON2
    call r15
    
    jmp r14

GetDelta:
    call GetDelta2
GetDelta2:
    pop rax
    sub rax, GetDelta2
    ret

; GetKernel32Ex
;   Returns kernel32 address in rax
;   Doesn't matter what position of. Guarantee to find the kernel32 because it checks the LDR_DATA_TABLE_ENTRY.DllName
GetKernel32Ex:
    xor rcx, rcx             ; RCX = 0
    mov rax, [gs:rcx + 0x60] ; RAX = PEB
    mov rax, [rax + 0x18]    ; RAX = PEB->Ldr
    mov rsi, [rax + 0x20]    ; RSI = PEB->Ldr.InMemOrder

GetKernel32ExCheckModule:
    lodsq
    mov rcx, [rax + 0x50]
    xchg rax, rsi
    mov rdx, 0x004E00520045004B  
    cmp QWORD [rcx], rdx
    jne GetKernel32ExCheckModule
    mov rdx, 0x00320033004C0045  
    cmp QWORD [rcx+0x08], rdx
    je GetKernel32ExCheckModuleFoundIt
    jmp GetKernel32ExCheckModule
GetKernel32ExCheckModuleFoundIt:        
    mov rax, [rsi+0x20]
    ret

; StrCmp  
;   Parameters: rcx = s1
;               rdx = s2
;   Return: rax == 0 if strings are equal
StrCmp:  
    xor     rax, rax
    sub     rsp, 16
    mov     qword [rsp], rsi
    mov     qword [rsp+8], rdi
    mov     rsi, rcx
    mov     rdi, rdx
StrCmpLoop:    
    lodsb
    or      al,  al
    jz      StrCmpStop
    sub     al, byte [rdi]
    jnz     StrCmpStop
    inc     rdi
    jmp     StrCmpLoop
StrCmpStop: 
    mov     rdi, qword [rsp+8]
    mov     rsi, qword [rsp]
    add     rsp, 16
    ret

;  GetProcAddressEx
;   Argument: rcx = pointer to function name 
;             rdx = module base
;   Return: eax = function address
GetProcAddressEx:   
    sub rsp, 24
    mov qword [rsp], rcx
    mov rbx, rdx

    ; Parse kernel32 PE
    xor r8, r8                 ; Clear r8
    mov r8d, [rbx + 0x3c]      ; R8D = DOS->e_lfanew offset
    mov rdx, r8                ; RDX = DOS->e_lfanew
    add rdx, rbx               ; RDX = PE Header
    mov r8d, [rdx + 0x88]      ; R8D = Offset export table
    add r8, rbx                ; R8 = Export table
    xor rsi, rsi               ; Clear RSI
    mov esi, [r8 + 0x20]       ; RSI = Offset namestable
    add rsi, rbx               ; RSI = Names table
    xor rcx, rcx               ; RCX = 0
    ; Loop through exported functions and find GetProcAddress
Get_FunctionEx:
    inc rcx                    ; Increment the ordinal
    xor rax, rax               ; RAX = 0
    mov eax, [rsi + rcx * 4]   ; Get name offset
    add rax, rbx               ; Get function name

    mov qword [rsp+8], rcx
    mov rcx, rax
    mov rdx, qword [rsp]       ; pointer to function name
    call StrCmp
    mov rcx, qword [rsp+8]
    test rax, rax
    jnz Get_FunctionEx
    xor rsi, rsi               ; RSI = 0
    mov esi, [r8 + 0x24]       ; ESI = Offset ordinals
    add rsi, rbx               ; RSI = Ordinals table
    mov cx, [rsi + rcx * 2]    ; Number of function
    xor rsi, rsi               ; RSI = 0
    mov esi, [r8 + 0x1c]       ; Offset address table
    add rsi, rbx               ; ESI = Address table
    xor rdx, rdx               ; RDX = 0
    mov edx, [rsi + rcx * 4]   ; EDX = Pointer(offset)
    add rdx, rbx               ; RDX = GetProcAddress
    mov rax, rdx               ; Save GetProcAddress in RDI

    add rsp, 24
    ret

; Kernel32_LoadLibraryA
;   Params: rcx = library name
;   Return: rax = ptr loaded module
Kernel32_LoadLibraryA:
    sub rsp, 8
    mov qword [rsp], rcx
    call GetKernel32Ex
    mov rcx, 0x41797261  
    push rcx
    mov rcx, 0x7262694C64616F4C  
    push rcx
    mov rcx, rsp
    mov rdx, rax
    call GetProcAddressEx
    add rsp, 16
    mov rcx, qword [rsp]
    sub rsp, 0x30
    call rax
    add rsp, 0x30
    add rsp, 8
    ret

;  GetUser32
;    Return: ptr user32 module in memory 
;
GetUser32:
    xor rcx, rcx
    mov rcx, 0x6c6c ; assembles into: mov ecx, imm16. Hence the xor            
    push rcx                      
    mov rcx, 0x642e323372657375   
    push rcx                      
    mov rcx, rsp                  
    call Kernel32_LoadLibraryA    
    add rsp, 0x10                 
    ret
SHELLCODE_END:    
;   ----------------------------  SHELLCODE SENDS HERE ----------------------------