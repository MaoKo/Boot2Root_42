
format ELF executable $03
entry _start

struc string data*& {
    .: db data
    .length = ($ - .)
}

S_IRWXU = $01C0
S_IRUSR = $0100
S_IWUSR = $0080
S_IXUSR = $0040
S_IRWXG = $0038
S_IRGRP = $0020
S_IWGRP = $0010
S_IXGRP = $0008
S_IRWXO = $0007
S_IROTH = $0004
S_IWOTH = $0002
S_IXOTH = $0001

SEEK_SET = $00
SEEK_CUR = $01
SEEK_END = $02

struc linux_dirent {
    .d_ino: rd $01
    .d_off: rd $01
    .d_reclen: rw $01
    .d_name: db ?
    ;.d_type: rb $01
}

DT_UNKNOWN = $00
DT_FIFO = $01
DT_CHR = $02
DT_DIR = $04
DT_BLK = $06
DT_REG = $08
DT_LNK = $0A
DT_SOCK = $0C

struc timespec {
    .tv_sec: rq $01
    .tv_nsec: rq $01
}

struc stat {
    .st_dev: rw $01
    .__pad1: rw $01
    .st_ino: rd $01
    .st_mode: rw $01
    .st_nlink: rw $01
    .st_uid: rw $01
    .st_gid: rw $01
    .st_rdev: rw $01
    .__pad2: rw $01
    .st_size: rd $01
    .st_blksize: rd $01
    .st_blocks: rd $01
    .st_atime: rd $01
    .__unused1: rd $01
    .st_mtime: rd $01
    .__unused2: rd $01
    .st_ctime: rd $01
    .__unused3: rd $01
    .__unused4: rd $01
    .__unused5: rd $01
}

irp _target, linux_dirent, timespec, stat {
    virtual at $00
        _target _target
        _target#.sizeof = $
    end virtual
}

macro _write_error string*, target {
    mov eax, $04
    mov ebx, $02
    mov ecx, string
    mov edx, string#.length
    int $80
    match _, target
        \{ jmp target \}
}

macro _wait_child status {
    mov eax, $07
    mov ebx, not $00
    match _, status \{ mov ecx, status \}
    match,status    \{ xor ecx,    ecx \}
    xor edx, edx
    int $80
}

_BUFFER = $40

segment executable readable

_strlen:
    xor al, al
    mov edi, dword [esp+$04]
    xor ecx, ecx
    not ecx
    repnz scasb
    inc ecx
    not ecx
    mov eax, ecx
    ret $04

_strcmp:
    push dword [esp+$04]
    call _strlen
    lea ecx, [eax+$01]
    mov esi, dword [esp+$04]
    mov edi, dword [esp+$08]
    repz cmpsb
    jnz .adjust
    xor eax, eax
    jmp .exit
.adjust:
    seta al
    setb dl
    neg dl
    add al, dl
    movsx eax, al
.exit:
    ret $08

_strstr:
    push ebx
    push dword [esp+$0C]
    call _strlen
    mov ebx, eax 
    push dword [esp+$08]
    call _strlen
    mov esi, dword [esp+$08]
    test ebx, ebx
    jz .found
    lea edx, [ebx-$01]
    mov ecx, eax
    sub ecx, edx
    jle .reset
.loop:
    mov edi, dword [esp+$0C]
    push ecx esi
    mov ecx, ebx
    repz cmpsb
    pop esi ecx
    jz .found
    inc esi
    loop .loop
.reset:
    xor eax, eax
    jmp .exit
.found:
    mov eax, esi
.exit:
    pop ebx
    ret $08

_extension_check:
; out
;  carry set - extension match
;  carry clear - reverse
    mov eax, dword [esp+$04]
    push eax
    call _strlen
    mov edi, dword [esp+$04]
    lea edi, [edi+eax-$01]
    mov eax, ecx
    mov al, $2E
    std
    repnz scasb
    cld
    jnz .clear
    add edi, $02
    mov esi, dword [esp+$08]
    push esi edi
    call _strcmp
    test eax, eax
    jnz .clear
    stc
    jmp .exit
.clear:
    clc
.exit:
    ret $08

_unsigned_atoi:
    mov esi, dword [esp+$04]
    xor edi, edi
    mov ecx, $0A
.loop:
    lodsb
    xor al, $30
    cmp al, $09
    ja .next
    movzx eax, al
    imul edi, edi, $0A
    add edi, eax
    jmp .loop
.next:
    mov eax, edi
    ret $04

_append_if_match:
; if the number in the file [esp+$08] == [esp+$0C]
;  then write into filde [esp+$04]
; out
;  carry set - found number
;  carry clear - reverse
    push ebp
    mov ebp, esp
    sub esp, stat.sizeof
    mov eax, $6A
    mov ebx, dword [ebp+$0C]
    mov ecx, esp
    int $80
    test eax, eax
    js _exit
    mov eax, dword [esp+stat.st_size]
    sub esp, eax
    dec esp
    and esp, not $00
    push eax
    mov eax, $05
    mov ebx, dword [ebp+$0C]
    xor ecx, ecx
    int $80
    test eax, eax
    js _exit
    push eax
    mov ebx, eax
    mov eax, $03
    mov edx, dword [esp+$04]
    lea ecx, dword [esp+$08]
    int $80
    test eax, eax
    js _exit
    cmp eax, dword [esp+$04]
    jnz _exit
    mov eax, $06
    pop ebx
    int $80
    mov eax, dword [esp]
    lea esi, dword [esp+$04]
    mov byte [esi+eax], $00
    push _search esi
    call _strstr
    test eax, eax
    jz .error
    add eax, _search.length
    push eax
    call _unsigned_atoi
    cmp eax, dword [ebp+$10]
    jnz .clear
    mov eax, $04
    mov ebx, dword [ebp+$08]
    pop edx
    mov ecx, esp
    int $80
    mov eax, $04
    mov ebx, dword [ebp+$08]
    mov ecx, _newline
    mov edx, $01
    int $80
    stc
    jmp .exit
.error:
    _write_error _pattern_not_found, _exit
.clear:
    clc
.exit:
    leave
    ret $0C

_iterate_folder:
; out
;  carry set - found a file with the target number
;  carry clear - reverse
    push ebp
    mov ebp, esp
    push not $00
    mov eax, $05
    mov ebx, _current_dir
    xor ecx, ecx
    int $80
    test eax, eax
    js _exit
    mov dword [esp], eax
    sub esp, _BUFFER
.loop:
    mov eax, $8D
    mov ebx, dword [ebp-$04]
    mov ecx, esp
    mov edx, _BUFFER
    int $80
    test eax, eax
    js _exit
    jz .clear
    xor ecx, ecx
    mov esi, esp
.list:
    movzx edx, word [esi+linux_dirent.d_reclen]
    cmp byte [esi+edx-$01], DT_REG
    jnz .update
    push ecx edx eax esi esi
    lea eax, byte [esi+linux_dirent.d_name]
    push _pcap eax
    call _extension_check
    pop esi
    jnc .unroll
    lea eax, byte [esi+linux_dirent.d_name]
    mov ecx, dword [ebp+$08]
    mov edx, dword [ebp+$0C]
    push edx eax ecx
    call _append_if_match
    jnc .unroll
    stc
    jmp .exit
.unroll:
    pop esi eax edx ecx
.update:
    add esi, edx
    add ecx, edx 
    cmp ecx, eax
    jb .list
    jmp .loop
.clear:
    clc
.exit:
    pushf
    mov ebx, dword [ebp-$04]
    mov eax, $06
    int $80
    popf
    leave
    ret $08

_START = $01
_start:
    and esp, not $0F
    mov ebp, esp
    mov eax, dword [esp]
    xor eax, $02
    jnz .usage
    mov eax, $0C
    mov ebx, dword [esp+$08]
    int $80
    test eax, eax
    jnz .chdir
    mov eax, $3C
    xor ebx, ebx
    int $80
    mov eax, $08
    mov ebx, _main
    mov ecx, S_IRUSR or S_IWUSR or S_IRGRP or S_IROTH
    int $80
    test eax, eax
    js _exit
    mov ecx, _START
.loop:
    push eax ecx ecx eax
    call _iterate_folder
    pop ecx eax
    jnc .continue
    inc ecx
    jb .loop
.continue:
    mov eax, $02
    int $80
    test eax, eax
    jz .child_1
    _wait_child
    sub esp, $08
    mov ebp, esp
    mov eax, $2A 
    mov ebx, esp
    int $80
    test eax, eax
    js _exit
    mov eax, $02
    int $80
    test eax, eax
    jz .child_2
    _wait_child
    sub esp, _BUFFER
    mov eax, $03
    mov ebx, dword [ebp]
    mov ecx, esp
    mov edx, _BUFFER
    int $80
    test eax, eax
    js _exit

rept $02 i:($00)
{
    mov eax, $06
    mov ebx, dword [ebp+(i*$04)]
    int $80
}
    mov eax, $2A
    mov ebx, ebp
    int $80
    test eax, eax
    js _exit
    mov eax, esp
    push _my_password_is eax
    call _strstr
    xor eax, esp
    jnz _exit
    add esp, _my_password_is.length
    mov ecx, _BUFFER - _my_password_is.length
    assert ((_BUFFER - _my_password_is.length) > $00)
    mov edi, esp
    mov al, $20
    repz scasb
    jz .buffer
    dec edi
    inc ecx
    mov esp, edi
    mov al, $0A
    repnz scasb
    jnz .buffer
    mov eax, $04
    mov ebx, dword [ebp+$04]
    mov ecx, esp
    mov edx, edi
    sub edx, esp
    dec edx
    int $80
    mov eax, $06
    mov ebx, dword [ebp+$04]
    int $80
    mov eax, $3F 
    mov ebx, dword [ebp]
    xor ecx, ecx
    int $80
    mov eax, $0B
    mov ebx, _bin_sha256sum
    xor edx, edx
    push edx ebx
    mov ecx, esp
    int $80
            _write_error _no_sha256sum, _exit
.child_1:
    xor eax, eax
    mov ebx, _bin_cc
    push eax _main ebx
    mov ecx, esp
    push eax _basic_path
    mov edx, esp
    mov eax, $0B
    int $80
    jmp .compiler
.child_2:
    mov eax, $3F
    mov ebx, dword [esp+$04]
    mov cl, $01
    movzx ecx, cl
    int $80
    mov eax, $0B
    mov ebx, _a_out
    xor edx, edx
    push edx ebx
    mov ecx, esp
    int $80
.chdir:     _write_error _cant_chdir, _exit
.compiler:  _write_error _no_compiler, _exit
.buffer:    _write_error _buffer_too_small, _exit
.usage:     _write_error _bad_usage
_exit:
    mov eax, $01
    xor ebx, ebx
    int $80

segment readable
_bad_usage string "BAD USAGE.", $0A
_cant_chdir string "CAN'T CHDIR.", $0A
_pattern_not_found string "PATTERN `//file` NOT FOUND", $0A
_no_compiler string "NO COMPILER", $0A
_no_sha256sum string "NO SHA256SUM", $0A
_buffer_too_small string "BUFFER TOO SMALL", $0A

_current_dir: db ".", $00
_main: db "./main.c", $00
_a_out: db "./a.out", $00
_search string "//file"
db $00
_pcap: db "pcap", $00
_bin_cc: db "/bin/cc", $00
_bin_sha256sum: db "/bin/sha256sum", $00
_basic_path: db "PATH=/bin:/usr/bin", $00
_newline: db $0A
_my_password_is string "MY PASSWORD IS:"
db $00

segment gnustack readable
segment gnurelro readable