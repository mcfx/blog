title: "PlaidCTF 2022 Writeup"
tags:
  - CTF
  - Writeup
#! meta end

Writeup for choreography and pressure in PlaidCTF 2022.

#! head end

# choreography

In `cipher.py`, if we assume that `encrypt1` is an encryption function, then `encrypt2` is the corresponding decryption function.

Let $A=a\oplus k_3,B=b\oplus k_0,C=c\oplus k_2,D=d\oplus k_1,k_{01}=k_0\oplus k_1,k_{23}=k_2\oplus k_3$. After 4 rounds of encryption, they becomes:

$$
\begin{align*}
A&\Rightarrow A\oplus \text{sbox}[B]\oplus \text{sbox}[B\oplus \text{sbox}[C\oplus \text{sbox}[D]]\oplus k_{01}]\\
B&\Rightarrow B\oplus \text{sbox}[C\oplus \text{sbox}[D]]\oplus \text{sbox}[C\oplus \text{sbox}[D]\oplus \text{sbox}[D\oplus \text{sbox}[A\oplus \text{sbox}[B]]\oplus k_{01}]\oplus k_{23}]\\
C&\Rightarrow C\oplus \text{sbox}[D]\oplus \text{sbox}[D\oplus \text{sbox}[A\oplus \text{sbox}[B]]\oplus k_{01}]\\
D&\Rightarrow D\oplus \text{sbox}[A\oplus \text{sbox}[B]]\oplus \text{sbox}[A\oplus \text{sbox}[B]\oplus \text{sbox}[B\oplus \text{sbox}[C\oplus \text{sbox}[D]]\oplus k_{01}]\oplus k_{23}]
\end{align*}
$$

Now suppose $k_{01}$ and $k_{23}$ is given.

After $2^{22}+2$ rounds, $A,B,C,D$ becomes $C',D',A',B'$. We can precompute this for all $(A,B,C,D)$ in $O(22\times 2^{32})$ time by binary lifting. Then we can calculate the mapping $f:(A\oplus A',B\oplus B',C\oplus C',D\oplus D')\Rightarrow (A,B,C,D)$. $f$ is a one-to-many function, we can store any of them.

For the original problem, when we get the encryption result $c',d',a',b'$ of some message $a,b,c,d$, we can try to call $f(a\oplus a',b\oplus b',c\oplus c',d\oplus d')$ to find $A,B,C,D$, and then find the keys.

This gives a final solution: precompute many of such mappings, and send random messages to the server. If any of these precomputed $k_{01},k_{23}$ is correct, then we can get the flag. I solved the challenge with ~120 mappings and ~1000 tries.

Program used to precompute mappings:

```cpp
#include<bits/stdc++.h>

typedef long long ll;
typedef unsigned int uint;
typedef unsigned char uc;
#define fo0(i,n) for(int i=0;i<n;i++)

const uc sbox[256]={/* omitted */};

int main(int argc,char**argv)
{
	int k01=atoi(argv[1]),k23=atoi(argv[2]);
	uint*tab1=new uint[1ll<<32],*tab2=new uint[1ll<<32];
#pragma omp parallel for num_threads(16)
	for(uint A=0;A<256;A++)
	{
		fo0(B,256)fo0(C,256)fo0(D,256)
		{
			uint NA=A^sbox[B]^sbox[B^sbox[C^sbox[D]]^k01];
			uint NB=B^sbox[C^sbox[D]]^sbox[C^sbox[D]^sbox[D^sbox[A^sbox[B]]^k01]^k23];
			uint NC=C^sbox[D]^sbox[D^sbox[A^sbox[B]]^k01];
			uint ND=D^sbox[A^sbox[B]]^sbox[A^sbox[B]^sbox[B^sbox[C^sbox[D]]^k01]^k23];
			tab1[(uint)A<<24|(uint)B<<16|(uint)C<<8|(uint)D]=NA<<24|NB<<16|NC<<8|ND;
		}
	}
	fo0(i,20)
	{
#pragma omp parallel for num_threads(16)
		for(ll i=0;i<(1ll<<32);i++)tab2[i]=tab1[tab1[i]];
		std::swap(tab1,tab2);
	}
#pragma omp parallel for num_threads(16)
	for(ll i=0;i<(1ll<<32);i++)
	{
		uint A=tab1[i]>>24,B=tab1[i]>>16&255,C=tab1[i]>>8&255,D=tab1[i]&255;
		uint NA=A^sbox[B];
		uint NB=B^sbox[C^sbox[D]];
		uint NC=C^sbox[D];
		uint ND=D^sbox[A^sbox[B]];
		tab2[i]=NA<<24|NB<<16|NC<<8|ND;
	}
	memset(tab1,0,4ll<<32);
#pragma omp parallel for num_threads(16)
	for(ll i=0;i<(1ll<<32);i++)tab1[tab2[i]^i]=i;
	FILE*f=fopen(("tab/"+std::to_string(k01)+"_"+std::to_string(k23)+".bin").c_str(),"wb");
	for(ll i=0;i<256;i++)fwrite(tab1+(i<<24),1,4<<24,f);
	fclose(f);
}
```

Program used to find keys given (raw, enc) pairs:

```cpp
#include<bits/stdc++.h>
#include<dirent.h>

typedef long long ll;
typedef unsigned char uc;
#define xx first
#define yy second
#define pb push_back
#define mp std::make_pair

const uc sbox[256]={/* omitted */};

void enc1(uc s[4],uc k[4],ll C)
{
	uc a=s[0],b=s[1],c=s[2],d=s[3];
	//for(ll i=C;i--;)
	for(ll i=0;i<C;i++)
	{
		a^=sbox[b^k[2*i&3]];
		c^=sbox[d^k[2*i+1&3]];
		uc t=a;
		a=b,b=c,c=d,d=t;
	}
	s[0]=a,s[1]=b,s[2]=c,s[3]=d;
}

bool chk(uint a,uint b,uc k[4])
{
	uc t[4];
	t[0]=a>>24,t[1]=a>>16&255,t[2]=a>>8&255,t[3]=a&255;
	enc1(t,k,1<<22|2);
	return b==((uint)t[2]<<24|(uint)t[3]<<16|(uint)t[0]<<8|t[1]);
}

std::vector<std::pair<uint,uint>>ps;

int main(int argc,char**argv)
{
	FILE*f=fopen(argv[1],"r");
	uint xa,xb;
	while(~fscanf(f,"%u%u",&xa,&xb))
	{
		ps.pb(mp(xa,xb));
	}
	fclose(f);
	DIR*d;
	struct dirent *dir;
	d=opendir("tab");
	assert(d);
	while(dir=readdir(d))
	{
		std::string fk=dir->d_name;
		int pos=fk.find("_");
		if(pos<0)continue;
		int k01=atoi(fk.substr(0,pos).c_str());
		int k23=atoi(fk.substr(pos+1,fk.find(".")-pos-1).c_str());
		FILE*f=fopen(("tab/"+std::to_string(k01)+"_"+std::to_string(k23)+".bin").c_str(),"rb");
		for(auto&o:ps)
		{
			fseek(f,ll(o.xx^o.yy)<<2,SEEK_SET);
			uint g;
			fread(&g,1,4,f);
			uint a=o.xx>>24,b=o.xx>>16&255,c=o.xx>>8&255,d=o.xx&255;
			uint A=g>>24,B=g>>16&255,C=g>>8&255,D=g&255;
			if(A^C^a^c^k23)continue;
			if(B^D^b^d^k01)continue;
			uc k[4];
			k[0]=B^b,k[1]=D^d,k[2]=C^c,k[3]=A^a;
			if(!chk(o.xx,o.yy,k))continue;
			if(!chk(ps[0].xx,ps[0].yy,k))continue;
			bool flag=1;
#pragma omp parallel for reduction(&:flag) num_threads(16)
			for(int i=1;i<(int)ps.size();i++)
			{
				flag&=chk(ps[i].xx,ps[i].yy,k);
			}
			if(flag)
			{
				printf("%u %u %u %u\n",B^b,D^d,C^c,A^a);
				return 0;
			}
		}
	}
}
```

Interacter:

```python
from pwn import *
import os, requests

context.log_level = 'debug'

QUERIES = 500
r = process(['python', 'cipher.py'])

r.recvuntil('input (hex): ')
x = os.urandom(QUERIES * 4)
r.sendline(x.hex())
r.recvuntil('input (hex): ')
y = os.urandom(QUERIES * 4)
r.sendline(y.hex())
r.recvuntil('result:')
z = bytes.fromhex(r.recvline().strip().decode())

a = x + z[QUERIES * 4:]
b = z[:QUERIES * 4] + y
ls = []
for i in range(0, len(a) // 2, 4):
    x = a[i] << 24 | a[i + 1] << 16 | a[i + 2] << 8 | a[i + 3]
    y = b[i + 2] << 24 | b[i + 3] << 16 | b[i] << 8 | b[i + 1]
    ls.append('%d %d' % (x, y))
for i in range(len(a) // 2, len(a), 4):
    x = a[i + 2] << 24 | a[i + 3] << 16 | a[i] << 8 | a[i + 1]
    y = b[i] << 24 | b[i + 1] << 16 | b[i + 2] << 8 | b[i + 3]
    ls.append('%d %d' % (x, y))

# a http service which calls the finder above
resp = requests.post('http://xxx', data={'input': '\n'.join(ls)})
r.recvuntil('key guess (hex): ')
if len(resp.text):
    r.sendline(bytes(map(int, resp.text.split())).hex())
else:
    r.sendline('0' * 8)
open('log.txt', 'ab').write(r.recvall())
```

# pressure

In this loop, when $k=1$, `hsh(b'1')` is always added to `s`:

```python
for k in range(1, CONST):
  s.add(hsh(bytes(str(k + CONST * (r % k)).strip('L').encode('utf-8'))))
```

So we can guess which one is `hsh(b'1')` in part 2, and send `2*hsh(b'1')`, `3*hsh(b'1')`, ..., to the server. The success probability is at least $\frac 1{4096+256}$.

```python
from nacl.bindings.crypto_scalarmult import (
  crypto_scalarmult_ed25519_noclamp,
  crypto_scalarmult_ed25519_base_noclamp,
)
from nacl.bindings.crypto_core import (
  crypto_core_ed25519_scalar_reduce,
)
from pwn import *
from ast import literal_eval
import random, hashlib


def sha512(b):
  return hashlib.sha512(b).digest()


def hsh(s):
  h = sha512(s)
  return crypto_scalarmult_ed25519_base_noclamp(crypto_core_ed25519_scalar_reduce(h))


r = process(['python', 'server.py'])
r.recvuntil(b'Send your data!\n')
r.sendline(b'[]')
r.recvuntil(b'Let\'s see if we share anything! I\'ll be the initiator this time.\n')
tc = literal_eval(r.recvline().decode().strip())
guess = random.choice(tc)
raw = hsh(b'1')
a = []
b = []
for i in range(2, len(tc) + 2):
    a.append(crypto_scalarmult_ed25519_noclamp(i.to_bytes(32, 'little'), raw))
    b.append(crypto_scalarmult_ed25519_noclamp(i.to_bytes(32, 'little'), guess))
r.recvuntil(b'Send client points: \n')
r.sendline(repr(a).encode())
r.recvuntil(b'Send masked server points: \n')
r.sendline(repr(b).encode())
res = r.recvline()
if res != b"Aw, we don't share anything.\n":
    open('res.txt', 'ab').write(res)
```