title: "第五空间 2021 Random Block Cipher"
tags:
  - CTF
  - Writeup
  - Crypto
  - 差分攻击
#! meta end

虽然在“人工智能”分类，但是其实并不需要炼丹……

#! head end

#! toc 目录

本次第五空间有一个“人工智能”分类，但是里面却是一道 Crypto 题目。队友搜索到了 https://www.cryptool.org/assets/posts/2019-11-05-20-years-cryptool-looking-back-and-forward/CT20years_DeepLearningSpeck.pdf 这个用人工智能分析块密码的 slide，但是我看到本题觉得用普通的差分攻击就能做，于是没考虑人工智能相关的东西。

本题下发文件可以在 [这里](old_uploads/5space2021_random_block_cipher.zip) 下载。

### 加密流程分析

`task.py` 中，实现了一个块密码，其中有一个 sbox，4 个 pbox，而明密文长度固定为 8 字节。main 函数每局会随机生成 sbox 和 pbox，给出这两个 box，在 1~4 中随机选择一个轮数，然后我们需要对他进行选择明文攻击，如果每局都解出某个随机密文对应的明文就赢了。

首先查看 encrypt 函数，主要部分如下：

```python
for i in range(self.r):
    L, R = R, L ^ BlockCipher.F(self.sbox, self.pbox[i], R ^ self.subkeys[i])
```

这里面调用到的三个主要函数如下：

```python
@staticmethod
def F(sbox,pbox,x):
    x = BlockCipher.S(sbox,x)
    x = BlockCipher.P(pbox,x)
    return x

@staticmethod
def S(sbox,x):
    B = [(x >> 24) & 0xff,(x >> 16) & 0xff,(x >> 8) & 0xff,x & 0xff]
    B = [sbox[i] for i in B]
    return (B[0] << 24) | (B[1] << 16) | (B[2] << 8) | B[3]

@staticmethod
def P(pbox,x):
    x = [int(i) for i in bin(x)[2:].rjust(32,"0")]
    result = 0
    for i in range(len(x)):
        if x[i] == 1:
            result |= 1 << pbox[i]
            return result
```

可以发现，S 函数是把每个字节过一遍 sbox，P 函数是把 32 bit 按 pbox[i] shuffle。

### 1~2 轮的攻击

为方便起见，定义 $S(x),P_i(x),F_i(x)$ 为代码中对应的函数（$i\in [0,3]$ 为使用的 pbox 编号，也即轮数），同时定义 $RS(x)=S^{-1}$，$RP_i,RF_i$ 同理。为了简化表述，把 $F_i(x\oplus key_i)$ 记作 $enc_i(x)$。

设初始时加密状态为 $(L,R)$，则一轮之后为 $(L_1,R_1)=(R,L\oplus enc_0(R))$，两轮之后为 $(L_2,R_2)=(L\oplus enc_0(R),R\oplus enc_1(L\oplus enc_0(R)))$。

可以解得 $key_0=RF_0(L_2\oplus L)\oplus R$。（$key_2$ 也可直接解出）

### 3 轮的攻击

$$
(L_3,R_3)=(R\oplus enc_1(L\oplus enc_0(R)),L\oplus enc_0(R)\oplus enc_2(R\oplus enc_1(L\oplus enc_0(R))))
$$

令 $a=RF_1(L_3\oplus R)\oplus L=enc_0(R)\oplus key_1$。

假设我们用两组 $(L,R),(L',R')$ 得到了 $a,a'$，那么 $a\oplus a'=enc_0(R)\oplus enc_0(R')$。

令 $b=RP_0(a\oplus a')$，则 $b=S(R\oplus key_0)\oplus S(R'\oplus key_0)$。

$b$ 的每个字节均满足 $byte_i(b)=sbox[byte_i(R\oplus key_0)]\oplus sbox[byte_i(R'\oplus key_0)]$，可以枚举 $key_0$ 的该字节，得到可能的 $key_0$ 选择。

取三组 $(L,R)$，两两如上操作，即可将 $key_0$ 求出，之后不难求出 $key_1$ 和 $key_2$。

### 4 轮的攻击

$$
(L_4,R_4)=(L\oplus enc_0(R)\oplus enc_2(R\oplus enc_1(L\oplus enc_0(R))),\\
R\oplus enc_1(L\oplus enc_0(R))\oplus enc_3(L\oplus enc_0(R)\oplus enc_2(R\oplus enc_1(L\oplus enc_0(R)))))
$$

令 $c=enc_0(R),d=R\oplus key_2,e=key_1\oplus enc_0(R)$，则

$$
\begin{align*}
L_4&=L\oplus enc_0(R)\oplus F_2(R\oplus key_2\oplus F_1(L\oplus key_1\oplus enc_0(R)))\\
&=L\oplus c\oplus F_2(d\oplus F_1(L\oplus e))
\end{align*}
$$

假设我们取两组 $(L,R),(L',R')$ 得到 $L_4,L_4'$，令

$f=RP_2(L_4\oplus L_4'\oplus L\oplus L')=S(d\oplus F_1(L\oplus e))\oplus S(d\oplus F_1(L'\oplus e))$。

$g=d\oplus F_1(L\oplus e),g'=d\oplus F_1(L'\oplus e)$

枚举 $e$ 的某个字节 $byte_i(e)$，我们控制 $L$ 和 $L'$ 仅在这个字节不同，则可以求出 $F_1(L\oplus e)\oplus F_1(L'\oplus e)$，令这个值为 $h$，则 $g\oplus g'=h$。

现在问题是，如何知道 $byte_i(e)$ 的的正确性。

我们可以再枚举 $g$ 的某个字节 $byte_j(g)$，那么可以得到 $byte_j(S(g)\oplus S(g\oplus h))$。注意到这个表达式即为 $f$，于是 $byte_i(e)$ 正确仅当 $\forall j\in[0,4],\exists\ byte_j(g)\ \text{s.t.}\ byte_j(S(g)\oplus S(g\oplus h))=byte_j(f)$。

由于这不是充要条件，我们需要固定 $L$，多取几组 $L'$，让解唯一。

由此可以得到 $e$。我们可以用相同的办法处理 $e$ 对 $g$ 的约束，从而得到 $g$。

最后

$$
\begin{align*}
key_0&=RF_0(F_2(g)\oplus L)\oplus R\\
key_1&=e\oplus F_0(key_0\oplus R)\\
key_2&=F_1(L\oplus e)\oplus g\oplus R
\end{align*}
$$

$key_3$ 则直接反推即可。

这个方法共需要 $4\cdot C$ 次选择明文，$C$ 是前面取的 $L'$ 数量。之后的枚举次数是 $(4\cdot 256)^2\cdot C$，非常快，不需要担心时限问题。

### 其他细节

题目中每次的轮数是随机的，但是并没有告诉我们，于是我们需要保证，对于 $r$ 轮，选择的明文包含了 $r-1$ 轮的。

1~2 轮的攻击均只需要一条明密文对就能解出 $key$，但是 2 轮的攻击还需要一条来验证他确实是两轮。

3 轮的攻击共需要 3 条明密文对，可以再加一条用来验证。让 1~2 轮的攻击使用其中前两条即可。

4 轮的攻击完全不缺次数，于是就无所谓了。

### 代码

Python 交互代码：

```python
import string
from pwn import *
from ast import literal_eval
from hashlib import sha256

context.log_level = 'debug'

#r = process(['python', 't.py'])
r = remote('114.115.154.39', 9998)

r.recvuntil('XXXX+')
suffix = r.recv(16)
r.recvuntil('== ')
hs = bytes.fromhex(r.recv(64).decode())
chars = string.ascii_letters + string.digits
ans = None
for a in chars:
    if ans is not None:
        continue
    for b in chars:
        for c in chars:
            for d in chars:
                t = a + b + c + d
                if sha256(t.encode() + suffix).digest() == hs:
                    ans = t
r.sendline(ans)

for _ in range(4):
    r.recvuntil('[*] Challenge')
    r.recvline()
    r.recvuntil('[*] The sbox is : ')
    sbox = r.recvline()
    r.recvuntil('[*] The pbox is : ')
    pbox = r.recvline()
    open('box.txt', 'wb').write(sbox + pbox)
    sbox = literal_eval(sbox.decode())
    pbox = literal_eval(pbox.decode())
    r.recvuntil('[*] The randomCipher is : ')
    cipher = bytes.fromhex(r.recvline().decode())
    solver = process('./a')
    while True:
        a = solver.recvline().decode().split()
        if a[0] == 'keys':
            break
        a, b = int(a[0]), int(a[1])
        r.sendline((a.to_bytes(4, 'big') + b.to_bytes(4, 'big')).hex())
        r.recvuntil('[*] The cipher is : ')
        tc = bytes.fromhex(r.recvline().decode())
        solver.sendline('%d %d' % (int.from_bytes(tc[:4], 'big'), int.from_bytes(tc[4:], 'big')))
    solver.sendline('%d %d' % (int.from_bytes(cipher[:4], 'big'), int.from_bytes(cipher[4:], 'big')))
    a, b = map(int, solver.recvline().decode().split())
    r.sendline((a.to_bytes(4, 'big') + b.to_bytes(4, 'big')).hex())
r.interactive()
```

C++ 攻击代码：（用了 OI 板子，没有注释，建议对照前面观看（虽然变量名和前面讲解部分不同））

```cpp
#include<bits/stdc++.h>
#ifdef __SIZEOF_INT128__
typedef __uint128_t ulll;typedef __int128_t lll;
#define Fr128 I Fr&OP,(lll&x){RX;if(f)x=-x;RT}I OP lll(){lll x;TR}I Fr&OP,(ulll&x){RU;RT}I OP ulll(){ulll x;TR}
#define Fw128 I Fw&OP,(lll x){WI(39,ulll);RT}I Fw&OP,(ulll x){WU(39);RT}
#else
#define Fr128
#define Fw128
#endif
#define xx first
#define yy second
#define mp(a,b)std::make_pair(a,b)
#define pb push_back
#define I __attribute__((always_inline))inline
#define mset(a,b)memset(a,b,sizeof(a))
#define mcpy(a,b)memcpy(a,b,sizeof(a))
#define fo0(i,n)for(int i=0,i##end=n;i<i##end;i++)
#define fo1(i,n)for(int i=1,i##end=n;i<=i##end;i++)
#define fo(i,a,b)for(int i=a,i##end=b;i<=i##end;i++)
#define fd0(i,n)for(int i=(n)-1;~i;i--)
#define fd1(i,n)for(int i=n;i;i--)
#define fd(i,a,b)for(int i=a,i##end=b;i>=i##end;i--)
#define foe(i,x)for(__typeof((x).end())i=(x).begin();i!=(x).end();++i)
#define fre(i,x)for(__typeof((x).rend())i=(x).rbegin();i!=(x).rend();++i)
#define OP operator
#define RT return*this;
#define RX x=0;char t=P();while((t<48||t>57)&&t!='-')t=P();bool f=0;if(t=='-')t=P(),f=1;x=t-48;for(t=P();t>=48&&t<=57;t\
=P())x=x*10+t-48
#define RL if(t=='.'){lf u=.1;for(t=P();t>=48&&t<=57;t=P(),u*=0.1)x+=u*(t-48);}if(f)x=-x
#define RU x=0;char t=P();while(t<48||t>57)t=P();x=t-48;for(t=P();t>=48&&t<=57;t=P())x=x*10+t-48
#define TR *this,x;return x;
#define WI(S,T)if(x){if(x<0){P('-'),x=-x;if(x<0){*this,(T)x;RT}}unsigned char s[S],c=0;while(x)s[c++]=x%10+48,x/=10;\
while(c--)P(s[c]);}else P(48)
#define WL if(y){lf t=0.5;for(int i=y;i--;)t*=0.1;if(x>=0)x+=t;else x-=t,P('-');*this,(ll)(abs(x));P('.');if(x<0)x=-x;\
while(y--){x*=10;x-=floor(x*0.1)*10;P(((int)x)%10+48);}}else if(x>=0)*this,(ll)(x+0.5);else*this,(ll)(x-0.5);
#define WU(S)if(x){char s[S],c=0;while(x)s[c++]=x%10+48,x/=10;while(c--)P(s[c]);}else P(48)
typedef unsigned int uint;typedef long long ll;typedef unsigned long long ull;typedef double lf;typedef long double llf;
typedef std::pair<int,int>pii;template<typename T>T max(T a,T b){return a>b?a:b;}template<typename T>T min(T a,T b){
return a<b?a:b;}template<typename T>T abs(T a){return a>0?a:-a;}template<typename T>T sqr(T x){return x*x;}template<
typename T>bool repr(T&a,T b){return a<b?a=b,1:0;}template<typename T>bool repl(T&a,T b){return a>b?a=b,1:0;}template<
typename T>T gcd(T a,T b){T t;if(a<b){while(a){t=a;a=b%a;b=t;}return b;}else{while(b){t=b;b=a%b;a=t;}return a;}}I bool
IS(char x){return x==10||x==13||x==' ';}template<typename T>struct Fr{T P;I Fr&OP,(int&x){RX;if(f)x=-x;RT}I OP int(){int
x;TR}I Fr&OP,(ll&x){RX;if(f)x=-x;RT}I OP ll(){ll x;TR}I Fr&OP,(char&x){for(x=P();IS(x);x=P());RT}I OP char(){char x;TR}I
Fr&OP,(char*x){char t=P();for(;IS(t)&&~t;t=P());if(~t){for(;!IS(t);t=P())*x++=t;}*x++=0;RT}I Fr&OP,(lf&x){RX;RL;RT}I OP
lf(){lf x;TR}I Fr&OP,(llf&x){RX;RL;RT}I OP llf(){llf x;TR}I Fr&OP,(uint&x){RU;RT}I OP uint(){uint x;TR}I Fr&OP,(ull&x){
RU;RT}I OP ull(){ull x;TR}void file(const char*x){P.file(x);}Fr128};struct Fwp{int p;};Fwp prec(int x){return(Fwp){x};}
template<typename T>struct Fw{T P;int p;I Fw&OP,(int x){WI(10,uint);RT}I Fw&OP,(uint x){WU(10);RT}I Fw&OP,(ll x){WI(19,
ull);RT}I Fw&OP,(ull x){WU(20);RT}I Fw&OP,(char x){P(x);RT}I Fw&OP,(const char*x){while(*x)P(*x++);RT}I Fw&OP,(const Fwp
&x){p=x.p;RT}I Fw&OP,(lf x){int y=p;WL;RT}I Fw&OP()(lf x,int y){WL;RT}I Fw&OP,(llf x){int y=p;WL;RT}I Fw&OP()(llf x,int
y){WL;RT}void file(const char*x){P.file(x);}void flush(){P.flush();}Fw128};
#ifdef LOCAL
struct Cg{I char operator()(){return getchar();}void file(const char*f){freopen(f,"r",stdin);}};struct Cp{I void
operator()(char x){putchar(x);}void file(const char*f){freopen(f,"w",stdout);}void flush(){fflush(stdout);}};struct Cpr{
I void operator()(char x){fputc(x,stderr);}void file(const char*f){freopen(f,"w",stderr);}void flush(){fflush(stderr);}}
;template<typename T>struct Fd{Fw<T>*o;template<typename P>I Fd&OP,(P x){(*o),x,' ';RT;}~Fd(){(*o),'\n';}};template<
typename T>struct Fds{Fw<T>*o;template<typename P>I Fd<T>OP,(P x){(*o),x,' ';return(Fd<T>){o};}};Fw<Cpr>err;Fds<Cpr>dbg{
&err};
#else
#define BSZ 131072
struct Cg{char t[BSZ+1],*o,*e;Cg(){e=o=t+BSZ;}I char operator()(){if(o==e)t[fread(o=t,1,BSZ,stdin)]=0;return*o++;}void
file(const char*f){freopen(f,"r",stdin);}};struct Cp{char t[BSZ+1],*o,*e;Cp(){e=(o=t)+BSZ;}I void operator()(char p){if(
o==e)fwrite(o=t,1,BSZ,stdout);*o++=p;}void file(const char*f){freopen(f,"w",stdout);}void flush(){fwrite(t,1,o-t,stdout)
,o=t,fflush(stdout);}~Cp(){fwrite(t,1,o-t,stdout);}};
#endif
Fr<Cg>in;Fw<Cp>out;

template<const char*fn>struct Cgf{
	FILE*f;
	Cgf(){f=fopen(fn,"r");}
	~Cgf(){fclose(f);}
	char operator()(){return fgetc(f);}
};

typedef uint8_t u8;

struct cipher
{
	u8 sbox[256],rsbox[256],pbox[4][32];
	uint pbu[4][32],pbr[4][32];

	void set(u8 sb[256],u8 pb[4][32])
	{
		mcpy(sbox,sb),mcpy(pbox,pb);
		fo0(i,4)fo0(j,32)
		{
			pbu[i][31-j]=1u<<pbox[i][j];
			pbr[i][pbox[i][j]]=1u<<31-j;
		}
		fo0(i,256)rsbox[sbox[i]]=i;
	}

	template<const char*fn>void open()
	{
		Fr<Cgf<fn>>f;
		u8 sb[256],pb[4][32];
		fo0(i,256)sb[i]=(int)f;
		fo0(i,4)fo0(j,32)pb[i][j]=(int)f;
		set(sb,pb);
	}

	void ran(int seed)
	{
		std::mt19937 ran(seed);
		u8 sb[256],pb[4][32];
		fo0(i,256)sb[i]=i;
		std::shuffle(sb,sb+256,ran);
		fo0(i,4)
		{
			fo0(j,32)pb[i][j]=j;
			std::shuffle(pb[i],pb[i]+32,ran);
		}
		set(sb,pb);
	}

	uint S(uint x)const
	{
		return sbox[x>>24]<<24|sbox[x>>16&0xff]<<16|sbox[x>>8&0xff]<<8|sbox[x&0xff];
	}

	uint P(int rd,uint x)const
	{
		uint r=0;
		fo0(i,32)if(x>>i&1)r|=pbu[rd][i];
		return r;
	}

	uint F(uint rd,uint x)const
	{
		return P(rd,S(x));
	}

	uint RS(uint x)const
	{
		return rsbox[x>>24]<<24|rsbox[x>>16&0xff]<<16|rsbox[x>>8&0xff]<<8|rsbox[x&0xff];
	}

	uint RP(int rd,uint x)const
	{
		uint r=0;
		fo0(i,32)if(x>>i&1)r|=pbr[rd][i];
		return r;
	}

	uint RF(uint rd,uint x)const
	{
		return RS(RP(rd,x));
	}

	std::pair<uint,uint> encrypt(uint L,uint R,const uint*keys,int rounds)const
	{
		fo0(i,rounds)
		{
			uint t=L^F(i,R^keys[i]);
			L=R,R=t;
		}
		std::swap(L,R);
		return mp(L,R);
	}

	std::pair<uint,uint> decrypt(uint L,uint R,const uint*keys,int rounds)const
	{
		fd0(i,rounds)
		{
			uint t=L^F(i,R^keys[i]);
			L=R,R=t;
		}
		std::swap(L,R);
		return mp(L,R);
	}
};

typedef std::vector<std::pair<uint,uint>>ciphers;
typedef std::function<ciphers(ciphers)>encrypt_func;
//#define ERR(s) (printf("Error at %s: %s\n", __func__, s),0)
//#define OK (printf("Solved keys %s: %u %u %u %u\n", __func__, keys[0], keys[1], keys[2], keys[3]),1)
#define ERR(s) 0
#define OK 1

bool solve_1round(const cipher&c,encrypt_func f,uint*keys)
{
	ciphers a;
	a.pb(mp(0,0));
	ciphers b=f(a);
	for(auto&o:b)std::swap(o.xx,o.yy);
	if(b[0].xx)return ERR("not 1 round");
	keys[0]=c.RF(0,b[0].yy);
	fo1(i,3)keys[i]=0;
	return OK;
}

bool solve_2round(const cipher&c,encrypt_func f,uint*keys)
{
	ciphers a;
	a.pb(mp(0,0));
	a.pb(mp(0,0x1010101));
	ciphers b=f(a);
	auto u=b.back();
	for(auto&o:b)std::swap(o.xx,o.yy);
	keys[0]=c.RF(0,b[0].xx);
	keys[1]=c.RF(1,b[0].yy)^b[0].xx;
	fo(i,2,3)keys[i]=0;
	if(c.encrypt(a[1].xx,a[1].yy,keys,2)!=u)return ERR("not 2 round");
	return OK;
}

bool solve_3round(const cipher&c,encrypt_func f,uint*keys)
{
	ciphers a;
	a.pb(mp(0,0));
	a.pb(mp(0,0x1010101));
	a.pb(mp(1,0x2020202));
	ciphers b=f(a);
	for(auto&o:b)std::swap(o.xx,o.yy);

	uint e0=c.RF(1,b[0].xx^a[0].yy)^a[0].xx;
	uint e1=c.RF(1,b[1].xx^a[1].yy)^a[1].xx;
	uint e2=c.RF(1,b[2].xx^a[2].yy)^a[2].xx;
	uint sb1=c.RP(0,e0^e1),sb2=c.RP(0,e0^e2),key0=0;
	fo0(i,4)
	{
		int cnt=0;
		fo0(j,256)
		{
			bool ok1=(c.sbox[j]^c.sbox[j^1])==(sb1>>i*8&255);
			bool ok2=(c.sbox[j]^c.sbox[j^2])==(sb2>>i*8&255);
			if(ok1&&ok2)key0|=uint(j)<<i*8,cnt++;
		}
		if(!cnt)return ERR("no solution found");
		if(cnt>1)return ERR("solution not unique");
	}
	keys[0]=key0;
	keys[1]=c.F(0,key0)^e0;
	keys[2]=c.RF(2,b[0].yy^c.F(0,key0))^c.F(1,c.F(0,key0)^keys[1]);
	keys[3]=0;
	for(auto&o:b)std::swap(o.xx,o.yy);
	fo0(i,a.size())if(c.encrypt(a[i].xx,a[i].yy,keys,3)!=b[i])return ERR("not 3 round");
	return OK;
}

bool solve_4round(const cipher&c,encrypt_func f,uint*keys)
{
	const int C=3;
	ciphers a;
	a.pb(mp(0,0));
	a.pb(mp(0,0x1010101));
	a.pb(mp(1,0x2020202));
	fo0(i,4)fo1(j,C)a.pb(mp(j<<i*8,0));
	ciphers b=f(a);
	for(auto&o:b)std::swap(o.xx,o.yy);

	auto get=[&](uint x,uint y){
		fo0(i,a.size())if(a[i]==mp(x,y))return b[i];
		assert(0);
	};

	uint kt1=0,kt2=0;
	int yoc[4][256];
	mset(yoc,0);
	fo0(xp,4) // guess pos of key1
	{
		uint odiff[C];
		fo0(i,C)odiff[i]=c.RP(2,get(i+1<<xp*8,0).xx^(i+1<<xp*8)^b[0].xx);
		//fo0(i,C)out,odiff[i],' ';out,'\n';
		std::vector<int>xo;
		fo0(xv,256)
		{
			uint diff[C];
			fo0(i,C)diff[i]=c.F(1,xv<<xp*8)^c.F(1,(xv^i+1)<<xp*8);
			//fo0(i,C)out,diff[i],' ';out,'\n';
			int ok_mask=0;
			std::vector<pii>yu;
			fo0(yp,4) // guess pos of key2
			{
				fo0(yv,256)
				{
					bool flag=1;
					fo0(i,C)flag&=(c.sbox[yv]^c.sbox[yv^(diff[i]>>yp*8&255)])==(odiff[i]>>yp*8&255);
					//if(yp&&flag)dbg,xp,xv,yp,yv;
					if(flag)ok_mask|=1<<yp,yu.pb(mp(yp,yv));
				}
			}
			if(ok_mask==15)
			{
				for(pii&a:yu)yoc[a.xx][a.yy]++;
				xo.pb(xv);
			}
		}
		if(xo.size()==0)return ERR("no solution");
		if(xo.size()>1)return ERR("solution not unique");
		kt1|=uint(xo[0])<<xp*8;
	}

	fo0(i,4)
	{
		int c=0;
		fo0(j,256)if(yoc[i][j]==4)c++;
		if(c==0)return ERR("no solution");
		if(c>1)return ERR("solution not unique");
		fo0(j,256)if(yoc[i][j]==4)kt2|=uint(j)<<i*8;
	}

	keys[0]=c.RF(0,c.F(2,kt2)^b[0].xx);
	keys[1]=kt1^c.F(0,keys[0]);
	keys[2]=kt2^c.F(1,kt1);
	keys[3]=c.RF(3,c.F(1,kt1)^b[0].yy)^b[0].xx;

	for(auto&o:b)std::swap(o.xx,o.yy);
	fo0(i,a.size())if(c.encrypt(a[i].xx,a[i].yy,keys,4)!=b[i])return ERR("not 3 round");
	return OK;
}

void test_basic()
{
	cipher c;
	c.ran(1);
	std::mt19937_64 ran(2);
	uint keys[4];
	fo0(i,4)keys[i]=ran();
	fo0(_,10)
	{
		uint a=ran(),b=ran()&3;
		assert(c.RF(b,c.F(b,a))==a);
	}
	fo0(_,10)
	{
		uint a=ran(),b=ran(),n=ran()%4+1;
		auto x=c.encrypt(a,b,keys,n);
		auto y=c.decrypt(x.xx,x.yy,keys,n);
		assert(a==y.xx&&b==y.yy);
	}
}

void test_solve()
{
	cipher c;
	const int seed=11;
	c.ran(seed);
	std::mt19937_64 ran(seed+1);
	uint keys[4],rkeys[4];
	fo0(i,4)keys[i]=ran();

	auto ufunc=[&](const int rounds){
		return [c,keys,rounds](ciphers s)->ciphers{
			ciphers res;
			for(auto&o:s)res.pb(c.encrypt(o.xx,o.yy,keys,rounds));
			//out,c.S(s[0].yy^keys[0])^c.S(s[1].yy^keys[0]),'\n'; // round 3
			return res;
		};
	};

	fo0(_,10)
	{
		c.ran(seed+_);
		fo0(i,4)keys[i]=ran();
		assert(solve_1round(c,ufunc(1),rkeys)&&keys[0]==rkeys[0]);
	}

	fo0(_,10)
	{
		c.ran(seed+_);
		fo0(i,4)keys[i]=ran();
		assert(solve_2round(c,ufunc(2),rkeys)&&keys[0]==rkeys[0]&&keys[1]==rkeys[1]);
	}

	fo0(_,10)
	{
		c.ran(seed+_);
		fo0(i,4)keys[i]=ran();
		//fo0(i,4)out,keys[i],' ';out,'\n';
		assert(solve_3round(c,ufunc(3),rkeys)&&keys[0]==rkeys[0]&&keys[1]==rkeys[1]&&keys[2]==rkeys[2]);
	}

	fo0(_,10)
	{
		c.ran(seed+_);
		fo0(i,4)keys[i]=ran();
		//fo0(i,4)out,keys[i],' ';out,'\n';
		//out,'/',keys[1]^c.F(0,keys[0]),'\n';
		//out,'/',keys[2]^c.F(1,keys[1]^c.F(0,keys[0])),'\n';
		assert(solve_4round(c,ufunc(4),rkeys)&&keys[0]==rkeys[0]&&keys[1]==rkeys[1]&&keys[2]==rkeys[2]&&keys[3]==rkeys[3]);
	}
}

constexpr char boxfn[]="box.txt";

int main()
{
	//test_basic();
	//test_solve();
	cipher c;
	c.template open<boxfn>();
	std::map<std::pair<uint,uint>,std::pair<uint,uint>>known;
	auto chk=[&](std::function<bool(const cipher&,encrypt_func,uint*)>solve,int reqcnt,int rd){
		uint keys[4];
		bool ok=solve(c,[&](ciphers s){
			ciphers res;
			for(auto&o:s)
			{
				if(!known.count(o))
				{
					out,o.xx,' ',o.yy,'\n';
					out.flush();
					uint a,b;in,a,b;
					known[o]=mp(a,b);
				}
				res.pb(known[o]);
			}
			return res;
		},keys);
		if(!ok)return;
		fo0(i,reqcnt-known.size())
		{
			out,0,' ',0,'\n';
			out.flush();
			uint a,b;in,a,b;
		}
		out,"keys";
		fo0(i,4)out,' ',keys[i];
		out,'\n';
		out.flush();
		uint a,b;in,a,b;
		auto o=c.decrypt(a,b,keys,rd);
		out,o.xx,' ',o.yy,'\n';
		out.flush();
		exit(0);
	};
	chk(solve_1round,2,1);
	chk(solve_2round,2,2);
	chk(solve_3round,4,3);
	chk(solve_4round,52,4);
	assert(0);
}
```
