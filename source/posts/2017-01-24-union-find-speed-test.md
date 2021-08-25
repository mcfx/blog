title: "对于各种并查集写法速度的研究"
tags:
  - 并查集
url: /archives/176/
#! meta end

最快的写法是：while 非递归+按秩合并+秩和 fa 记在一个数组上，当 N 较小时秩选用 size，当 N 较大时秩选用 depth。  
当不方便非递归时可以写递归的。
inline 似乎没有明显优化。

#! head end

2018.3.3：更新了测试代码，加入了更多写法，修复了一些致命错误。

测试机 CPU 为 Intel® Celeron® Processor G3900，内存为 8GB DDR4，系统为 Debian 9。

编译命令为 `g++ test.cpp -o test -O3`。

先放测试代码：

```c++
#include<cstdio>
#include<ctime>
#include<random>
#include<cassert>
#define N 1024
#define T 100000
int fa[N+233],st[N+233],sz[N+233];
int find1(int x)
{
	return x==fa[x]?x:fa[x]=find1(fa[x]);
}
inline int find2(int x)
{
	return x==fa[x]?x:fa[x]=find2(fa[x]);
}
inline int find3(int x)
{
	while(x!=fa[x])x=fa[x]=fa[fa[x]];return x;
}
inline int find4(int x)
{
	int se=0;st[0]=x;
	while(fa[x]!=x)st[++se]=x=fa[x];
	while(se)fa[st[--se]]=x;
	return x;
}
inline int find5(int x)
{
	int t=x,p;
	while(x!=fa[x])x=fa[x];
	while(t!=x)p=fa[t],fa[t]=x,t=p;
	return x;
}
int find6(int x)
{
	return 0>fa[x]?x:fa[x]=find6(fa[x]);
}
inline int find7(int x)
{
	return 0>fa[x]?x:fa[x]=find7(fa[x]);
}
inline int find8(int x)
{
	while(fa[x]>=0&&fa[fa[x]]>=0)x=fa[x]=fa[fa[x]];return fa[x]<0?x:fa[x];
}
long long global_checksum;
unsigned int count,seed;
std::mt19937 ran_(0);
void init_rand(int x)
{
	ran_=std::mt19937(x);
	ran_(),ran_(),ran_();
	count=0;
}
int rand()
{
	if(count&1023)seed=ran_();
	count++;
	seed^=seed<<13;
	seed^=seed>>17;
	seed^=seed<<5;
	return seed;
}
inline long long test(int(*f)(int))
{
	init_rand(19260817);
	long long last,timeusage=0,checksum=0;
	for(int t=0;t<T;t++)
	{
		for(int i=0;i<N;i++)fa[i]=i;
		last=clock();
		for(int i=0,x,y;i<N;i++)
		{
			x=rand(),y=rand();
			x&=N-1,y&=N-1;
			x=f(x),y=f(y);
			if(x!=y)fa[x]=y;
		}
		timeusage+=clock()-last;
		for(int i=0;i<N;i++)checksum=checksum*998244353+(f(i)==f(0));
	}
	assert(global_checksum==checksum||global_checksum==0);
	global_checksum=checksum;
	return timeusage;
}
inline long long test2(int(*f)(int))
{
	init_rand(19260817);
	long long last,timeusage=0,checksum=0;
	for(int t=0;t<T;t++)
	{
		for(int i=0;i<N;i++)fa[i]=i;
		for(int i=0;i<N;i++)sz[i]=1;
		last=clock();
		for(int i=0,x,y;i<N;i++)
		{
			x=rand(),y=rand();
			x&=N-1,y&=N-1;
			x=f(x),y=f(y);
			if(x!=y){if(sz[x]>sz[y])sz[x]+=sz[y],fa[y]=x;else sz[y]+=sz[x],fa[x]=y;}
		}
		timeusage+=clock()-last;
		for(int i=0;i<N;i++)checksum=checksum*998244353+(f(i)==f(0));
	}
	assert(global_checksum==checksum||global_checksum==0);
	global_checksum=checksum;
	return timeusage;
}
inline long long test3(int(*f)(int))
{
	init_rand(19260817);
	long long last,timeusage=0,checksum=0;
	for(int t=0;t<T;t++)
	{
		for(int i=0;i<N;i++)fa[i]=-1;
		last=clock();
		for(int i=0,x,y;i<N;i++)
		{
			x=rand(),y=rand();
			x&=N-1,y&=N-1;
			x=f(x),y=f(y);
			if(x!=y){if(fa[x]<fa[y])fa[x]+=fa[y],fa[y]=x;else fa[y]+=fa[x],fa[x]=y;}
		}
		timeusage+=clock()-last;
		for(int i=0;i<N;i++)checksum=checksum*998244353+(f(i)==f(0));
	}
	assert(global_checksum==checksum||global_checksum==0);
	global_checksum=checksum;
	return timeusage;
}
inline long long test2_1(int(*f)(int))
{
	init_rand(19260817);
	long long last,timeusage=0,checksum=0;
	for(int t=0;t<T;t++)
	{
		for(int i=0;i<N;i++)fa[i]=i;
		for(int i=0;i<N;i++)sz[i]=1;
		last=clock();
		for(int i=0,x,y;i<N;i++)
		{
			x=rand(),y=rand();
			x&=N-1,y&=N-1;
			x=f(x),y=f(y);
			if(x!=y){if(sz[x]>sz[y])fa[y]=x;else{fa[x]=y;if(sz[x]==sz[y])sz[y]++;}}
		}
		timeusage+=clock()-last;
		for(int i=0;i<N;i++)checksum=checksum*998244353+(f(i)==f(0));
	}
	assert(global_checksum==checksum||global_checksum==0);
	global_checksum=checksum;
	return timeusage;
}
inline long long test3_1(int(*f)(int))
{
	init_rand(19260817);
	long long last,timeusage=0,checksum=0;
	for(int t=0;t<T;t++)
	{
		for(int i=0;i<N;i++)fa[i]=-1;
		last=clock();
		for(int i=0,x,y;i<N;i++)
		{
			x=rand(),y=rand();
			x&=N-1,y&=N-1;
			x=f(x),y=f(y);
			if(x!=y){if(fa[x]<fa[y])fa[y]=x;else{if(fa[x]==fa[y])fa[y]--;fa[x]=y;}}
		}
		timeusage+=clock()-last;
		for(int i=0;i<N;i++)checksum=checksum*998244353+(f(i)==f(0));
	}
	assert(global_checksum==checksum||global_checksum==0);
	global_checksum=checksum;
	return timeusage;
}
int main()
{
	printf("CLOCKS_PER_SEC:%d\n",CLOCKS_PER_SEC);
	printf("find1:%lld %lld %lld\n",test(find1),test2(find1),test2_1(find1));
	printf("find2:%lld %lld %lld\n",test(find2),test2(find2),test2_1(find2));
	printf("find3:%lld %lld %lld\n",test(find3),test2(find3),test2_1(find3));
	printf("find4:%lld %lld %lld\n",test(find4),test2(find4),test2_1(find4));
	printf("find5:%lld %lld %lld\n",test(find5),test2(find5),test2_1(find5));
	printf("find6:%lld %lld\n",test3(find6),test3_1(find6));
	printf("find7:%lld %lld\n",test3(find7),test3_1(find7));
	printf("find8:%lld %lld\n",test3(find8),test3_1(find8));
}
```

当 N=1024,T=500000 时，输出：

```
find1:20089351 15887467 16531550
find2:20097390 15910071 16540963
find3:17256541 13390076 13982165
find4:19644034 15645215 16138683
find5:19427605 15368866 15878426
find6:15846219 16573551
find7:15818575 16527184
find8:14988614 15839679
```

当 N=131072,T=5000 时，输出：

```
CLOCKS_PER_SEC:1000000
find1:40043295 28478678 29630797
find2:40079319 28487803 29605407
find3:34651392 23403124 24607184
find4:40438077 27544080 28666981
find5:39498635 26400323 27404284
find6:25862629 26859295
find7:25814962 26853594
find8:24541376 25698358
```

当 N=2097152,T=500 时，输出：

```
CLOCKS_PER_SEC:1000000
find1:240728970 173155213 166865669
find2:240076225 173137194 166896002
find3:257240885 186958166 159086582
find4:240671337 168750996 164743633
find5:210863641 130934764 128655852
find6:107561256 107685991
find7:107630995 107676199
find8:101390000 100197421
```

当 N=16777216,T=400 时，输出：

```
CLOCKS_PER_SEC:1000000
find1:2537867344 1538207603 1438028041
find2:2542492294 1537816024 1438141065
find3:2878818361 1750536054 1388536804
find4:2497444413 1495104276 1413699601
find5:2212506256 1083761103 1015381467
find6:983906431 926941775
find7:984064763 926552621
find8:892107319 808279658
```

（原结果有误，已删）
最后得出的结果是 find8（while 非递归+按秩合并+秩和 fa 记在一个数组上）最快，当 N 较小时秩选用 size，当 N 较大时秩选用 depth。
当不方便非递归时可以写递归的（find6 或 find7）。
inline 似乎没有明显优化。
