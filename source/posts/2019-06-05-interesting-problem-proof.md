title: "一个有趣的问题的（部分）证明"
tags:
  - 算法
url: /archives/265/
#! meta end

http://ljt12138.blog.uoj.ac/blog/5059

对于第二个问题，当 $n\ge 8$ 时，可以如下构造：

对于 $1$ 的个数为偶数和奇数的两种数，按 $1$ 的个数从小到大，其次大小从大到小排序。$p$ 个人在偶数堆中从前向后选，$q$ 个人在奇数堆中从后向前选。

显然只需要验证 $p+q=\lfloor\frac{2^n}{3}\rfloor$ 且 $\max(p,q)\le 2^{n-2}$ 的正确性。

用程序可以容易的证明 $n$ 较小情况的正确性（[https://paste.ubuntu.com/p/XndFcftKF9/](https://paste.ubuntu.com/p/XndFcftKF9/)）。

设 $p$ 个人中最后一个选择的数 $x$ 的 $1$ 的个数为 $i$，$q$ 个人中最后选择的数 $y$ 的 $1$ 的个数为 $j$，那么显然 $j>i$。

当 $j>i+2$ 时，显然不会有数相邻；而 $j=i+1$ 时，只要证明 $x>y$，那么 $y$ 去掉某个 $1$ 之后一定比 $x$ 小，也就证明了不可能有两个数相邻。

只要预处理组合数，就可以在 $O(n)$ 时间内知道某个 $x$ 对应的 $y$，然后再找到比这个 $y$ 小的最大的 $x$，这样不停迭代，最终就可以验证这个的正确性（[https://paste.ubuntu.com/p/gHmTyZbvGr/](https://paste.ubuntu.com/p/gHmTyZbvGr/)）。
