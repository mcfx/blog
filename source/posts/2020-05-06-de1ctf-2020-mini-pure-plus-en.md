title: "De1CTF 2020 Mini Purε Plus Writeup (English)"
tags:
  - CTF
  - Writeup
#! meta end

First I searched Mini Purε, and checked the official writeup of De1CTF2019. In that problem, we randomly select the key of last round, and use interpolation to check it.

Let the message be $(C,x)$, after 15 rounds, it becomes $(F(x),G(x))$, where $F$ is a polynomial of degree about $3^{14}$. If we still enumerate the key and then check, the time complexity is about $O(3^{42})$, which is too high.

Suppose there's some polynomial $f$, and the degree of $f$ is less than $k$, and we are given $f(0),f(1),\dots,f(k)$. Now consider the formula of Lagrange interpolation:

$$
f(x)=\sum_{j=0}^k f(j)\prod_{i=0,i\neq j}^k\frac{x\oplus i}{j\oplus i}
$$

It's difficult to compute in most cases, but if $k+1=2^p$ for some $p$, it become easier.

We have

$$
\prod_{i=0,i\neq j}^k{x_j\oplus x_i}=\prod_{i=1}^{k}i
$$

(Consider removing the constraint $i\neq j$, then $0,1,\dots,k$ all occurs in the left side)

Let $A=\prod_{i=1}^{k}i,B=\prod_{i=0}^{k}x\oplus i$, then

$$
f(x)=\sum_{j=0}^k f(j)\frac{B}{A\cdot(x\oplus j)}
$$

Since $A,B$ can be computed in $O(k)$ time and the inverse of $x\oplus j$ can be precalculated in $O(k)$ time, $f(x)$ can be calculated in $O(k)$ time.

For the polynomial $F$ that I mentioned at the start of this writeup, $F(x)$ is a cubic polynomial in $\text{key}[15]$. Let $k=2^{23}-1,x=2^{23}$, by the equation above, we can find a cubic equation of $\text{key}[15]$. It's easy to solve, and then we can find $\text{key}[2],\dots,\text{key}[14]$ by the same method.

See code in [Chinese version writeup](/archives/284/#Mini%20Pur%CE%B5%20Plus)
