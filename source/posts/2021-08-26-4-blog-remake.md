#! title: 如何手搓一个博客？

我的上一个博客系统是 Typecho。他本身还是能用，但是我找的 LaTex 插件工作的不是很好，而文章预览也是当时手搓的拖拉机。虽然这些问题也都能解决，但是总还是需要折腾，耗费的精力可能不比重新搞一个博客系统少。  
那么应该换什么呢？动态博客其实已经被我排除在外了，因为总会有来不及修的洞。而静态博客虽然有非常多的选择，但是选择太多反而让人不知道选啥好（另外好像也没啥横评）。  
这时经群友点拨，我决定手写一个，毕竟拿 Markdown 转 html 再套上 GitHub 的样式就（似乎）已经写完了。

#! head end

### 背景

我的上一个博客系统是 Typecho。他本身还是能用，但是我找的 LaTex 插件工作的不是很好，而文章预览也是当时手搓的拖拉机。虽然这些问题也都能解决，但是总还是需要折腾，耗费的精力可能不比重新搞一个博客系统少。  
那么应该换什么呢？动态博客其实已经被我排除在外了，因为总会有来不及修的洞。而静态博客虽然有非常多的选择，但是选择太多反而让人不知道选啥好（另外好像也没啥横评）。  
这时经群友点拨，我决定手写一个，毕竟拿 Markdown 转 html 再套上 GitHub 的样式就（似乎）已经写完了。

### 博客设计

博文我计划用 Markdown 撰写，全放在一个目录里，但其他元数据需要找个地方存储。看了看 Hexo 的实现是在子文件夹里面存放，但是我不想建子文件夹，所以得建其他文件，或者嵌入在 md 里面。经过一番考虑，最终我决定嵌入在 md 里，通过一些特定的分隔符来表示他们是元数据。

### 技术选型

那么就开工吧。语言部分，我随便选了 js（可能是因为 Hexo 等项目也用 js 吧）。Markdown 解析器，我使用了 Google 搜到的第一个——marked。LaTex 解析器，我使用了 Google 搜索“marked.js latex”的第一个结果——KaTex。把他们缝合起来的过程还是比较顺畅的。

博客系统除了文章本身，还有标题、文章列表等。为了方便的处理他们，应该需要一个模板引擎，我又随便 Google 了一下，然后决定用 ejs。这一部分需要手搓一些 html 和 css，我从[漩涡的博客](https://xuanwo.io/)中学习了一点响应式的 css，又从很久之前写的动态博客系统里抄来了翻页部分的代码。

最后还有评论。评论系统也有非常多的选择。我看到[漩涡的博客](https://xuanwo.io/)中使用的 Giscus 使用的是 GitHub 的讨论，于是决定也就用这个了。在页面末尾加了一个 script 标签就配好了。

至此，一个博客基本就写好了，完整代码可见 [mcfx/blogen](https://github.com/mcfx/blogen) 及 [mcfx/blog](https://github.com/mcfx/blog)。

### 没有实现的 feature

#### RSS

比较懒，不写了。

#### 搜索

靠搜索引擎吧。https://www.google.com/search?q=site%3Amcfx.us 请（原有链接基本都保留了）。

#### meta description & keyword

懒得搞 SEO 优化了，反正也没啥人看。

### 其他东西

由于是纯静态的，加载速度还是非常不错。

Giscus 用到了 cdnjs，国内部分地区被屏蔽了，反代并 hack 了一下让他至少能显示出第一条评论。