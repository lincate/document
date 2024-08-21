## 开篇
1. 期望目标是什么？
	1. 知道eBPF的基本原理
	2. 能够使用Go进行eBPF编程，特别是网络功能，监控功能
	3. 深入理解Cilium已经K8S网络插件
2. 对于这个已经知道了哪些？
	1. 基于内核编程
	2. 底层只能使用C
	3. 效率最高，但是有诸多限制
3. 需要重点关注是什么？
	1. 代码编写流程
	2. eBPF的底层架构
	3. 如何与用户态交互
	4. 如何具备通用性
	5. 已经有的项目如何应用
## 概念
### 什么是eBPF:
（External Berkeley Package Filter）
在内核中运行沙盒程序，用于扩展内核功能。 （内核的升级缓慢）
基本架构：
![基本架构](https://ebpf.io/static/e293240ecccb9d506587571007c36739/f093e/overview.webp)
eBPF允许以沙盒方式运行程序，可以在安全，网络，可观测性上广泛应用。
自定义的eBPF程序在通过了Verifier的验证和JIT帮助下，直接在OS层执行。

### eBPF事件
eBPF是由事件驱动的，当某个运行到某个事件时，则可以运行eBPF程序。常用的事件包括：系统调用，函数进入/退出，网络事件，内核跟踪点。
示例：
![](https://ebpf.io/static/b4f7d64d4d04806a1de60126926d5f3a/12151/syscall-hook.png)
当系统调用时,会触发进入eBPF. 除了预定义的钩子以外，则可以创建内核探针（kprobe）或用户探针（uprobe），以便在内核或用户应用程序的几乎任何位置附加 eBPF 程序。

完整事件如下:
![](https://ebpf.io/static/99c69bbff092c35b9c83f00a80fed240/b5f15/hook-overview.png)

如何编写eBPF程序呢?
通常,不会从最底层开始编写,而是用已经提供了SDKs的包的基础上进行编写,例如:bcc(基于Python), Cilium(基于Go), bpftrace(C). 各个的侧重点不一样,可根据实际需求选定.
最底层的SDKs,面向OS的依然是已C语言方式编写.
同时还有日新月异的新组件产生.查看列表: [新兴应用](https://ebpf.io/zh-hans/applications/)

eBPF期望是以字节码运行,因此需要使用LLVM的编译器将代码编译成为eBPF的字节码,如图:
![](https://ebpf.io/static/a7160cd231b062b321f2a479a4d0848f/e9739/clang.webp)
### 工具组件
#### Clang
#### llvm
### 指令集(Instruction Sets)
### 辅助函数(Helper Functions)
### 存储映射(Maps)
### 尾部调用(Tail Calls)
### BPF调用(BPF to BPF calls)
### 及时编译(JIT)
## 基本架构
### 加载器和校验架构

确定所需的钩子后，可以使用 bpf 系统调用将 eBPF 程序加载到 Linux 内核中。这通常是使用一个可用的 eBPF 库来完成的。下一节将介绍一些开发工具链。

[![Go](https://ebpf.io/static/1a1bb6f1e64b1ad5597f57dc17cf1350/b14d5/go.png)](https://ebpf.io/static/1a1bb6f1e64b1ad5597f57dc17cf1350/6515f/go.png)

当程序被加载到 Linux 内核中时，它在被附加到所请求的钩子上之前需要经过两个步骤：

### 验证

验证步骤用来确保 eBPF 程序可以安全运行。它可以验证程序是否满足几个条件，例如：

[![Loader](https://ebpf.io/static/7eec5ccd8f6fbaf055256da4910acd5a/b14d5/loader.png)](https://ebpf.io/static/7eec5ccd8f6fbaf055256da4910acd5a/b5f15/loader.png)

- 加载 eBPF 程序的进程必须有所需的能力（特权）。除非启用非特权 eBPF，否则只有特权进程可以加载 eBPF 程序。
- eBPF 程序不会崩溃或者对系统造成损害。
- eBPF 程序一定会运行至结束（即程序不会处于循环状态中，否则会阻塞进一步的处理）。

### JIT 编译

JIT (Just-in-Time) 编译步骤将程序的通用字节码转换为机器特定的指令集，用以优化程序的执行速度。这使得 eBPF 程序可以像本地编译的内核代码或作为内核模块加载的代码一样高效地运行。

### Maps

eBPF 程序的其中一个重要方面是共享和存储所收集的信息和状态的能力。为此，eBPF 程序可以利用 eBPF maps 的概念来存储和检索各种数据结构中的数据。eBPF maps 既可以从 eBPF 程序访问，也可以通过系统调用从用户空间中的应用程序访问。

[![Map architecture](https://ebpf.io/static/e7909dc59d2b139b77f901fce04f60a1/b14d5/map-architecture.png)](https://ebpf.io/static/e7909dc59d2b139b77f901fce04f60a1/ad1b4/map-architecture.png)

下面是支持的 map 类型的不完整列表，它可以帮助理解数据结构的多样性。对于各种 map 类型，共享的或 per-CPU 的变体都支持。

- 哈希表，数组
- LRU (Least Recently Used) 算法
- 环形缓冲区
- 堆栈跟踪 LPM (Longest Prefix match)算法
- ...

### Helper 调用
eBPF 程序不直接调用内核函数。这样做会将 eBPF 程序绑定到特定的内核版本，会使程序的兼容性复杂化。而对应地，eBPF 程序改为调用 helper 函数达到效果，这是内核提供的通用且稳定的 API。

[![Helper](https://ebpf.io/static/6e18b76323d8520107fab90c033edaf4/b14d5/helper.png)](https://ebpf.io/static/6e18b76323d8520107fab90c033edaf4/01295/helper.png)

可用的 helper 调用集也在不断发展迭代中。一些 helper 调用的示例:

- 生成随机数
- 获取当前时间日期
- eBPF map 访问
- 获取进程 / cgroup 上下文
- 操作网络数据包及其转发逻辑

### 尾调用和函数调用

eBPF 程序可以通过尾调用和函数调用的概念来组合。函数调用允许在 eBPF 程序内部完成定义和调用函数。尾调用可以调用和执行另一个 eBPF 程序并替换执行上下文，类似于 execve() 系统调用对常规进程的操作方式。

[![Tail call](https://ebpf.io/static/106a9d37e6b2b88e24b923d96e852dd5/b14d5/tailcall.png)](https://ebpf.io/static/106a9d37e6b2b88e24b923d96e852dd5/f39e4/tailcall.png)

### eBPF 安全

_能力越大责任越大。_

eBPF 是一项非常强大的技术，并且现在运行在许多关键软件基础设施组件的核心位置。在 eBPF 的开发过程中，当考虑将 eBPF 包含到 Linux 内核中时，eBPF 的安全性是最关键的方面。eBPF 的安全性是通过几层来保证的：

#### 需要的特权

除非启用了非特权 eBPF，否则所有打算将 eBPF 程序加载到 Linux 内核中的进程必须以特权模式 (root) 运行，或者需要授予 CAP_BPF 权限 (capability)。这意味着不受信任的程序不能加载 eBPF 程序。

如果启用了非特权 eBPF，则非特权进程可以加载某些 eBPF 程序，这些程序的功能集减少，并且对内核的访问将会受限。

#### 验证器

如果一个进程被允许加载一个 eBPF 程序，那么所有的程序仍然要通过 eBPF 验证器。eBPF 验证器确保程序本身的安全性。这意味着，例如：

- 程序必须经过验证以确保它们始终运行到完成，例如一个 eBPF 程序通常不会阻塞或永远处于循环中。eBPF 程序可能包含所谓的有界循环，但只有当验证器能够确保循环包含一个保证会变为真的退出条件时，程序才能通过验证。
- 程序不能使用任何未初始化的变量或越界访问内存。
- 程序必须符合系统的大小要求。不可能加载任意大的 eBPF 程序。
- 程序必须具有有限的复杂性。验证器将评估所有可能的执行路径，并且必须能够在配置的最高复杂性限制范围内完成分析。

验证器是一种安全工具，用于检查程序是否可以安全运行。它不是一个检查程序正在做什么的安全工具。

#### 加固

在成功完成验证后，eBPF 程序将根据程序是从特权进程还是非特权进程加载而运行一个加固过程。这一步包括：

- **程序执行保护**： 内核中保存 eBPF 程序的内存受到保护并变为只读。如果出于任何原因，无论是内核错误还是恶意操作，试图修改 eBPF 程序，内核将会崩溃，而不是允许它继续执行损坏/被操纵的程序。
- **缓解 Spectre 漏洞**： 根据推断，CPU 可能会错误地预测分支并留下可观察到的副作用，这些副作用可以通过旁路（side channel）提取。举几个例子: eBPF 程序可以屏蔽内存访问，以便在临时指令下将访问重定向到受控区域，验证器也遵循仅在推测执行（speculative execution）下可访问的程序路径，JIT 编译器在尾调用不能转换为直接调用的情况下发出 Retpoline。
- **常量盲化（Constant blinding）**：代码中的所有常量都是盲化的，以防止 JIT 喷射攻击。这可以防止攻击者将可执行代码作为常量注入，在存在另一个内核错误的情况下，这可能允许攻击者跳转到 eBPF 程序的内存部分来执行代码。

#### 抽象出来的运行时上下文

eBPF 程序不能直接访问任意内核内存。必须通过 eBPF helper 函数来访问程序上下文之外的数据和数据结构。这保证了一致的数据访问，并使任何此类访问受到 eBPF 程序的特权的约束，例如，如果可以保证修改是安全的，则允许运行的 eBPF 程序修改某些数据结构的数据。eBPF 程序不能随意修改内核中的数据结构。

### eBPF 对 Linux 内核的影响

现在让我们回到 eBPF。为了理解 eBPF 对 Linux 内核的可编程性的影响，有必要对 Linux 内核的体系结构及其与应用程序和硬件的交互方式有一个高层次的了解。

[![Kernel architecture](https://ebpf.io/static/560d57883f7df9beafb47eee1d790247/b14d5/kernel-arch.png)](https://ebpf.io/static/560d57883f7df9beafb47eee1d790247/01295/kernel-arch.png)

Linux 内核的主要目的是对硬件或虚拟硬件进行抽象，并提供一致的 API（系统调用），允许应用程序运行和共享资源。为了实现这一点，内核维护了一组广泛的子系统和层来分配这些职责。每个子系统通常允许某种级别的配置，以满足用户的不同需求。如果无法配置所需的行为，则需要更改内核，从历史上看，只剩下两个选项：

### 原生支持

1. 更改内核源代码并使 Linux 内核社区相信改动是有必要的。
2. 等待几年后，新的内核才会成为一个通用版本。

### 内核模块

1. 编写一个内核模块
2. 定期修复它，因为每个内核版本都可能破坏它
3. 由于缺乏安全边界，有可能损坏 Linux 内核

有了 eBPF，就有了一个新的选项，它允许重新编程 Linux 内核的行为，而不需要更改内核源代码或加载内核模块。在许多方面，这与 JavaScript 和其他脚本语言解锁系统演进的方式非常相像，对这些系统进行改动的原有方式已经变得困难或昂贵。

## 开发工具链

已经有几个开发工具可以帮助开发和管理 eBPF 程序。它们对应满足用户的不同需求:

#### bcc

BCC 是一个框架，它允许用户编写 python 程序，并将 eBPF 程序嵌入其中。该框架主要用于应用程序和系统的分析/跟踪等场景，其中 eBPF 程序用于收集统计数据或生成事件，而用户空间中的对应程序收集数据并以易理解的形式展示。运行 python 程序将生成 eBPF 字节码并将其加载到内核中。

[![bcc](https://ebpf.io/static/def942c66b8c7565f0cfeab1c1017a80/b14d5/bcc.png)](https://ebpf.io/static/def942c66b8c7565f0cfeab1c1017a80/c5f83/bcc.png)

#### bpftrace

bpftrace 是一种用于 Linux eBPF 的高级跟踪语言，可在较新的 Linux 内核（4.x）中使用。bpftrace 使用 LLVM 作为后端，将脚本编译为 eBPF 字节码，并利用 BCC 与 Linux eBPF 子系统以及现有的 Linux 跟踪功能（内核动态跟踪（kprobes）、用户级动态跟踪（uprobes）和跟踪点）进行交互。bpftrace 语言的灵感来自于 awk、C 和之前的跟踪程序，如 DTrace 和 SystemTap。

[![bpftrace](https://ebpf.io/static/c53dfcbff6ea67a8f00896bd76e4c07c/b14d5/bpftrace.png)](https://ebpf.io/static/c53dfcbff6ea67a8f00896bd76e4c07c/c5f83/bpftrace.png)

#### eBPF Go 语言库

eBPF Go 语言库提供了一个通用的 eBPF 库，它将获取 eBPF 字节码的过程与 eBPF 程序的加载和管理进行了解耦。eBPF 程序通常是通过编写高级语言，然后使用 clang/LLVM 编译器编译成 eBPF 字节码来创建的。

[![Go](https://ebpf.io/static/1a1bb6f1e64b1ad5597f57dc17cf1350/b14d5/go.png)](https://ebpf.io/static/1a1bb6f1e64b1ad5597f57dc17cf1350/6515f/go.png)

#### libbpf C/C++ 库

libbpf 库是一个基于 C/ c++ 的通用 eBPF 库，它可以帮助解耦将 clang/LLVM 编译器生成的 eBPF 对象文件的加载到内核中的这个过程，并通过为应用程序提供易于使用的库 API 来抽象与 BPF 系统调用的交互。

[![Libbpf](https://ebpf.io/static/f4991ee40f74df260dbb3e0541855044/b14d5/libbpf.png)](https://ebpf.io/static/f4991ee40f74df260dbb3e0541855044/b990c/libbpf.png)


[阅读清单](https://blog.csdn.net/21cnbao/article/details/95585483)
https://segmentfault.com/a/1190000044635034
https://tonybai.com/2022/07/19/develop-ebpf-program-in-go/
https://cheneytianx.github.io/posts/2022/02/
https://docs.kernel.org/bpf/libbpf/program_types.html
https://www.slideshare.net/slideshow/bpf-tracing-and-more/71128334#19
https://man7.org/linux/man-pages/man7/bpf-helpers.7.html
https://time.geekbang.org/column/article/483364
https://elixir.bootlin.com/linux/v5.10.163/source/include/uapi/linux/bpf.h

略窥门径

## Map类型
https://blog.spoock.com/2024/01/23/eBPF-Map/
enum bpf_map_type  
{  
	BPF_MAP_TYPE_UNSPEC,  
	BPF_MAP_TYPE_HASH,  
	BPF_MAP_TYPE_ARRAY,  
	BPF_MAP_TYPE_PROG_ARRAY,  
	BPF_MAP_TYPE_PERF_EVENT_ARRAY,  
	BPF_MAP_TYPE_PERCPU_HASH,  
	BPF_MAP_TYPE_PERCPU_ARRAY,  
	BPF_MAP_TYPE_STACK_TRACE,  
	BPF_MAP_TYPE_CGROUP_ARRAY,  
	BPF_MAP_TYPE_LRU_HASH,  
	BPF_MAP_TYPE_LRU_PERCPU_HASH,  
	BPF_MAP_TYPE_LPM_TRIE,  
	BPF_MAP_TYPE_ARRAY_OF_MAPS,  
	BPF_MAP_TYPE_HASH_OF_MAPS,  
	BPF_MAP_TYPE_DEVMAP,  
	BPF_MAP_TYPE_SOCKMAP,  
	BPF_MAP_TYPE_CPUMAP,  
};

不同类型的参数传递；
普通事件使用上下文
网络事件使用__sk_buff

在用户面能否使用指针直接获取变量值

`__attribute__((preserve_access_index))`是一个GCC特定的属性，用于保留结构体成员的访问索引，以便在内核代码中可以通过索引访问结构体成员，而不需要显式地指定成员名称。
`__attribute__((unused))`是GCC编译器的一个属性，用于标记一个变量、函数或类型声明为未使用。编译器在编译时会忽略这些标记为未使用的代码，以避免产生未使用代码的警告。

具体来说，`__attribute__((unused))`可以用于以下几种情况：

1. **变量声明**：标记为未使用的变量声明，编译器不会产生未使用变量的警告。
2. **函数声明**：标记为未使用的函数声明，编译器不会产生未使用函数的警告。
3. **类型声明**：标记为未使用的类型声明，编译器不会产生未使用类型的警告。



BPF_MAP_TYPE_RINGBUF
场景一：更高效、保证事件顺序地往用户空间发送数据
替代 perf event array

BTF工具集安装
https://blog.csdn.net/qq_53928256/article/details/129737658

2024/08/19 18:08:11 loading objects: field TcDropTcp: program tc_drop_tcp: load program: permission denied: R1 type=ctx expected=fp
其中 R1 type=ctx expected=fp 说的是，验证器期望 R1 的类型是 fp 而不是 ctx 。 所谓的 fp 指的是栈上的指针类型，即期望 R1 是栈上的数据而不是 ctx 。

升级WSL内核版本：
https://learn.microsoft.com/en-us/community/content/wsl-user-msft-kernel-v6

升级内核
https://rbconnect.eu/kb/wsl2-kernel-v6-howto-for-windows-11/


www.exception.site