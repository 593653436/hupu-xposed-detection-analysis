# 网易易盾（NetEase YiDun）防护机制 —— 公开技术资料摘录

来源：[AWAKE wiki — NetEase YiDun](https://awakewiki.org/packers/netease-yidun/)
（原文为第三方研究资料，此处仅为摘录与对照，供本项目定位使用。）

---

## 一、产品区分（重要）

易盾有两套产品，虎扑用的是**前者**：

| | **App Packer**（虎扑用的） | SDK Reinforcement (NIS) |
|---|---|---|
| 包名 | **`com.netease.nis.wrapper`** | `com.netease.nis.sdkwrapper` |
| 入口类 | **`Entry`, `MyJni`, `MyApplication`** | `Utils`（native 方法 `rL()`, `rD()`） |
| 原生库 | **`libnesec.so`** | `libsecsdk.so` |
| 机制 | **加密整个 `classes.dex`，运行时加载** | 把单个 Java 方法体编译成原生 AArch64 |
| 资源 | `nedata.db`, `nedig.properties` | 随机命名的加密文件 |

**与我们的实测完全一致**：空壳类 `com.netease.nis.wrapper.*`、版本串 `7.6.3_943`、
`.cache/classes.dex` 运行时解密、`libnesec.so`。

App Packer 的防护要点（原文）：
- DEX 加密（多密钥方案）
- **反调试与反 hook**
- 原生库完整性校验
- **内存保护（对已解密区域做 `mprotect`）**

---

## 二、⭐ 为什么 GOT 补丁打不中 —— 官网文献直接给出了答案

> **Raw-syscall mprotect (no PLT import)**
>
> "To write into the read-execute method-body section, NIS needs `mprotect(…, PROT_WRITE)`.
> Importing `mprotect` via the normal PLT path would put the function in the library's import
> table — a near-universal unpacker tell. NIS issues `mprotect` as a **raw syscall** instead."
>
> "**The same trick is used for `openat` (56) and `close` (57): the library reads
> `/proc/self/maps` and `/proc/self/task/*/status` via raw syscalls, so hooks on libc's
> `open`/`read`/`fopen` see no traffic.**"
>
> "The raw-syscall thunks are reached only via function pointer, never by direct `bl`."

**结论：**
1. 易盾用**内联 `svc #0`** 直接发系统调用，**完全绕开 libc 与 PLT** →
   **任何 GOT/PLT 补丁都不可能命中**。这解释了我们 xhook 方案全部落空。
2. 这也**证明 seccomp 是唯一正确的切入点**——它工作在系统调用边界，躲不开。

---

## 三、⭐ Tripwires（绊线）——四条判定通道

| 绊线 | 机制 | 原文给出的化解方向 |
|---|---|---|
| **Map scan** | 原始系统调用 `openat("/proc/self/maps")`，遍历查找插桩特征串（`frida-agent`、`re.frida.server`、`libsubstrate`） | **隐藏模块名** |
| **Thread-name scan** | 遍历 **`/proc/self/task/*/status`**，匹配 `Name:` 行（`gum-js-loop`、`linjector`） | 改掉可疑线程名 |
| **Module walk** | **`dl_iterate_phdr` 枚举已加载的共享对象** | **隐藏注入的模块** |
| **Signal tripwires** | `sigaction` 安装处理器，故障时 **`raise(SIGKILL)`** | **soft-hook `sigaction`，把 SIGILL(4)、SIGTRAP(5)、SIGBUS(7)、SIGSEGV(11) 四个全部置空——少一个都会留一条自毁路径** |

关于绊线激活时机（原文）：

> "**The tripwires arm within the first few hundred milliseconds of process start.**
> Late-attach almost always fails — the library spots the instrumentation at the next scan,
> installs an unavoidable `SIGKILL` pending signal, and the process dies on the next context switch."

**与我们实测的"约 200 毫秒被杀"完全吻合。**

### 对照我们已完成的工作

| 通道 | 我们是否覆盖 | 说明 |
|---|---|---|
| Map scan（`/proc/self/maps`） | ✅ 已用 seccomp + ADDFD 伪造（删掉 7 条匿名可执行/memfd 映射） | 但**监听端存在未应答通知导致卡死**，读数不可信 |
| Thread-name scan（`/proc/self/task/*/status`） | ❌ **完全未覆盖** | 我们的伪造只匹配了 maps 路径 |
| Module walk（`dl_iterate_phdr`） | ❌ **完全未覆盖** | 这**不是系统调用**，seccomp 拦不到，需另想办法 |
| Signal tripwires（`sigaction`） | ⚠️ 部分 | 我们做过 seccomp 精确拦 `rt_sigaction(SIGILL)`，但没覆盖 SIGTRAP/SIGBUS/SIGSEGV |

**这解释了"伪造 maps 后应用仍不前进"**——还有两条独立通道在起作用，
其中 `dl_iterate_phdr` 甚至不在我们的武器射程内。

---

## 四、App Packer 的脱壳思路（原文，供参考）

原文给出的 App Packer 脱壳法是 **hook `mprotect`**，阻止它把已解密 DEX 的内存页设为不可读：

```javascript
Interceptor.attach(Module.findExportByName("libc.so", "mprotect"), {
    onEnter: function(args) {
        if (args[2].toInt32() === 0) {   // PROT_NONE
            args[2] = ptr(1);            // 改成 PROT_READ
        }
    }
});
```

然后用 `frida-dexdump` 扫描可读内存里的 DEX 头。**注意**：这条针对的是"脱壳"，
不是我们要解决的"绕过 Xposed 检测"。

---

## 五、给本项目的直接启示

1. **不要再在 GOT/PLT 上花时间** —— 已被文献和实测双重否证。
2. **seccomp 方向是对的**，但必须：
   - 先修好监听端的健壮性（保证每个通知都被应答，否则死锁）
   - 把伪造路径从 `/proc/self/maps` **扩展到 `/proc/self/task/*/status`**
3. **`dl_iterate_phdr` 是新的、且 seccomp 覆盖不到的通道** —— 需要用
   hook `dl_iterate_phdr`（inline hook，因为易盾可能通过函数指针调用）或
   直接在模块列表上做手脚。
4. **信号绊线要四个信号一起处理**（SIGILL/SIGTRAP/SIGBUS/SIGSEGV），
   只处理一个会留下自毁路径。
