# 突破：易盾自毁链已拆到第三级

日期：2026-09-24（第二轮）
关联：`FINDINGS.md`（第一轮结论，其中第 8 条已被本文推翻）

**状态：目标仍未达成（虎扑界面依旧起不来），但自毁链的机制已完全查清，
前两级已被实证瓦解，第三级目标明确。**

---

## 0. 修正第一轮的一处错误结论

`FINDINGS.md` 第 8 条说：SIGILL 处理器不触发，是因为"壳用内联 `rt_sigaction`
在 trap 前沿微秒级恢复 `SIG_DFL`"。

**这是错的。** 实测：看门狗持续查询处置权，**处置权始终是我们的**（无 `SIGILL_TAKEN`）。
真正的原因是 **`rt_sigprocmask` 把 SIGILL 屏蔽掉了** —— 见下文。

---

## 1. 三个我们自己的 bug（都已修复，且每一个都曾伪装成"易盾太强"）

### 1.1 `libshadowhook.so` 进了 `DT_NEEDED`，导致模块原生库整个加载失败

```
E HupuShield: native lib NOT loaded:
  java.lang.UnsatisfiedLinkError: JNI_ERR returned from JNI_OnLoad in ".../libhupushield.so"
```

`libhupushield.so` 自己不定义 `JNI_OnLoad`，而 `dlsym(handle, "JNI_OnLoad")`
**会沿依赖链搜索** —— 于是找到了 `libshadowhook.so` 导出的那个，它返回 `JNI_ERR`，
ART 判定整个库加载失败。原生层**一行代码都没跑起来**。

**修法**：不链接，改为运行时 `dlopen`（`RTLD_NOW | RTLD_LOCAL`）+ 自解析符号；
同时自己定义一个返回 `JNI_VERSION_1_6` 的 `JNI_OnLoad` 兜底。

验证：`DT_NEEDED` 只剩 `liblog/libdl/libm/libc`；`JNI_OnLoad` 变为本库 `FUNC GLOBAL`。

### 1.2 `static const char DL_SURVEY[512][192]` —— 往只读段写

墓碑是铁证：

```
signal 11 (SIGSEGV), code 2 (SEGV_ACCERR)
#00 strncpy+24                         libc.so
#01 libhupushield.so          ← hs_dl_trampoline
#02 __dl__Z18do_dl_iterate_phdr...     linker64
#04 dl_iterate_phdr                    libdl.so
#05 libhupushield.so
#06-#10 libshadowhook.so
```

`const` 让它落进 `.rodata`（只读），而 trampoline 用 `strncpy` 往里写。
`SEGV_ACCERR` 就是"写只读页"的意思。

**症状极具误导性**：原生日志精确停在 `hook dl_iterate_phdr -> ok` 之后，
看起来完全像 ShadowHook 自锁死锁；而墓碑不会进 logcat，所以进程像是"静默死亡"。

### 1.3 seccomp 过滤 `rt_sigaction` 时没放行"查询"形式，把自己的看门狗弄瞎

原规则：只要 `signum == SIGILL` 就拒绝。于是看门狗那句
`sigaction(SIGILL, NULL, &cur)`（`act == NULL`，纯查询）也拿到 `EPERM`，
分支被跳过 —— 看门狗从此永远打印 "disposition verified" 却再也看不见任何变化。
**一个看不见的守卫比没有守卫更糟。**

**修法**：BPF 里加一层 `args[1] == 0` 判断，查询放行、写入拒绝。

### 附带：`dl_iterate_phdr` 的真身不在 `libc.so`

```
libc.so :  UND  dl_iterate_phdr@LIBC        （size 0，空壳占位）
libdl.so:  0x10dc FUNC WEAK dl_iterate_phdr@@LIBC   （28 字节跳板，真实现）
```

Android 14 bionic 上必须钩 `libdl.so`，钩 `libc.so` 只会得到
`Find symbol in ELF failed`。

---

## 2. 易盾自毁链 —— 三级，逐级降级

关键在于**每堵住一级，下一级就现形**。这本身就是最有力的证据。

| 级 | 机制 | 证据 | 现状 |
|---|---|---|---|
| **1** | 内联 `svc` 调用 `exit_group` | 无 seccomp：**干净退出，无任何信号**；开 seccomp：死法变成 SIGILL | ✅ **已瓦解** |
| **2** | `rt_sigprocmask` 屏蔽 SIGILL → 执行 `udf` | 粗过滤 `rt_sigprocmask` 后，SIGILL 处理器**立刻触发 197 次** | ⚠️ **已瓦解但覆盖不全** |
| **3** | SIGSEGV（疑似主动） | 第 2 级堵死后，`signal 11` 出现 37 次 | ❌ 未处理 |

### 第 2 级的完整机制（本轮最重要的发现）

```
SIGILL 1 7eb24a8c28 1     ← si_code = 1 = ILL_ILLOPC，真正的 udf
SIGILL 2 7eb24a8c2c 1     ← 紧邻的第二条 udf（正好差 4 字节）
```

- `si_code = 1` 证实是 **`udf` 非法指令**，不是 `raise()`
- 两条 `udf` 连续排布，是刻意的双保险
- **PC 跨进程完全一致**（`7eb24a8c28`）—— 因为 Android 应用进程由 zygote fork，
  ASLR 只在 zygote 里做一次。这是一个**确定性地址**

**为什么处理器之前一次都不触发**：同步信号（`udf` 产生的 SIGILL）**不能被挂起** ——
线程会永远重复执行出错指令。所以一旦掩码把它屏蔽，内核**无法投递**，
只能转而执行默认动作。处理器装着、处置权是我们的、信号却根本到不了。

**修法**：拒绝"会把 SIGILL 加进掩码"的 `rt_sigprocmask`。
BPF **无法解引用指针**，看不了掩码内容，所以必须用 `SECCOMP_RET_USER_NOTIF`
交给监管线程读内存再裁决。

### 第 2 级的遗留问题：覆盖不全

`SECCOMP_FILTER_FLAG_NEW_LISTENER` **不能与 `TSYNC` 同时使用**，
所以这个过滤器只落在安装它的那一个线程上。派生覆盖是不完整的：

- 主线程 ✅，主线程派生的线程 ✅
- 已存在的 ART 线程 ❌，**它们派生的线程 ❌**

实测：精确守卫下 `signal 4` 死亡回到 38 次；而粗过滤（`TSYNC`，全线程）
下是 **0 次**。

### 掩码内容无法用于区分敌我

```
SPROCMASK_DENY 2 ffffffffffffffff    ← SIG_SETMASK，全信号
SPROCMASK_DENY 0 ffffffffffffffff    ← SIG_BLOCK，全信号
```

`bits = ~0`（屏蔽**所有**信号）。而 bionic 的 `pthread_create` 也正是
`sigfillset` + `SIG_SETMASK`，参数上**完全无法区分**。
按"集合含 SIGILL"判断 → 误伤所有线程创建（每进程约 99 次）。

---

## 3. 当前代码状态

文件：`module/app/src/main/cpp/hupushield.c`

| 组件 | 状态 |
|---|---|
| ShadowHook `dlopen` 加载 | ✅ 工作 |
| `sigaction` inline 钩子 | ✅ 装上，但易盾不走 libc → 从未触发 |
| `dl_iterate_phdr` inline 钩子 | ✅ 装上，但易盾不调用它 → 从未触发 |
| SIGILL 处理器 + 备用栈 + 无锁日志 | ✅ 工作（197 次捕获） |
| 无锁事件通道 `hupushield.log.events` | ✅ 工作，是本次排障的关键工具 |
| seccomp 阻断器（TSYNC，全线程） | ✅ 工作 |
| sigprocmask 精确守卫（用户通知） | ⚠️ 逻辑正确但**只覆盖单线程** |
| SIGSEGV 处理 | ❌ 未实现（ART 拥有该处置权，必须链式转发） |

配置：`/sdcard/Android/data/com.hupu.games/files/hupushield.conf`
当前 `blockNative=1 inlineHooks=1 traceOpenat=0 fakeMaps=0`

---

## 4. 下一步（按优先级）

1. **让掩码守卫覆盖全线程**。
   唯一已知能覆盖全线程的是 `TSYNC`，而 `TSYNC` 不能带监听器。
   可行方向：`TSYNC` 粗过滤 + 在监管线程里补救；或改用 `SECCOMP_RET_TRAP`
   （SIGSYS 处理器能拿到寄存器，可以自行读掩码并模拟该系统调用）。

2. **SIGSEGV 链式处理器**：保存 ART 原处理器，命中易盾自毁点则跳过 4 字节，
   否则**原样转发**给 ART。绝不能夺走 ART 的 SIGSEGV 处置权 ——
   ART 靠它做隐式空指针检查与栈溢出检测。

3. **验证第 3 级到底是易盾的主动手段，还是粗过滤的副作用**。
   粗过滤下 37 次 SIGSEGV **完全没有生成墓碑**（`ls -t` 最新仍是 22:52 那次
   我们自己的崩溃），这提示崩溃上报链路本身也被粗过滤破坏了，
   倾向于"副作用"一侧。

4. 若三级都堵住后仍死，考虑回到"**让检测不发生**"的路线
   （伪造 `/proc/self/maps`，`fakeMaps` 开关已有雏形）——
   毕竟对照实验证明，**模块完全关闭时易盾照样自杀**，
   说明它检测的是 LSPosed 本身，而非我们的模块。

---

## 5. 第三轮：换路线成功 —— 伪造 maps 真的打在要害上

### 5.1 先确认目标存在

用 openat 追踪器实测，**易盾确实在大读 `/proc/self/maps`**（单轮 635 次，
连续几十次打开），随后才自杀。这条路不是猜的。

而且用户通知过滤器**能拦住它的原始 `svc` openat** —— 壳再怎么绕过 libc，
`openat` 仍然是系统调用，seccomp 照拦不误。

### 5.2 maps 里到底暴露了什么（关键）

抓取虎扑真实进程的 maps 快照，**唯一可疑的条目是我们自己的模块**：

```
/data/app/~~EZU.../com.dsh.hupushield-PSoH.../base.apk
```

**没有 `liblspd.so`、没有 `zygisk`、没有 `LSPosed` 路径** ——
LSPosed / Zygisk Next 已经把自己的库藏好了（走 memfd / 匿名映射）。
暴露的是**我们模块的 APK 路径**。

### 5.3 一个具体的、可修的漏洞

原来的关键词表里是 `"libhupushield"`（.so 名），
而实际路径里是 **`com.dsh.hupushield`（包名）** —— 不含 `.so` 名，
所以**这条最关键的证据根本没被过滤掉**。

同时那两条"匿名可执行映射"和"memfd"规则是基于猜测加的：
ART 自己的 JIT 缓存就叫 `/memfd:jit-cache`，规则会把**正常条目**删掉，
反而制造出检测器最爱找的那种空白。实测 `[maps kept] anonymous exec: 0`
—— 现实里根本不存在这种映射。

改成有证据支撑的规则：① 关键词表；② **任何 `/data/app/` 下不属于本应用的条目**
（通用规则：从目标进程内部看，别的包的 APK 就是 Xposed 模块的样子）。

### 5.4 效果：数量级的改善

| | 修复前 | 修复后 |
|---|---|---|
| 单进程存活 | ~300 ms | **~11 s** |
| CPU | 30–76% 空转 | **3.6–5%，`S<` 稳定空闲** |
| `has died`（20s 内） | 100+ | **6** |
| 进展 | `Application.onCreate` 前即死 | 已读到 SystemUI 资源覆盖层 |

`MAPS FAKED (#1, tid=..., dropped=3, newfd=82)` —— 每次快照稳定删掉 3 行。

### 5.5 新的死因：ANR，而且是我们自己造成的

死法从"干净退出"变成了 **signal 9 (SIGKILL)**。ANR 报告给出了精确答案：

```
Subject: App requested: Changing to new focus window timeout
"main" prio=5 tid=1 Native
  #04 unwindstack::ThreadEntry::Wait
  #05 unwindstack::ThreadUnwinder::UnwindWithSignal
  #07 dump_thread
  #11 __dl_debuggerd_fallback_handler
```

配合：

```
libunwindstack: Timeout waiting for unwind to complete
openat RECV failed: Interrupted system call
ActivityManager: TheiaManager sendEvent:com.hupu.games ANR happen
Zygote: Process 30130 exited due to signal 9 (Killed)
```

心跳日志也印证：`[T+271ms] alive #1` 之后**冻结了整整 10 秒**才有 `alive #2`。

**链条**：`debuggerd` 的进程内兜底要 dump 堆栈 → `unwindstack` 需要
`/proc/self/maps` → 也被我们拦下 → 监管线程被拖住 → 反手把 unwinder 卡死
→ 主线程冻结 → ANR → 系统 SIGKILL。

**不是 maps 伪造错了，是监管线程自己太重。** 它每拦一次 openat 就往 logcat
写一行（`__android_log_print` 写 logd 是可能阻塞的），而 Java 侧每 250 ms
写一次心跳日志又制造一次 openat —— 自激振荡。

### 5.6 下一步修复（按优先级）

1. **监管线程禁止阻塞式日志**。改用预开 fd 的裸 `write()`（与信号处理器同款），
   或直接删掉逐条 `[openat N]` 打印。
2. **别拦所有 openat**。BPF 看不了路径字符串，但**能看 flags**：
   maps 用的是 `0x0` / `0x88000`，而日志写入是 `0x441`
   （`O_WRONLY|O_CREAT|O_APPEND`）。只对"非写打开"发通知即可去掉绝大部分往返。
3. **降低 Java 侧心跳频率**，或让它不再每次 openat。
4. 之后再与 kill 阻断器组合，形成"检测不到 + 死不掉"的双保险。

---

## 7. 第四轮状态：ANR 仍在，但已定位到抛信号的人

已实施 5.6 的修复 1 与 2：

- 监管线程的 logcat 打印从 500 行砍到 30 行（`OPENAT_LOG_LIMIT`）
- BPF 只对**只读打开**发通知（`(flags & O_ACCMODE) == 0`），
  日志写入用的 `0x441` 被排除，250ms 心跳不再产生往返
- 新增：**`flags & O_NONBLOCK` 的 maps 打开放行真表**
  （假设：易盾用 `flags=0x0`，unwindstack 用 `flags=0x88000`）

**结果**：存活稳定在 ~13 s，但 ANR 仍在（1 次/轮），随后 SIGKILL。
`MAPS REAL` 计数为 0 —— 说明转储路径没有走到那次带 `O_NONBLOCK` 的 maps 读，
或者 ANR 的成因不止一个。

**最新 ANR 堆栈把抛信号的人直接指了出来：**

```
#11 __dl_debuggerd_fallback_handler
#12 __dl_debuggerd_signal_handler
#13 libsigchain.so (art::SignalChain::Handler+1072)
#14 [vdso]
#15 /data/app/~~Re5.../com.hupu.games-.../lib/arm64/libnesec.so (???)
```

**是 `libnesec.so` 在主线程上抛了信号**（不是我们），ART 的 SignalChain 接住，
启动进程内墓碑转储，转储没跑完 → 主线程冻结 → ANR → 系统 SIGKILL。
`signal 4` 计数为 0，说明不再是 `udf`。

### 仍需回答的问题

1. **libnesec 为什么在 ~12 s 才抛信号？**
   早期检测被 maps 伪造挡住了，这是**延迟触发**的第二条检测，
   还是它自己代码里的真实崩溃（例如它拿伪造的表去定位自己的段）？
2. 转储为什么跑不完 —— 是否真有某个线程卡在被拦的 openat 上。
   可在监管线程里记录"未被回答的通知数量"来判定。
3. `has died` / `signal 9` 计数（11）远多于我们观察到的存活进程，
   说明有大量进程在更早阶段就死了，值得单独统计分布。

### 一个必须记住的教训

**监管线程是单点故障。** 它一慢，整个被过滤的进程都慢；
它一死，所有被拦的 openat 永久挂起。给它加任何阻塞式 I/O
（尤其是 logcat）都是在给自己埋雷。

---

## 8. 工具与手法（可复用）

- **无锁事件通道**是排查信号问题的唯一可靠手段。
  信号处理器里**绝不能**调用 `dladdr()`（动态链接器锁）或 stdio（FILE 锁）——
  陷阱恰好发生在 `dlopen` 前后，链接器锁极可能正被持有。
  做法：预开 fd + 裸 `write()` + 手写整数格式化。
- **`/data/tombstones/` 不会进 logcat**。进程"静默死亡"时第一件事就该去看它。
- **`/data/anr/` 会给出发起 ANR 的那条线程的完整 native 堆栈** ——
  判断"卡在哪"比任何日志都直接。
- **对比实验**：`Zygote: Process N exited due to signal X` 是判断死因的金标准；
  无此行 = 干净退出（`exit_group`）。
- 关闭全部开关做对照（`hupushield.conf` 全 0），可干净地区分
  "我们的问题"与"环境的问题"。
- 应用进程由 zygote fork，**ASLR 只做一次**，所以库地址和自毁点地址
  **跨进程完全一致**，是可依赖的确定性信息。
- **抓 maps 要在启动应用之前**把循环挂到后台 —— 应用只活几百毫秒，
  adb/su 的往返延迟就足以错过整个窗口。

---

## 9. 第五轮：否证 —— 卸载模块后虎扑**依然**起不来

### 9.1 实验设计

读 LSPosed 数据库（只读拷贝 `modules_config.db` + WAL 到本机，用
`platform-tools/sqlite3.exe` 查询），作用域含 `com.hupu.games` 的只有两条：

| mid | 模块 | 状态 |
|---|---|---|
| 203 | `com.yumito.yumyhook` | **已禁用** |
| 214 | `com.dsh.hupushield` | 已启用 |

所以卸载 HupuShield 后，虎扑进程里**一个已启用模块都没有，LSPosed 完全不注入**。

### 9.2 结果

```
是否有 LSPosed 注入虎扑 : 0          ← 确实没有注入
是否有 HupuShield 日志   : 0
进程                     : com.hupu.games + com.hupu.games:pushcore 存活 35s+
```

比之前好很多（之前有模块时几百毫秒就死），**而且虎扑的真实业务代码开始跑了**：

```
com.hupu.games.main.sign.SignErrorInterceptor.intercept(SignErrorInterceptor.kt:3)
CookieManager / okhttp
Start proc com.google.android.webview:sandboxed_process0...   ← WebView 沙箱
```

说明**壳的解包是成功的**，之前那个 `androidx.core.app.CoreComponentFactory`
的 `ClassNotFoundException` 确实只是良性噪声。

**但界面始终没有出现**（截图确认停在桌面，`Displayed` 计数为 0），
主进程在 2–16 秒之间死亡，而且：

```
Zygote 信号记录：无      ← 干净 exit_group 退出
```

**这正是易盾的签名式死法。**

### 9.3 结论：问题和 Xposed 无关

| # | 问题 | 证据 |
|---|---|---|
| 1 | Xposed 检测 | 有模块时 ~300ms 死；洗 maps 或卸载可缓解到 ~13s |
| 2 | **与 Xposed 无关的第二个死因** | **一个模块都没有时，依然 2–16s 干净退出** |

**所以"屏蔽 Xposed 检测"目前不是瓶颈。** 在搞清楚第二个死因之前，
继续投入模块开发是无效功。

### 9.4 新嫌疑名单（都在环境侧，不在 LSPosed 作用域内）

设备上**会注入所有应用**的非 LSPosed 模块：

| 模块 | 状态 | 备注 |
|---|---|---|
| `hma_oss_zygisk` | enabled | **Hide My Applist OSS** —— 我们配置过它（45 个包名），它会 hook 每个应用的 PackageManager |
| `zygisk_shamiko` | enabled | 隐藏 root |
| `xfingerprint-pay-*` | 4 个 enabled | 支付类指纹模块，可能广泛注入 |
| `scene_systemless` / `WorkSettingPro` / `ace3_thermal_opt` / `RescueBrick` | enabled | 工具类 |

其它可能：
- KernelSU root 本身（易盾是 native，可能直接查 `/proc`）
- **伪造的 `ro.boot.flash.locked=1` / `verifiedbootstate=green`** 与实际
  `oplusboot.verifiedbootstate=orange` 矛盾，可能被一致性检查抓到

### 9.5 下一步：二分法

**依次停用非必要的 Zygisk 模块**（先 `hma_oss_zygisk`，它是最激进、
且是唯一由我们改动过配置的），每停一个测一次虎扑。
这是唯一能定位第二个死因的方法。

---

## 10. 第六轮：用 ptrace 从进程外拿到了易盾的完整检测清单

### 10.1 自制工具（都不注入、不改设备）

| 工具 | 作用 | 源码 |
|---|---|---|
| `hs-trace` | arm64 ptrace 系统调用跟踪器，记录入口/返回与路径 | `work/hs-trace.c` |
| `hs-acctest` | 降到应用 uid + 清空能力位，实测应用能看到的权限结果 | `work/hs-acctest.c` |

编译用 NDK 26.3：`aarch64-linux-android26-clang -O2 -fPIE -pie`。
**静态链接（`-static`）会触发 NDK 的 TLS 对齐 bug**（`underaligned: alignment is 8,
needs 64`），必须动态链接。

ptrace 被 SELinux 拦（且被 `dontaudit` 吞掉日志，看不到 AVC）。
`ksud sepolicy apply` 可**动态**加规则（`ksud sepolicy patch/apply/check`），
但实测对 `untrusted_app_30` 不生效；**`setenforce 0` 可以立刻打通**（内存级，随时恢复）。

### 10.2 易盾探测的完整路径清单（`faccessat`）

**Xposed**：`/data/data/de.robv.android.xposed.installer`、
`/data/data/com.virtualprotect.exposed`、`/system/framework/XposedBridge.jar`、
`/system/xposed.prop`、`/system/lib{,64}/libxposed_art.so{,.no_orig}`

**Magisk/Riru/LSPosed**：`/data/adb/lspd`、`/data/adb/riru/modules/{lspd,edxp.prop,dreamland}`、
`/data/misc/{riru/modules/{edxp,dreamland},taichi}`、
`/sbin/.magisk/modules/{riru-core,riru_lsposed,riru_edxposed,taichi}`、
`/system/lib64/{libriruloader.so,libriru_edxp.so}`、`/data/data/com.topjohnwu.magisk`

**root/su**：`/sbin/su`、`/su/suhide`、`/system/usr/we-need-root/su-backup`、
`/system/app/Superuser.apk`、`/system/bin/magiskpolicy`

**注入框架**：`/data/local/tmp/re.frida.server/`、`/data/local/tmp/frida-server`

**云手机/模拟器**：`/sys/devices/virtual/misc/vboxuser`、
`/sys/devices/virtual/redfinger_audio`（红手指）

**另外证实了 `/proc` 两条扫描线**：逐进程读 `/proc/<pid>/maps`、`/proc/<pid>/stat`，
以及**逐线程读 `/proc/<pid>/task/<tid>/status`**（线程名绊线）。

### 10.3 精确泄漏表（关键成果）

用 `hs-acctest` 降到 uid 10452 并清空能力位后实测：

| 路径 | 结果 |
|---|---|
| `/data/adb/lspd` | **EACCES** ❌ |
| `/data/adb/riru/modules/lspd` | **EACCES** ❌ |
| `/data/adb/riru/modules/edxp.prop` | **EACCES** ❌ |
| `/data/adb/riru/modules/dreamland` | **EACCES** ❌ |
| `/data/adb`（本身） | 0 存在 ⚠️ |
| **其余 27 条全部** | **ENOENT** ✅ |

**根因只有一个**：`EACCES` 不是来自子路径，而是来自 **`/data/adb` 本身是 `0700 root:root`** ——
应用连穿过它都不行，所以**任何 `/data/adb/...` 一律 EACCES，与该子路径是否存在无关**。

> **陷阱**：KernelSU 的 su 设了 `PR_SET_KEEPCAPS`，`setresuid` 后
> `CAP_DAC_OVERRIDE` 会存活，0700 目录照样能打开 —— 不先
> `prctl(PR_SET_KEEPCAPS, 0)` + `capset` 清零，测出来的会是"存在性"而不是"访问结果"。
> 必须用 `/proc/self/status` 的 `CapEff` 确认已经清零。

### 10.4 修复规则（极简）

```
拦截 faccessat / faccessat2 / newfstatat / statx / openat / openat2
若 path == "/data/adb" 或 path 以 "/data/adb/" 开头  →  返回 -ENOENT
否则 CONTINUE
```

一条前缀判断覆盖全部 4 条泄漏。**不需要刷内核。**

唯一风险是性能：这几个系统调用调用量远大于 `/proc/self/maps`
（启动期 921 条不同路径），监管线程每多一次阻塞 I/O 都可能把应用拖到 ANR。
监管线程必须只做"读路径 + 前缀比较 + 回响应"，禁止任何 logcat / stdio。

### 10.5 收尾状态

- SELinux 已恢复 `Enforcing`（已验证）
- `ksud sepolicy` 加的是**内存级**规则，重启即消失
- boot 三个分区已备份到电脑（`work/boot-backup/`），**未刷任何东西**

---

## 11. 第七轮：结案 —— 虎扑新版本现在完全正常运行

### 11.1 事实

新版本 `8.2.62.09111`（vc 12310）在当前环境下**稳定运行**：

- 主进程存活数分钟（多次采样同一个 pid 不变）
- `检测到Xposed环境` toast 计数 = **0**
- `Zygote: exited due to signal` = 0（没有自毁）
- 界面完整可用（截图确认）

而且**清空 `/data/user/0/com.hupu.games` 全部私有数据后依然正常** →
说明**不是**任何缓存的判决结果。

### 11.2 真正的原因：KernelSU 的 per-app「卸载模块」

开机日志（`/data/adb/lspd/log/kmsg.log`）里有决定性两行：

```
KernelSU: load_allow_uid, name: com.hupu.games, uid: 10452, allow: 0
KernelSU: set app profile, key: com.hupu.games, uid: 10452, umount modules: 1
```

即 **KernelSU 的「应用配置 / App Profile」对 `com.hupu.games` 开了
「卸载模块(umount modules)」**，并且**没有授予该应用 root**（`allow: 0`）。

效果：KernelSU 在**该应用自己的挂载命名空间里**卸载掉所有模块挂载 →
Zygisk Next 不再向它注入 → LSPosed 也不再向它注入。

`/data/adb/ksu/.allowlist`（10872 B，mtime `2026-09-25 00:34`）的字符串里，
`com.hupu.games` 与 `com.android.bankabc` 是仅有的两个**没有跟随
`u:r:su:s0` 策略串**的条目 —— 正是"只在 Profile 里、没给 root"的形态。

### 11.3 对照证据（这是"per-app"而不是"全局关闭"的证明）

运行时实测虎扑进程 `maps` 8817 行里的注入痕迹：

| 关键字 | 命中 |
|---|---|
| `lspd` / `zygisk` / `shamiko` / `xposed` / `riru` / `magisk` / `hupushield` | **全部 0** |

同一个时刻，LSPosed 自己的 `modules_*.log` 里**活跃注入的应用**（虎扑 0 条）：

```
com.luckyzyx.luckytool   com.coloros.phonemanager   com.omarea.vtools
com.bug.hookvip          com.heytap.cloud           me.hd.wauxv
com.coolapk.market       tv.danmaku.bili            com.tencent.mm
com.heytap.themestore    com.coderstory.toolkit     com.android.launcher
```

**结论：其它 Xposed 模块一个都没受影响，只有虎扑被单独排除。**

### 11.4 这直接回答了最初的需求

| 需求 | 状态 |
|---|---|
| 虎扑正常使用 | ✅ 达成 |
| 其它 Xposed 模块继续工作 | ✅ 达成（日志可证） |
| 不丢 root | ✅ 达成（只是给虎扑一个 per-app 配置） |
| 不刷机 / 不动内核 | ✅ |

**代价**：虎扑上不能再用 Xposed 模块 —— 但这正是用户在
"那我不要在虎扑上使用 Xposed，我想让我目前的环境下正常使用虎扑"
里明确接受的条件。

### 11.5 因此被否定的假设（都别再走）

- ❌ 不是"缓存了判决结果"（全量清数据后照常运行）
- ❌ 不是 SELinux 状态（Enforcing 下照常运行）
- ❌ 不是 `hs-nshide-daemon`（停掉它没有任何变化）
- ❌ 不是 HMA-OSS（已禁用，且禁用前后都一样）
- ❌ 不是 `/data/adb` 的 EACCES 泄漏 —— 在 `umount modules` 生效后，
  应用**根本看不到** `/data/adb`，§10.4 的拦截规则在这个配置下是多余的
- ⚠️ Zygisk Next 的 `denylist_enforce=1`（强制）虽然方向类似，但它是
  **全局**的，会连带卸掉 Shamiko 的隐藏 → 用户"模块全掉"。
  **正确做法是 KernelSU 的 per-app App Profile，不是 Zygisk 的全局排除表。**

### 11.6 仍未回答（用户明确表示想知道）

**易盾到底"看到"了什么才判定 Xposed。** 目前的证据链指向
§10.2 的清单 + `/proc/self/maps` 扫描（启动期约 635 次），
但**具体命中的那一条**还没钉死，因为：

- 判定逻辑在**动态解密的 dex** 里（壳的 `classes.dex` 是 95.4 MB 的加密体，
  旧/新两个版本的 dex 里都搜不到 `/system/xposed.prop`、
  `.magisk/modules`、`riru_lsposed` 等明文）
- `hs-dexdump` 上一轮只按 `dex\n035` 扫，**命中 0 个镜像**，
  需要扩到 `dex\n038`/`039` 重跑

有了 §11.2 这个"开关"，现在终于能做**干净的单变量对照实验**了：
关掉/打开虎扑的 `umount modules`，就得到"被注入 / 不被注入"两个
只差一个变量的世界，再用 `hs-trace` 对比易盾的 syscall 轨迹 ——
这比之前所有实验都干净。

---

## 12. 版本更正：真正的最新版是 8.2.63，已验证同样正常

### 12.1 版本事实

先前测的 `8.2.62.09111`（vc 12310）**不是最新版**。各渠道实测：

| 来源 | 版本 |
|---|---|
| 应用宝 `sj.qq.com/appdetail/com.hupu.games` | **V8.2.63 / 8.2.63.09241**，2026.9.25 更新 |
| 虎扑应用内更新（用户操作下载） | `hupu_556557717_8.2.63.09241.apk` |
| APK 实测 `aapt2 dump badging` | `versionCode=12314 versionName=8.2.63.09241` |

另注：虎扑论坛上有 `8.2.63 灰度版` 的 bug 反馈帖，说明它是**灰度推送**，
应用宝上已经是这个版本。

### 12.2 获取路径（可复用）

**应用宝网页端不暴露 App 直链**（只给自家 `qqdownloader` 的 apk），
`wechat-apkinfo` 接口对该包返回空、`sj.qq.com/api/*` 全 404。

**最可靠的拿包方式：让虎扑自己下。** 应用内点更新后，包落在：

```
/sdcard/Android/data/com.hupu.games/files/hupu/update/hupu_556557717_<版本>.apk
```

（即 `/data/media/0/Android/data/com.hupu.games/files/hupu/update/`）
拷出 → 校验签名 → `pm install -r -d` 即可。

### 12.3 8.2.63 真伪校验

`apksigner verify --print-certs`，与已装 8.2.62 **逐项一致**：

```
Signer #1 certificate DN: CN=Jerry Ching, OU=R&D, O=Hupu, L=HongKou, ST=ShangHai, C=CN
Signer #1 certificate SHA-256: ebb492d45cd4c9722430f9f2fd0b5286974731c95072a680c174b50cf4f5e1ed
Signer #1 certificate SHA-1  : 922406466f76544840c4d2a136445290430e8442
```

APK：`work/hupu-8.2.63.apk`，77,683,924 B，
md5 `e22322a05250cc7e97590a549e717191`，
sha256 `2d54527d8b60716d42fa2901e69eb7c84db162a7d6075e6aa0bd115ddbeb7367`。

### 12.4 打包方式未变（易盾壳照旧）

| 文件 | 8.2.62 | 8.2.63 |
|---|---|---|
| `lib/arm64-v8a/libnesec.so` | 1,035,712 | **1,035,712**（同尺寸） |
| `lib/arm64-v8a/libnshelper.so` | 612,744 | **612,744**（同尺寸） |
| `lib/arm64-v8a/libnesec-x86.so` | — | 1,207,928 |
| `classes.dex` | 100,061,736 | **100,078,172** |

`targetSdk=30`、`minSdk=24`、`compileSdk=33` 都没变。
**没有换成新壳，只是内容有微调。**

### 12.5 8.2.63 实测结果（通过）

`pm install -r -d` 安装 → `versionCode=12314 / versionName=8.2.63.09241`。
启动后连续观测：

```
T+5s … T+60s  pid=17792 全程不变        ← 60 秒零重启
toast「检测到…」     : 0
Zygote signal / FATAL: 0
maps_lines           : 9085
注入痕迹命中          : 0
mCurrentFocus        : com.hupu.games/com.hupu.games.main.MainActivity
```

截图确认界面完整（推荐流 / 投票卡 / 底部导航全在），
仅因之前清过数据而显示「登录后体验完整功能」。

**结论：8.2.62 与 8.2.63 在 `umount modules` 配置下都完全正常，
KernelSU per-app 的结论对最新版同样成立。**

---

## 13. 第八轮：**推翻第 11 节** —— 关键变量是 root 授权，不是 umount modules

### 13.1 用户做的三个单变量实验

| # | 操作 | 结果 |
|---|---|---|
| 1 | 把「卸载模块(umount modules)」**关掉**，重启 | **虎扑依然正常进入** |
| 2 | 把 **HMA 打开** | **依然正常进入** |
| 3 | **给虎扑 root 权限** | toast **「检测到 root 权限」** → **退出** |

### 13.2 结论：第 11 节的归因是错的

第 11 节把功劳给了 `umount modules: 1`。**实验 1 直接否证了它** ——
关掉并重启后照常运行。

本次开机的 dmesg 也印证了这一点：

```
KernelSU: load_allow_uid, name: com.hupu.games, uid: 10452, allow: 0
KernelSU: set app profile, key: com.hupu.games, uid: 10452, umount modules: 0
KernelSU: uid :10452, allow: 0
```

`umount modules: 0`（已关）**且** `allow: 0`（未授 root）→ 正常运行。

**真正的关键变量是 `allow`（是否给该应用 root）。**

### 13.3 修正后的模型：两条互相独立的检测分支

| 分支 | 触发条件 | 文案 |
|---|---|---|
| **Xposed 分支** | 进程里存在注入痕迹（LSPosed/Zygisk 注入了该应用） | 「检测到Xposed环境」 |
| **root 分支** | **KernelSU 给该应用授予了 root**（`allow: 1`） | 「检测到root权限」 |

- 实验 1、2 没有改变这两个条件中的任何一个：
  - LSPosed 作用域里**没有启用**的模块指向虎扑 → 不注入 → Xposed 分支不触发
  - `allow: 0` → root 分支不触发
- 实验 3 打开了第二个条件 → 报 root → 退出。

**可操作结论：不要去给虎扑授权 root。**（umount modules 开不开都无所谓。）

### 13.4 第八轮抓到的完整 root 探测清单（`hs-trace` ptrace）

启动期实测（3730 行轨迹，`faccessat` 947 / `newfstatat` 459 / `openat` 462 / `readlinkat` 94）：

**su 路径（RootBeer 风格，34 条）**

```
/system/bin/su  /bin/su  /system/xbin/su  /xbin/su  /system/sbin/su  /sbin/su
su(裸名，走 PATH)  /systemsu  /su/bin/su  /data/local/xbin/su  /data/local/bin/su
/data/local/su  /system/sd/xbin/su  /system/bin/failsafe/su  /system/bin/.ext/.su
/system/etc/.installed_su_daemon  /system/etc/.has_su_daemon  /system/xbin/sugote
/system/xbin/sugote-mksh  /system/xbin/supolicy  /system/.supersu
/system/etc/init.d/99SuperSUDaemon  /product/bin/su
/apex/com.android.runtime/bin/su  /apex/com.android.art/bin/su  /system_ext/bin/su
/system/xbin/bstk/su  /odm/bin/su  /vendor/bin/su  /vendor/xbin/su
/system/bin/.ext/su  /system/usr/we-need-root/su  /cache/su  /data/su  /dev/su
```

**Magisk / Riru / Taichi**

```
/sbin/.magisk/modules/{riru-core,riru_lsposed,riru_edxposed,taichi}
/data/misc/{riru/modules/{edxp,dreamland},taichi}
/sdcard/Download/magisk_patched.img        ← 注意这条！
/data/fart   /sdcard/fart   /data/dexname
```

**Xposed**

```
/system/xposed.prop   /system/framework/XposedBridge.jar
/system/lib{,64}/libxposed_art.so{,.no_orig}
/data/data/de.robv.android.xposed.installer
/data/data/com.virtualprotect.exposed
```

**重要：整个轨迹里 `execve` / `execveat` = 0 次。**
**它不执行 su，只用 stat 系列探测文件是否存在。**

### 13.5 仍然存活的泄漏点（只有 5 条不是 ENOENT）

| 路径 | 结果 |
|---|---|
| `/cache/su` | **EACCES** |
| `/data/adb/lspd` | **EACCES** |
| `/data/adb/riru/modules/lspd` | **EACCES** |
| `/data/adb/riru/modules/edxp.prop` | **EACCES** |
| `/data/adb/riru/modules/dreamland` | **EACCES** |

其余全部 34+ 条 su 路径、magisk 镜像、Xposed 文件都是 **ENOENT（干净）**。

### 13.6 一个被排除的解释

怀疑过"授权 root 会让 KernelSU 放开 `/data/adb` 的访问"。
用 `hs-acctest` 分别以 **uid 10452（虎扑，allow=0）** 和
**uid 10488（MT管理器，`.allowlist` 里有 `u:r:su:s0`）** 降权实测：

```
两者结果完全一致：6/33 泄漏，/data/adb/* 一律 EACCES
```

**说明 KernelSU 的 allowlist 不改变文件系统 DAC 视图**
（至少对"降权后的普通进程"不改变）。

同理，虎扑进程与 MT 进程的挂载命名空间也**逐项一致**
（都是 219 行 mountinfo、3 条 `/data/adb` 命中、无 `su` 文件）。

### 13.7 尚未定论 + 下一步

既然 `execve = 0`、DAC 视图不随 allow 变化，那么
**"授权 root 后究竟是哪一条探测从 ENOENT/EACCES 翻盘"** 还没钉死。

**决定性实验（单变量，一次点击即可）：**
1. 在 KernelSU 管理器里给虎扑**再授一次 root**
2. 同时用 `hs-trace --wait com.hupu.games 30 -v` 抓启动轨迹
3. 与 §13.4/13.5 的基线**逐行 diff**

翻盘的那一条就是它判定 root 的确切依据。
预期最可能的翻盘点是 `/data/adb/lspd`：`EACCES → 0`（存在）。
若成立，则 §10.4 那条"把 `/data/adb*` 一律返回 ENOENT"的拦截规则
**正是对 root 分支的正确修法**。

（实验后把 root 授权撤销，恢复当前可用状态。）

---

## 14. 第九轮：**破案** —— root 分支的确切判据是 `faccessat("/system/bin/su")`

### 14.1 实验

用户在 KernelSU 管理器里给虎扑**授予 root**，随即用同一命令抓启动轨迹，
与 §13.4 的基线逐行对比。

### 14.2 结果：两条轨迹的差异是压倒性的

| | 基线（`allow: 0`，未授权） | 授权后（`allow: 1`） |
|---|---|---|
| 轨迹总行数 | 3730 | **95** |
| 探测到的 su 路径数 | **38 条** | **1 条** |
| `faccessat /system/bin/su` | `-2` **ENOENT** | **`0` EXISTS** |
| 后续 | 继续跑完 38 条，全部 ENOENT | **立刻停止** |
| 进程结局 | 正常存活 | `Process com.hupu.games has died: fg SVC`（**无 signal 行 → 干净 `exit_group`**） |

授权后的轨迹里，`faccessat /system/bin/su → 0` 出现在**第 10 行**，
而**这是整个轨迹里唯一一条 su 探测**。

```
[4986] faccessat   /system/bin/su   -> 0  EXISTS      <== leak
```

### 14.3 机制（定论）

**KernelSU 一旦给某个应用授予 root，就会在该应用的命名空间里
把 `su` 暴露到 `/system/bin/su`。**

于是易盾的 root 分支：

```
faccessat("/system/bin/su")
  → ENOENT  ⇒ 没有 root ⇒ 继续跑（然后还要把其余 37 条 su 路径查一遍）
  → 0       ⇒ 有 root   ⇒ 立刻判「检测到root权限」⇒ 干净退出
```

**它第一条就查这个路径**，是这条检测链的"快速通道"。

### 14.4 顺带修正两个先前的猜测

- ❌ 我之前猜"易盾会执行 `su`"—— **错**。`execve`/`execveat` 全程 **0 次**，
  它只用 `faccessat`/`newfstatat` 探文件存在性。
- ❌ 我猜"`com.hupu.games` 出现在 `.allowlist` 里说明 App 自己请求过 root"—— **错**。
  既然它从不执行 `su`，就不会去请求 root；那条记录是**人手动加的**。

### 14.5 这对模块路线意味着什么（重要）

既然 root 分支是**纯 `stat` 探测**，那么 §10.4 的拦截方案
**可以直接打败它，而且不需要撤销 root 授权**：

```
拦截 faccessat / faccessat2 / newfstatat / statx / openat / openat2
若 path 命中以下任一前缀/名单  →  返回 -ENOENT
    /data/adb            （含所有 /data/adb/...）
    /system/bin/su       （以及 §13.4 的其余 33 条 su 路径）
    /cache/su
    /sbin/.magisk/...    /data/misc/{riru,taichi}
    /system/xposed.prop  /system/framework/XposedBridge.jar
    /system/lib{,64}/libxposed_art.so{,.no_orig}
    /sdcard/Download/magisk_patched.img   /data/fart  /sdcard/fart  /data/dexname
```

**路线 B（自带 ShadowHook 的 HupuShield 模块）因此重新变得有意义**：
目标不再是"屏蔽 Xposed 检测"这一条，而是**同时屏蔽 root 分支与 Xposed 分支**，
且能让虎扑在**保留 root 授权**的前提下运行。

注意：这只是"让应用在自我检测时看不到"，不是绕过、也不是欺骗第三方 ——
与之前 §10.4 的结论一脉相承，唯一新增的是 **su 路径名单**。

---

## 15. 第十轮：复盘 —— "之前为什么不行"的答案（大部分是自己造成的）

### 15.1 用户的疑问

> "我也有一直开着卸载，怎么之前不行，降级升级后又行了？"

`umount modules` **从来不是那个变量**（§13.2 已证）。真正让虎扑起不来的，
是**本轮开发过程中我们自己造成的三类故障**。历史 tombstone 与 dropbox
把证据完整保留了下来。

### 15.2 原因一：**HupuShield 模块自己的 bug**（最主要）

`/data/tombstones/tombstone_00~06, 20~31`（共 19 个）全部是
`com.hupu.games` + `signal 11 (SIGSEGV) SEGV_ACCERR`，
时间集中在 **22:51:24 → 22:52:13** 的连环爆发，堆栈**每次都一模一样**：

```
#00 strncpy+24                       /apex/.../libc.so
#01 libhupushield.so                 ← 我们的模块
#02 do_dl_iterate_phdr               /apex/.../linker64
#03 __loader_dl_iterate_phdr         linker64
#04 dl_iterate_phdr                  libdl.so
#05 libhupushield.so
#06~#10 libshadowhook.so
#11 libhupushield.so
#12 Java_com_dsh_hupushield_Native_nativeInstall+120
```

故障地址**全部以 `...3e7c` 结尾**（`0x7d80a63e7c` / `0x7d83463e7c` /
`0x7d83103e7c` …），是"往只读页写"的固定偏移。

**这是模块在 `dl_iterate_phdr` 回调里用 `strncpy` 写到 `.rodata` 的经典 bug**
（开发期曾记录为 `hs_dl_trampoline` / `DL_SURVEY` 那个 `static const` 问题）。
它发生在 `nativeInstall` 里，也就是**模块一被加载就崩** ——
跟易盾、跟 `umount modules` 都毫无关系。

`dropbox` 里同一时段的 12 条 `data_app_native_crash@…` 也全部指向
`libhupushield.so`，其中一条显示 `Process uptime: 1s`（起来 1 秒就崩）。

### 15.3 原因二：**SELinux 实验把 zygote 搞崩了**

`tombstone_09 ~ 18`（19:25:47 → 19:36:17）全是 `zygote64` + `SIGABRT`：

```
Abort message: 'JNI FatalError called: (org.lsposed.manager)
  frameworks/base/core/jni/com_android_internal_os_Zygote.cpp:2048:
  selinux_android_setcontext(2000, 0, "platform:privapp:targetSdkVersion=34:complete",
  "org.lsposed.manager") failed'
```

这正是我做 `setenforce 0` / `ksud sepolicy` 那段时间。
**zygote 一崩，任何应用都起不来** —— 这足以表现为"虎扑进不去"。

另外 `tombstone_07`（00:24:30）与 `tombstone_19`（19:36:17）是
`zygote64` 的 `SIGSEGV`，堆栈落在 ART 的
`FaultManager::HandleSigsegvFault` / `Mutex::ExclusiveLock` /
`Runtime::AttachCurrentThread` —— 同样是 zygote 层面的损坏。

### 15.4 原因三：**openat 拦截导致 ANR**

`/data/anr/` 里 21:30 → 00:13 有**几十条** `anr_*`，进程都是 `com.hupu.games`，
Subject 统一是：

```
Subject: App requested: Changing to new focus window timeout
```

这正是模块拦截 `openat` 后监管线程拖慢 I/O 的后果
（§7 记录过：`Timeout waiting for unwind to complete`）。

### 15.5 所以"降级升级后就好了"的真相

不是因为换了版本。版本因素已被三重排除：

1. **清空全部私有数据后行为不变**（§11.1）→ 不是缓存
2. **8.1.12 / 8.2.62 / 8.2.63 三个版本行为一致**（§12.5）
3. 两个检测分支的判据都是**环境**（注入 / root），与包内容无关

真正的分界是那一轮操作把**上面三类自造故障全部清掉了**：

| 时期 | 状态 | 结果 |
|---|---|---|
| 19:25–19:36 | 我在改 SELinux/sepolicy，zygote64 连环崩 | 应用起不来 |
| 21:30–00:13 | 模块开着拦截 openat | 大量 ANR |
| 22:51–22:52 | 模块 bug（dl_iterate_phdr + strncpy）| 虎扑连环 native crash |
| 00:24 | zygote64 再次崩 | 应用起不来 |
| **之后** | **模块卸载 + SELinux 恢复 Enforcing + 未授 root** | **正常** |

### 15.6 一句话总结

- **`umount modules` 开不开都无所谓**，它从来不是变量。
- **之前的失败基本是我这边的锅**：模块自身的 native bug、我做的 SELinux 实验、
  以及我加的 openat 拦截。用户的设置一直是对的。
- 现在能用的**充分必要条件**只有两条：
  1. **LSPosed 作用域里没有"已启用"的模块指向虎扑**（否则触发 Xposed 分支）
  2. **KernelSU 不要给虎扑授予 root**（否则 `/system/bin/su` 可见，触发 root 分支）

两条都满足 ⇒ 虎扑正常运行。用户的"隐藏着用"本来就成立。

---

## 16. 第十一轮：追查「最初那次检测」—— 证据已过期，缩到两个候选

用户指出：**在我写模块之前，虎扑就已经报检测了**，所以 §15 的自造故障
解释不了最初那次。本节是针对性追查。

### 16.1 设备上的历史证据全部过期

| 来源 | 保留范围 | 最早的虎扑相关记录 |
|---|---|---|
| LSPosed `log/` | 仅本轮开机（`log.old/` 为空） | 无 |
| KernelSU `dmesg.log` / `.old` | 仅 2 轮开机 | 无 |
| `/data/system/dropbox` | 241 个文件 | **09-24 20:51** |
| `/data/tombstones` | 67 个文件 | **09-24 19:25** |
| `/data/anr` | — | 09-24 21:30 |
| `/data/misc/logd/` | **不存在**（ColorOS 关了持久化 logcat） | 无 |
| 应用 Bugly `.catch` | 被 01:18–01:22 覆写，且内容混淆 | 无 |

`dropbox` 时间戳换算：epoch `1790254241` ↔ 墙上时间 **09-24 20:51**
（锚点：`1790272502966` = 09-25 01:55:02）。

**而用户的原始报告早于我的介入**（我构建 `HupuShield-1.1.apk` 是 20:01）。

### 16.2 用下载时间重建的时间线（09-24）

| 时间 | 事件 |
|---|---|
| 18:12 | Bugly 会话起（`.catch` 文件名里的 `1790244741914`） |
| 18:21 | 下载 WeiXin |
| 18:34 | 下载 **Zygisk 指纹支付（微信 / 支付宝）** |
| 18:36 | 下载 **LSPosed v2.1.1-7790** |
| 18:38 | 下载 Scene v1.11.0 |
| 19:11 / 19:15 | 尝试下载 Zygisk Next（0 字节失败，`.oplusdownload`） |
| 19:25–19:36 | zygote64 连环崩（我的 sepolicy 实验，见 §15.3） |
| 20:01 | 我构建 HupuShield-1.1 |

**出问题的时间窗正好落在"装 LSPosed + Zygisk 那批模块"的窗口内。**

### 16.3 已排除的候选

| 候选 | 排除依据 |
|---|---|
| **YumyHook 注入** | `firstInstallTime = 2026-09-24 22:22:29`，比原始报告晚约 3 小时 |
| **"虎扑不在 KernelSU 名单里所以看到 su"** | 新实测否证，见 §16.4 |
| `umount modules` | 用户实验 1（关掉+重启后照常） |
| HMA-OSS | 用户实验 2 |
| 我模块自己的 bug / SELinux 崩 zygote / openat ANR | 时间上都晚于原始报告（见 §15） |

### 16.4 新工具 `hs-su` 的实测（重要否证）

`work/hs-su.c`：`prctl(PR_SET_KEEPCAPS,0)` + `setresuid` + `capset` 清零后
实测 `/system/bin/su` 的可见性。

| uid | 身份 | `/system/bin/su` |
|---|---|---|
| 10452 | 虎扑（在 `.allowlist`，`allow=0`） | **ENOENT（隐藏）** |
| **10488** | **MT管理器（在 `.allowlist`，`allow=1`）** | **EXISTS（可见）** |
| 10999 / 10500 / 10666 | **完全不在名单里** | ENOENT（隐藏） |

**结论：KernelSU 对"根本不在名单里"的应用同样隐藏 `su`；
只有 `allow=1` 的应用才看得见。**
所以"当时虎扑不在名单里 ⇒ 它看到 su ⇒ 被检测"这条假设**不成立**。

同时确认：`/system/bin/su` **在磁盘上真实存在**
（`-rwxr-xr-x root shell 324472`，日期 2024-08-13，是 ROM 自带的），
KernelSU 用 `su->sh!` 的路径重写在应用侧把它藏起来。

### 16.5 只剩两个候选（就是已证的两条分支）

1. **root 分支**：当时 KernelSU 给虎扑授权了 root（`allow=1`）
   → `/system/bin/su` 可见 → 「检测到root权限」
2. **Xposed 分支**：当时 LSPosed 里有**已启用**的模块把虎扑圈进了作用域
   → 注入 → 「检测到Xposed环境」

### 16.6 倾向 root 分支的证据（但非铁证）

`/data/adb/ksu/.allowlist` 里 **`com.hupu.games` 有一条 `allow=0` 的条目**。
应用只有在**申请 root 被处理过**之后才会出现在该列表里 ——
对照 `com.android.bankabc`（农业银行）同样是一条 `allow=0`，
典型的"银行 App 主动求 root 被拒"。

"存在一条已拒绝的条目"最自然的解释是：**它曾被授权过，后来被撤销**。
但也可能只是 00:34 那次人工操作的产物 —— **所以只是倾向，不是结论。**

### 16.7 当前 LSPosed 作用域的实况（可查）

读 `modules_config.db`（经 `/sdcard` 中转，避免 `cp` 被 SELinux 拒）：

```
作用域里包含 com.hupu.games 的模块：
  mid 203  com.yumito.yumyhook   enabled=0   ← 唯一一个，且已禁用

其它已启用模块（都不含虎扑）：
  mid 2    com.luckyzyx.luckytool  enabled=1  scope=57
  mid 81   com.bug.hookvip         enabled=1  scope=26
  mid 115  com.omarea.vtools       enabled=1  scope=4
  mid 78   com.wye4.hookforvip     enabled=1  scope=2
  mid 112  me.hd.wauxv             enabled=1  scope=2
  mid 120  com.coderstory.toolkit  enabled=1  scope=2
```

`YumyHook` 的 dex 里 `nis`（网易易盾包名 `com.netease.nis`）命中 **35 次**、
`Xposed` 34 次、`隐藏` 16 次 —— 它是冲着易盾去的对抗模块，
但**安装时间决定了它不可能是最初的原因**。

### 16.8 待用户回答的四个问题（能一锤定音）

1. 最初那个提示的**原话**是什么？（「检测到Xposed环境」／「检测到root权限」／其它）
2. 最初是否是**刚装好 LSPosed / Zygisk 那批模块之后**就出问题？
3. 有没有在 KernelSU 里**给虎扑授权过 root**，或见过「虎扑 请求 root 权限」的弹窗？
4. 最初报检测时，**LSPosed 模块页里有哪些模块是打开的**？

### 16.9 可一锤定音的实验（各一次点击，均可逆）

- **Xposed 分支**：启用 `YumyHook`（作用域里已经只有虎扑）→ 启动虎扑
  → 预期立刻报「检测到Xposed环境」。同时抓 `hs-trace` 看是哪条探测翻盘。
- **root 分支**：已复现（授权 root ⇒ `/system/bin/su` 翻成 EXISTS ⇒ 秒退）。

---

## 17. 第十二轮：**真正的根因** —— 易盾判的是「包名」，解法是 Hide My Applist

### 17.1 决定性证据

用户提供了一份第三方"一键过环境"整合包
（`[20260919第15次修改]一键过环境通用.zip`，58.5 MB）。解包后它的
`files/config.json`（28937 B）**不是普通配置，而是 Hide My Applist 的配置**，
其中**明确写了虎扑**：

```json
"templates":{"白名XJYYDS91":{"isWhitelist":true,
                            "appList":["com.tencent.mobileqq","com.tencent.mm"]}},
"com.hupu.games":{"useWhitelist":true,"excludeSystemApps":true,
                  "applyTemplates":["白名XJYYDS91"],"extraAppList":[]}
```

含义：**对虎扑启用白名单模式 —— 让它只能看见 QQ 和微信，
其它所有包（LSPosed 管理器、各种 Xposed 模块）一律隐藏。**

### 17.2 这份配置早就在设备上，而且已经生效

| 事实 | 值 |
|---|---|
| `/data/adb/config.json` 大小 | **28937 B**（与整合包里那份**逐字节同尺寸**） |
| 它的 mtime | **2026-09-24 18:28** |
| 它的内容 | 就是上面那段 HMA 配置，`com.hupu.games` 白名单在列 |
| 被 HMA 接管的应用数 | **175** |
| `/data/adb/.kernel/` 目录 mtime | **2026-09-24 18:22**（整合包的脚本落地处） |
| 落地脚本 | `/data/adb/.kernel/XJYYDS1环境优化.sh`、`XJYYDS91_环境优化助手.sh` |
| `hma_oss_zygisk` 模块 | **2026-09-24 22:29 安装，无 `disable` → 启用中** |
| Zygisk Next 是否加载它 | **是**（`/data/adb/zygisksu/modules_info` 里有 `hma_oss_zygisk`） |

**所以"装不上"的印象不准确**：整合包的脚本与配置在 18:22–18:28 确实写进了设备，
只是 **HMA-OSS 模块还没装，配置无人执行**。22:29 装上 HMA-OSS 后配置才生效。

### 17.3 为什么是包名检测，而不是我们追了一路的注入检测

设备上装着 **11 个 Xposed/LSPosed 相关应用**，任何 App 查一次
`PackageManager` 就能看到：

```
com.luckyzyx.luckytool   com.bug.hookvip        me.hd.wauxv
com.wye4.hookforvip      com.coderstory.toolkit com.omarea.vtools
com.yumito.yumyhook      com.jy.xposed.skip     io.github.wauxv.v1
com.fkzhang.qqxposed     com.fkzhang.wechatxposed
```

于是：

```
虎扑（新版本）查询已安装包 → 看到 Xposed/LSPosed 相关包
    → 判「检测到Xposed环境」→ 闪退
```

- **老版本虎扑不做这个检查** ⇒ 降级就好（用户两次都是这么"解决"的）
- **新版本一查就中** ⇒ 这就是「检测到Xposed环境」的确切来源

### 17.4 与之前所有结论的关系（全部重新定位）

| 之前的结论 | 在新认识下的地位 |
|---|---|
| root 分支（`/system/bin/su`） | **真实存在，但不是本次的触发点** |
| Xposed 分支的"注入痕迹" | **真实存在（易盾确实扫 maps 68 次），但不是本次的触发点** |
| `umount modules` / LSPosed 作用域 / HMA 开关 | **全是旁支**，都不是关键 |
| 我们写的 HupuShield 模块 | **方向错了** —— 它去挡注入痕迹，而真正的判据是包名 |
| 我 §15 归因的"自造故障" | 那些只解释 19:25 之后的失败，与最初那次无关 |

**为什么我全程跑偏：** 包查询走的是 Binder，`ptrace` 抓 syscall 看不到；
而 HMA 的配置恰好藏在我早期扫到、却没深究的 `/data/adb/config.json` 里。

### 17.5 给用户的结论与建议

**操作铁律：**

1. **不要停用 `hma_oss_zygisk`，也不要删除或覆盖 `/data/adb/config.json`。**
   虎扑现在能用，全靠这两样。停用 HMA ⇒ 立刻退回「检测到Xposed环境」闪退。
2. **那个 58 MB 整合包建议不要装。** 理由：
   - 它打包了 **LSPosed 2.2.0 / Zygisk Next / susfs 1.5.21 / TEE 模拟器 /
     PlayIntegrityFix / TrickyStore / APatch AutoExclude / Scene** 等一整套，
     装上会**替换用户现在稳定工作的 LSPosed / Zygisk Next 版本**
   - **susfs 需要内核支持**，本机内核没有
   - 它的 `post-fs-data.sh` 含**一长串 `rm -rf`**，`customize.sh` 35 KB，
     会额外装 4 个 APK、改属性与 SELinux 相关配置 —— 风险远大于收益
   - **真正需要的那一小块（HMA 配置 + 脚本）已经在设备上**
3. 用户最初"找个过环境的插件"的方向**其实是对的**；
   是我把问题带到了"屏蔽注入检测"这条路上。

---

## 18. 第十三轮：**推翻 §17** —— HMA 从来没有生效过；工具包脚本解码结果

### 18.1 用户的否证实验

用户把 HMA 模块**关闭并重启**，虎扑**依然正常**。实测确认：

| 检查项 | 结果 |
|---|---|
| `/data/adb/modules/hma_oss_zygisk/disable` | **存在**（02:30 创建） |
| Zygisk Next 本次开机加载 | **不含 `hma_oss_zygisk`**（`.old` 里有，对照成立） |
| 11 个 Xposed 相关包 | **`installed=true hidden=false`，全部可见** |
| 虎扑 | 正常运行（同一 pid 持续 2 分钟以上） |

### 18.2 更致命的一条：HMA-OSS 根本没有配置

```
/data/user/0/org.frknkrc44.hma_oss/files/
    profileInstalled
    profileinstaller_profileWrittenForLastUpdateTime.dat
    temp_config.json          ← 1823 B，不是生效配置
（没有 config.json）
```

而且工具包脚本要拷贝的**源文件** `/data/adb/HMA-OSS/config.json` **从来不存在**
（`/data/adb/HMA-OSS/` 目录是空的），老版 HMA `com.tsng.hidemyapplist` **根本没安装**。

**结论：HMA-OSS 一直以空配置运行，从未对虎扑生效。§17 的结论作废。**
（用户此前"开 HMA 也照样进得去"的实验，本来就是因为它什么都没做。）

### 18.3 工具包脚本解码（它们其实是 hex 加密的）

`XJYYDS1环境优化.sh` / `XJYYDS91_环境优化助手.sh` 的**前 3 行是自解码壳**：

```sh
folders=($(find /data/ -maxdepth 1 -mindepth 1 -type d))
random_folder="${folders[$((RANDOM % ${#folders[@]}))]}"
wenjmz="$(date +%s | sha256sum | base64 | head -c 32)"
sed -n "$((LINENO+1)),$ p" < "$0" | xxd -rp > "${random_folder}/$wenjmz"
chmod 700 "$zhixilp"; (sleep 5; rm -fr "$zhixilp") & "$zhixilp" "$@"
```

→ 把第 4 行起的 **hex 解开、丢进随机目录、执行、5 秒后删掉自己**。
（这也是为什么按关键词搜这两份脚本什么都搜不到。）
本地 `xxd -r` 解码后得到 347 行 + 655 行真实脚本。

### 18.4 脚本真正做的事

1. **`resetprop` 伪造约 21 条属性**：`ro.boot.vbmeta.device_state=locked`、
   `ro.boot.verifiedbootstate=green`、`ro.boot.flash.locked=1`、
   `ro.boot.veritymode=enforcing`、warranty_bit=0、`ro.debuggable=0`、
   `ro.secure=1`、`ro.adb.secure=1`、`ro.build.type=user`、
   `ro.build.tags=release-keys`、`sys.oem_unlock_allowed=0`、
   `ro.secureboot.lockstate=locked`…
   **`resetprop -n` 是内存级 → 重启即失效。** 实测现在只有
   `ro.boot.{vbmeta.device_state,verifiedbootstate,flash.locked,veritymode}` 等少数几条
   仍是伪造值（来自 KernelSU/Shamiko），脚本设的其余几条**现在都是空的**。
2. 部署 keybox 到 `tricky_store` / `teesim`（本机没有这两个目录 → 跳过）。
3. 部署 HMA 配置（源文件不存在 → **空转**，见 §18.2）。
4. **大规模清理"搞机痕迹"**（这才是核心）：
   - `/sdcard/Download`、`/Documents`、`/MT2`、`/WechatXposed`、`/imei`、`/km`…
   - `/storage/emulated/0/*.img`、`*.zip`、`*.apk`、`*.txt`、`*.sh`、`*.xml`
     ← **包含易盾会探的 `/sdcard/Download/magisk_patched.img`**
   - 各"环境检测"App 的外部数据（`me.garfieldhan.holmes`、`com.zhenxi.hunter`、
     `icu.nullptr.*`、`com.lingqing.detector`、`io.github.vvb2060.mahoshojo`…）
   - `/data/local/tmp/*` 全部、`shizuku*`
   - `find /storage/emulated/0 -name "*内核*"|"*环境*"|"*驱动*"|"*远程*"|"*私人*"`
   - `/cache/*`、`/data/cache/*`、`/data/dev/pts/*`
   - **`rm -rf /data/system/dropbox/* /data/anr/* /data/log/* /data/tombstones/*`**
5. `iptables -F/-X/-Z`、inotify 上限调整。
6. **自毁并重启**：`mkdir -p /data/adb/modules/XJYYDS91*/remove` + `reboot`。

### 18.5 由此纠正的两处错误

| 我之前的说法 | 实际 |
|---|---|
| "历史证据因日志轮转而过期" | **是被这个脚本在 18:28 显式删除的**（dropbox/anr/log/tombstones 全清） |
| §17：HMA 配置是虎扑能用的原因 | **HMA 从未生效**，原因是两条检测分支当前都不成立 |

### 18.6 当前能用的确切原因（唯一站得住的说法）

| 条件 | 状态 |
|---|---|
| KernelSU 是否给虎扑 root | **否**（`allow: 0`）→ root 分支不触发 |
| LSPosed 作用域里有无**启用**模块指向虎扑 | **无**（全库只有 `YumyHook`，且 `enabled=0`）→ Xposed 分支不触发 |
| HMA | 关闭且从未配置（无关） |
| `umount modules` | 关闭（无关） |
| 易盾会探的文件 | 全部不存在（`/sbin/.magisk/*`、`/system/xposed.prop`、
  `libxposed_art.so`、`/cache/su`、`/data/local/tmp/*`、`magisk_patched.img`…） |

### 18.7 关于 18:00 那次的最终判断

能产生「检测到Xposed环境」的只有 **Xposed 分支**，而它要求
**LSPosed 真的在虎扑上激活了模块**。所以：

> **18:00 那次，LSPosed 确实在虎扑上激活过某个已启用的模块。**

YumyHook（22:22 才安装）已排除。剩下的可能是**当时某个虎扑作用域内的模块，
后来被卸载了** —— LSPosed 的作用域行会随模块卸载**级联删除**，
所以数据库里查不到。而**能证明它的日志（`/data/system/dropbox`、
`/data/anr`、`/data/tombstones`、`/data/log`）已被 18:28 那个脚本清空**。

**因此：18:00 的现场已经无法从设备上还原。** 这不是"证据过期"，
是**用户自己运行的工具包把它抹掉了**。

### 18.8 对那个整合包的最终建议

**不要再用。** 除 §17.5 列出的风险（替换 LSPosed/Zygisk Next、装 susfs、
多条 `rm -rf`）之外，这次解码还确认了它会：

- **整个删除 `/sdcard/Download` 目录**与内部存储根目录下的所有
  `*.apk` / `*.zip` / `*.img` / `*.txt` / `*.sh` / `*.xml`
- **删除系统日志目录**（`dropbox` / `anr` / `log` / `tombstones`）—— 出问题就再也查不到原因
- **清空 `/data/local/tmp`**
- 执行后**自毁并重启**（所以"装不上"其实是"装完就消失"）
- 脚本用随机路径 + 5 秒自删 + hex 加密来规避审计

---

## 19. 第十四轮：**找到了触发事件** —— 用户把 LSPosed 从旧版更新到了 v1.11.0

### 19.1 用户提供的关键信息

> "我更新了 LSP，更新到了 1.11 版，之前是 1.7 版"

设备实测**完全对上**：

```
/data/adb/modules/zygisk_lsposed/module.prop
    id=zygisk_lsposed
    name=Zygisk - LSPosed
    version=v1.11.0 (7209)
    versionCode=7209
    author=JingMatrix & LSPosed Developers
    updateJson=.../JingMatrix/LSPosed/master/magisk-loader/update/zygisk.json
```

且 `/sdcard/Download/v1.11.0_7209.zip`（6.7 MB）的 **mtime = 2026-09-24 18:38**，
与用户描述的时间窗吻合（同一批下载里还有 `LSPosed-v2.1.1-7790-release.zip` 18:36）。

**即：用户装的是 JingMatrix 维护分支的 LSPosed v1.11.0（build 7209），
之前跑的是很旧的版本。**

### 19.2 为什么这能解释「检测到Xposed环境」

LSPosed 的**模块作用域**保存在 `/data/adb/lspd/config/modules_config.db`。
**更新/重装 LSPosed 会重建这个库并重新初始化各模块的作用域**
（本机该库所在目录 `config` 的 mtime = **09-24 19:31**，
而 `zygisk_lsposed` 模块目录 mtime = **09-24 19:30** —— 说明那一小时内发生过
至少两次 LSPosed 安装/更新）。

在这种重装之后，**原本没有被圈进作用域的模块可能被重新纳入**，
于是一个**已启用**的模块开始在虎扑上激活 → 注入 → **Xposed 分支触发**
→ 「检测到Xposed环境」→ 闪退。

这同时解释了用户长期的困惑：

> "我以为是要强制升级了（所以降级就好）"

—— 其实降级虎扑只是**绕开了新版本里那条检查**，而真正的触发源是
**LSPosed 那次更新**。

### 19.3 现状与已证模型仍然自洽

| 条件 | 现在 |
|---|---|
| LSPosed 作用域里指向虎扑的**已启用**模块 | **没有**（全库只有 `YumyHook`，`enabled=0`） |
| KernelSU 是否给虎扑 root | **否**（`allow: 0`） |

两条分支都不成立 ⇒ 虎扑正常。**与 §18.6 完全一致。**

### 19.4 可一键复现（收尾实验）

设备上就有一个**作用域恰好只有虎扑**的模块：`com.yumito.yumyhook`
（mid 203，`enabled=0`，scope = `com.hupu.games`）。

**在 LSPosed 里把它启用 → 启动虎扑 → 预期立刻复现「检测到Xposed环境」+ 闪退。**
再关掉即恢复。这能一次性证实整条因果链（也能顺便核对提示文案）。

### 19.5 给用户的长期经验法则

1. **LSPosed 每次更新/重装之后，都要检查一遍各模块的作用域**，
   尤其是有没有把虎扑圈进去。这是这类"莫名其妙的 Xposed 检测"最常见的来源。
2. 虎扑要正常，只有两条：
   - **LSPosed 作用域里没有任何"已启用"模块指向虎扑**
   - **KernelSU 不要给虎扑授权 root**
3. HMA / `umount modules` / `/data/adb` 可见性 / su 路径 —— **都不是必要条件**，
   别再为它们折腾（§11、§13、§17 的结论均已被实验否证）。

---

## 20. 第十五轮：**发现虎扑有两条不同的检测分支（文案不同）**

### 20.1 实测抓到的第二条文案

在用户**启用 `YumyHook`** 后启动虎扑，用连拍截图抓到了提示原文：

> ## 「检测到该应用在hook环境中运行」

**这与用户最初看到的「检测到Xposed环境」是两条不同的提示。**

| 文案 | 分支 |
|---|---|
| **「检测到该应用在hook环境中运行」** | **通用注入检测** |
| **「检测到Xposed环境」** | **Xposed 专项检测** |

### 20.2 关键细节：YumyHook 其实没加载成功

```
I LSPosed : Loading xposed for com.hupu.games:pushcore/10452
I ActivityManager: Process com.hupu.games (pid 1122) has died: fg SVC

E LSPosedContext: Failed to load class
    com.yumito.yumyhook.xposed.entry.YumyHookModule
java.lang.NoSuchMethodException: YumyHookModule.<init>
    [interface io.github.libxposed.api.XposedInterface,
     interface io.github.libxposed.api.XposedModuleInterface$ModuleLoadedParam]
```

`YumyHook 4.1.4` 用的是**新版 libxposed API，与设备上的
LSPosed v1.11.0 (7209) 不兼容**，模块加载失败。

**所以那条"hook环境"提示完全来自 LSPosed 的注入本身，与 YumyHook 的 hook 逻辑无关。**

### 20.3 由此得到的推论（重要）

既然"LSPosed 注入"只会产生「检测到该应用在hook环境中运行」，
那么**18:00 那次虎扑并没有被注入** —— 否则用户看到的应该是"hook"那条。
**所以最初那次命中的是「Xposed 专项检测」。**

该分支在我们抓到的轨迹里对应的路径是：

```
/system/xposed.prop
/system/framework/XposedBridge.jar
/system/lib{,64}/libxposed_art.so{,.no_orig}
/data/data/de.robv.android.xposed.installer
/data/data/com.virtualprotect.exposed
/data/adb/lspd                        ← 唯一"随环境变化"的一条
/data/adb/riru/modules/{lspd,edxp.prop,dreamland}
/sbin/.magisk/modules/{riru_lsposed,riru_edxposed,taichi}
```

### 20.4 `/data/adb` 权限假设（实验中，已被 YumyHook 污染）

`/data/adb` 是 `0700`，所以应用看 `/data/adb/lspd` 得到 **EACCES**；
**若 `/data/adb` 是 `0755`，同一条会变成 `0 EXISTS`** —— 实测确认：

```
（chmod 0755 /data/adb 后，用 hs-su 降权到 uid 10452）
/data/adb                0   EXISTS
/data/adb/lspd           0   EXISTS
（实验后已恢复 0700，已复核）
```

**若易盾把"EXISTS"判为 Xposed、把"EACCES"判为干净**，那么
**18:00 那次的触发点就是 `/data/adb/lspd` 当时可读**，
而后来某次操作（LSPosed 更新/重装、工具包清理）把它变回了 EACCES。

**但本次验证被 YumyHook 污染**（它仍启用，LSPosed 仍在注入，
hook 分支抢先报错）。**必须先关闭 YumyHook 再重测。**

### 20.5 待办

1. **关闭 `YumyHook`**（恢复虎扑可用状态）
2. 在 YumyHook 关闭的前提下，重做 `/data/adb` 0755 实验：
   - 若报「检测到Xposed环境」→ **根因确定**
   - 若正常进入 → 该假设否证

### 20.6 实验结果：`/data/adb` 假设**已被否证**

用户关闭 `YumyHook` 后重做实验：

**对照（YumyHook 关闭、`/data/adb` = 0700）**

```
8 秒后 pid=27427（存活）
LSPosed 注入虎扑次数 = 0
无死亡记录
```

**实验（`/data/adb` = 0755）**

```
uid 10452 视角：/data/adb = 0 EXISTS，/data/adb/lspd = 0 EXISTS
结束时 pid=29678（存活）
LSPosed 注入虎扑次数 = 0
无死亡记录
截图 = 虎扑启动广告页（"跳过 2"）→ 应用确实正常启动
```

**结论：`/data/adb` / `/data/adb/lspd` 的可见性不是
「检测到Xposed环境」的触发点。** 权限已恢复 `0700`（脚本 trap 兜底 + 事后复核）。

### 20.7 新的领先假设：文案取决于"注入的是什么"

对比两次注入实验：

| 被注入的东西 | 提示 |
|---|---|
| LSPosed 注入，但模块**加载失败**（YumyHook，新 libxposed API 不兼容） | **「检测到该应用在hook环境中运行」** |
| （18:00）推测：注入了一个**能正常加载**的模块 | **「检测到Xposed环境」** |

设备上的其它启用模块（`com.luckyzyx.luckytool`、`com.bug.hookvip`、
`me.hd.wauxv`、`com.coderstory.toolkit`、`com.omarea.vtools`、`com.wye4.hookforvip`）
用的都是**旧版 Xposed API**（日志里可见 `IXposedHookLoadPackage$Wrapper`），
加载时会**把 `XposedBridge` 那一套兼容类带进目标进程**。

**假设：虎扑的「Xposed 专项检测」判的就是进程里有没有
`de.robv.android.xposed` / `XposedBridge` 这些类；
而通用注入检测只看有没有外码映射。
所以只有"能正常加载的旧 API 模块"被注入时，才会报「检测到Xposed环境」。**

这与 §19 的判断一致：18:00 那次是 **LSPosed 更新导致作用域重置**，
某个**旧 API 模块**被重新圈进虎扑 → 报「检测到Xposed环境」。

### 20.8 最后一个可一键验证的实验

**在 LSPosed 里把「虎扑」加进 `com.luckyzyx.luckytool` 的作用域**
（它已启用、旧 API、且能正常加载）→ 启动虎扑。

- 若报 **「检测到Xposed环境」** → 与 18:00 完全一致，**根因链闭环**
- 若报「检测到该应用在hook环境中运行」或正常进入 → 假设否证

验证后把虎扑从该模块作用域移除即可恢复。

### 20.9 实验结果：假设再次否证

用户把虎扑加入 `com.luckyzyx.luckytool`（已启用、旧 API、能正常加载）的作用域后启动虎扑：

> **报的仍然是「检测到该应用在hook环境中运行」**

**结论：只要 LSPosed 往虎扑进程注入，无论被注入的模块是
"旧 API 且加载成功"还是"新 API 且加载失败"，报的都是「在hook环境中运行」。**
§20.7 的假设否证。

---

## 21. 最终结论（第十六轮）

### 21.1 虎扑会报三条不同的话（已全部复现过其中两条）

| # | 文案 | 触发条件 | 验证状态 |
|---|---|---|---|
| 1 | **「检测到root权限」** | KernelSU 给虎扑授予 root（`allow: 1`） | **已复现** |
| 2 | **「检测到该应用在hook环境中运行」** | LSPosed 往虎扑进程**注入任何东西** | **已复现 3 次**（YumyHook 加载失败 / LuckyTool 正常加载） |
| 3 | **「检测到Xposed环境」** | **18:00 那次**，当前环境**无法复现** | 未复现 |

第 2 条不区分"注入的是什么"。第 3 条因此是**独立的第三种判定**。

### 21.2 第 3 条（Xposed 专项）是什么，以及为什么复现不了

易盾的 Xposed 专项检查是**一份固定的文件清单**（§20.3 已列出：`/system/xposed.prop`、
`XposedBridge.jar`、`libxposed_art.so{,.no_orig}`、`/data/data/de.robv.android.xposed.installer`、
Riru / Taichi / Magisk 的成套路径）。**实测这 27 条现在全部不存在**
（唯一"存在"的 `/data/adb/lspd` 已被 §20.6 否证）。

**所以当时至少有一条是存在的，而它现在没了。**

设备上留下的两条线索：

1. **Magisk 残留**：`/data/adb/magisk`、`/data/adb/magisk.db`（40960 B）、
   `/data/adb/post-fs-data.d`、`/data/adb/service.d` —— 时间戳很老，
   说明**这台机器以前用过 Magisk**。Magisk 时代
   `/sbin/.magisk/modules/{riru-core,riru_lsposed,...}` 这些路径是存在的。
2. **LSPosed 在 09-24 19:30 被重装为 Zygisk 版**（`/data/adb/modules/zygisk_lsposed/`
   的 mtime = 19:30，内含 `manager.apk`/`daemon.apk`），版本 v1.11.0 (7209)；
   用户自述"更新到了 1.11 版，之前是 1.7 版"。

**推论：** 用户原来的 LSPosed 是**旧形态（Riru/Magisk 时代）**，
它会在系统里留下 `/system/xposed.prop`、`libxposed_art.so`、
`/data/adb/riru/modules/lspd`、`/sbin/.magisk/modules/riru_lsposed` 之类的产物 →
**Yidun 的 Xposed 专项检查命中** → 「检测到Xposed环境」。
**18:36–19:30 那次更新到 Zygisk 版 LSPosed，把旧形态的产物替换/清除了** →
第 3 条提示从此消失。

这也解释用户"很久以前也犯过一次、降级就好了"：
每次 LSPosed 换形态或大版本更新，旧形态的残留会短暂存在；
而重装/降级虎扑时恰好也会连带清掉一些残留，于是看起来像"版本问题"。

### 21.3 当前可用配置（请保持）

| 项 | 值 |
|---|---|
| KernelSU 是否给虎扑 root | **否** |
| LSPosed 作用域里是否有**已启用**模块指向虎扑 | **无** |
| HMA | 开关都行（无关） |
| `umount modules` | 开关都行（无关） |
| `/data/adb` 权限 | `0700`（无关） |
| SELinux | Enforcing |

### 21.4 以后再遇到时的排查顺序

1. **看它报的是哪一句** —— 三句话对应三个完全不同的原因：
   - 「检测到root权限」→ KernelSU 里把虎扑的 root 关掉
   - 「检测到该应用在hook环境中运行」→ LSPosed 作用域里有人把虎扑圈进去了，
     **逐个模块检查并取消勾选**
   - 「检测到Xposed环境」→ 系统里存在 Xposed/Riru/Magisk 残留文件，
     按 §20.3 的清单逐条查
2. **不要**去动 HMA、`umount modules`、`/data/adb` 权限、su 路径 —— 实测全部无关。

### 21.5 被实验否证的假设清单（避免重复劳动）

| 假设 | 否证方式 |
|---|---|
| `umount modules` 是关键 | 用户关闭并重启后照常运行 |
| HMA 隐藏应用列表是关键 | 关闭后照常；且 HMA 从未有过配置 |
| 应用列表/包名可见性是关键 | 11 个 Xposed 相关包完全可见时仍正常 |
| `/data/adb` / `/data/adb/lspd` 可读是关键 | 改为 0755 使应用可见后仍正常 |
| "注入一个能正常加载的旧 API 模块会报 Xposed" | 实测仍报「hook环境中运行」 |
| 我写的 HupuShield 模块是解法 | 方向错误：真正判据与注入痕迹无关 |

---

## 22. 第十七轮：**回到最初的日志** —— §19 的推论被推翻

用户提醒："能不能从最开始留的记录找到蛛丝马迹？原来的 LSPosed 也是 Zygisk 版，
我是从 Zygisk 1.7 升级到 1.11。"（即**不是** Riru→Zygisk 的形态切换）

### 22.1 最初的日志还在

`work/` 下保留着**我介入之前**的抓包：

| 文件 | 时间 | 说明 |
|---|---|---|
| `logcat-launch.txt` | **09-24 18:52** | 第一次复现（含 Toast 原文） |
| `logcat-run2.txt` | 09-24 18:54 | 干净复现 |
| `FEASIBILITY.md` | 09-24 18:54 | **第一份分析报告** |
| `logcat-umount.txt` | 09-24 19:07 | 关掉 umount 后 |
| `logcat-shield.txt` | 09-24 19:13 | — |

### 22.2 ★ 决定性发现：最初那次 **LSPosed 注入 = 0**

对全部历史 logcat 统计 `Loading xposed for com.hupu.games` 与虎扑死亡次数：

| 日志 | 时间 | **注入虎扑** | 死亡 |
|---|---|---|---|
| logcat-launch | **18:52** | **0** | 8 |
| logcat-run2 | 18:54 | **0** | 4 |
| logcat-umount | 19:07 | **0** | 7 |
| logcat-shield | 19:13 | **0** | 7 |
| **lc.txt** | **20:34** | **27** | 26 |
| lc2 | 20:35 | 0 | 6 |
| lc3 | 20:50 | 5 | 10 |
| lc9 | 21:35 | 29 | 29 |
| logcat-prev | 22:50 | 41 | 114 |

**注入是从 20:34 才出现的 —— 而 `HupuShield-1.1.apk` 的构建时间是 20:01。
也就是说：注入完全是我自己的模块带来的。**
19:13 之前（含最初的 18:52）**虎扑进程里一次注入都没有**。

→ **§19 的推论（"LSPosed 更新导致某个模块被圈进虎扑作用域、开始注入"）作废。**
**最初那次「检测到Xposed环境」与注入无关。**

### 22.3 ★ 最初的 Toast 原文与时间点

```
09-24 18:52:09  启动进程 28520
09-24 18:52:11.053  W/NotificationService: ... the following toast was blocked
    and discarded: TextToastRecord{2aae9c5 28520:com.hupu.games/u0a452
    isSystemToast=false ... text=检测到Xposed环境 duration=0}
09-24 18:52:11.068  紧接着发起网络请求（uid/pid:10452/28520）
```

启动后 **2 秒**就弹了这条 —— 且此时**注入 = 0、未授 root**。

### 22.4 ★★ 我第一份报告（18:54）里其实已经写对了方向

`FEASIBILITY.md` §4 记录了我当时对 APK 做的**全量字节扫描**（69 个 `.so` + `classes.dex`，
ASCII + UTF-16LE 双编码）：

| 特征串 | 位置 |
|---|---|
| `de.robv.android.xposed.XposedBridge` / `XposedHelpers` | 仅 `classes.dex` |
| `com.elderdrivers.riru.edxp.config.EdXpConfigGlobal`（EdXposed） | 仅 `classes.dex` |
| `isInstallXposed` / `isRooted` | 仅 `classes.dex` |
| `com.topjohnwu.magisk` | 仅 `classes.dex` |
| **`xposedmodule` / `xposedminversion`（扫模块清单）** | **仅 `classes.dex`** |
| 成套 su 路径表 | 仅 `classes.dex` |
| **`Xposed` / `magisk` / `frida` / `substrate`** | **native 层 69 个 .so 一处都没有** |

**→ 判定逻辑在 Java 层，且包含"扫描已安装模块的清单（`xposedmodule` 元数据）"。**
**这就是我 18:54 的判断，后来被我自己丢掉了。**

同时那份报告 §7 的"备选方案"（把虎扑加进 Zygisk denylist / Shamiko 白名单
让 LSPosed 不注入）**在当时就注定无效** —— 因为本来就没有注入。
这一点我 18:54 就该看出来，却花了七个小时用实测才确认。

### 22.5 为什么现在不报（推测，但有依据）

虎扑 `targetSdk=30`，在 Android 14 上受**包可见性过滤**约束。
`dumpsys package` 读出的虎扑 `<queries>` 清单里**没有任何 Xposed 模块**
（全是支付 / 推送 / 设备 ID SDK 需要的包：淘宝、微信、支付宝、京东、美团…）。

**→ 它 `getInstalledPackages()` 大概率根本拿不到用户装的那 11 个 Xposed 模块，
所以现在不报。**

### 22.6 时间线上唯一"新出现"的东西

```
18:22–18:28  工具包脚本执行 + 自毁重启
18:34        zygisk-module-xfingerprint-pay-{alipay,wechat} 目录时间戳
18:36–18:38  下载并更新 LSPosed（1.7 → v1.11.0 7209）
18:52        ★ 虎扑首次报「检测到Xposed环境」，注入 = 0
```

这两个新变量（**指纹支付 Zygisk 模块** / **LSPosed 更新**）是当时唯一"新出现"的东西。
**目前没有直接证据区分它们** —— 包查询走 Binder，`logcat` 不记录。

### 22.7 要彻底钉死还缺什么

1. **用户手上还有 LSPosed 1.7 的 zip 吗？**（设备上已被工具包清空 `*.zip`）
   有的话解包看 `customize.sh` / `post-fs-data.sh` / `service.sh`，
   就能知道 1.7 会造哪些 1.11 不造的文件，直接对上易盾的检查清单。
   （对照：整合包里 LSPosed **2.2.0** 的模块内容 = `machikado` / `mazoku` / `lspd` /
   `daemon` / `framework.dex` / `manager.apk` / `daemon.apk` / `zn_modules.txt`，
   安装时 `rm -f /data/adb/lspd/manager.apk`。）
2. 或者接受当前结论：**"注入"与"root"是仅有的两条已证分支；
   最初那次是第三条、纯 Java 层的"模块清单/文件"检查，而它现在被包可见性挡着。**

---

## 23. 收尾（用户结束会话时）

### 23.1 设备最终状态（已验证可用）

```
虎扑：启动 9 秒后存活，LSPosed 注入 = 0，无死亡记录        ✅ 正常
LSPosed 作用域含虎扑的模块 = 仅 com.yumito.yumyhook (enabled=0)
KernelSU 对虎扑授权 = allow: 0
SELinux = Enforcing        /data/adb = 700
dalvik.vm.dex2oat-flags = 空        denylist_enforce = 0
HMA = 停用（且从未有配置，本就无效）
```

### 23.2 已清理 / 已保留

- **设备**：删除我推送的全部工具、脚本、日志、截图、APK 与数据库副本；
  **保留** boot 三件套备份 与 虎扑应用数据备份（`/data/local/tmp` 由 ~1.2 GB 降到 783 MB，
  其中 780 MB 就是这两组备份）。
- **电脑**：删除约 1.2 GB 派生产物（应用数据解包、截图、旧 LSPosed 解包、整合包解包、
  数据库副本等）；项目由 ~2.1 GB 降到 879 MB。
  **保留**：全部文档、模块源码、自制工具源码与二进制、最初那两次的原始 logcat、
  APK 与解包产物、boot 备份副本。

### 23.3 教训文档

**`LESSONS.md`** —— 包含：

- 三句话对应三个原因的对照表（**以后出问题先看文案**）
- 当前环境快照 + 一键自查命令
- **复发预判**（LSPosed 更新重置作用域 / 手滑圈入虎扑 / 授权 root /
  装新模块往 `/system` 写文件 / 换回旧版 LSPosed / 虎扑再次大版本更新）
- 技术教训 7 条（含"`/data/adb` 永远 EACCES 因而整类路径不可能是触发点"这一条关键否证）
- **方法教训 6 条**（最重要的一条：我 18:54 写的第一份报告里就已经有正确方向，
  却没有回头读它，绕了七个小时）
- 运维提醒（**永不使用那个会删除系统日志的"一键过环境"整合包**——本次现场正是被它抹掉的）
- 附录 A：易盾 Xposed 检查的完整文件清单（供复发时逐条排查）
- 附录 B：保留的资产清单

### 23.4 仍未闭合的一条

**附录 A 中 Riru 分支往 `/system/lib{,64}` 写的 `libriruloader.so` / `libriru_*.so`
是唯一"机制与清单能对上、又可直接验证"的候选。**
验证方法：临时 KernelSU 模块放一个 `system/lib64/libriruloader.so` 空文件 → 重启 →
启动虎扑。报「检测到Xposed环境」即根因确认。需 2 次重启，用户已决定不再验证。












