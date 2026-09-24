# 虎扑 Xposed 检测对抗 —— 完整技术结论

日期：2026-09-24
目标：让 `com.hupu.games` 8.2.62 在已 root（KernelSU + LSPosed）的设备上正常运行
**当前状态：未达成目标。已完成对防护机制的完整逆向，代码与工具链就绪。**

> **注意：本文部分结论已在第二轮被推翻，请先读 `BREAKTHROUGH.md`。**
> 要点：自毁不是 `exit_group` + 恢复 `SIG_DFL`，而是**三级降级链** ——
> ① `exit_group` ② `rt_sigprocmask` 屏蔽 SIGILL + `udf` ③ SIGSEGV。
> 前两级已被实证瓦解，且过程中修掉了三个我们自己的 bug。

---

## 1. 一句话结论

虎扑被 **网易易盾加固**。它在 `libnesec.so` 的 `JNI_OnLoad` 阶段完成 Xposed 判定，
并在 **`Application.onCreate` 之前**用干净的系统调用 `exit_group` 结束进程。
这条链路在 Java 层完全不可达；在 native 层我们已能**拦住退出**，但拦截后的未定义延续
会触发 `udf` 自毁指令（SIGILL），目前尚未跨过这一关。

---

## 2. 证据链（按发现顺序）

| # | 观察 | 证据 |
|---|---|---|
| 1 | 应用启动约 1.5s 后弹 Toast 并自杀 | `NotificationService: text=检测到Xposed环境`；`Process com.hupu.games (pid N) has died: fg TOP` |
| 2 | 无 FATAL、无 tombstone、无信号 | 崩溃缓冲区为空 → 是**主动终止** |
| 3 | 静态逆向受阻 | APK 内 `classes.dex` 名义 100MB，DEX 头只描述 **66KB / 30 类**的空壳；真实代码运行时解密到 `/data/user/0/com.hupu.games/.cache/classes.dex` |
| 4 | 加固厂商 | 空壳类为 `com.netease.nis.wrapper.*`，版本串 `7.6.3_943` → **网易易盾** |
| 5 | 检测逻辑在 Java 层还是 native？ | 对 69 个 `.so` 做 ASCII+UTF-16 全量扫描：`de.robv.android.xposed.*`、`isInstallXposed`、su 路径表等**全部只在 classes.dex，.so 中一个都没有** |
| 6 | 判定发生的精确时刻 | 自研探针：`loadLibrary0(nesec) from com.netease.nis.wrapper.o` 之后进程即死，**`Application.onCreate` 从未执行** |
| 7 | 死因（关键） | 无 seccomp 时：`has died`，**无任何信号** → 干净退出；开 seccomp 拦住 exit 后：`Zygote: exited due to signal 4 (Illegal instruction)` |
| 8 | 自毁不可捕获的原因 | ~~壳用内联 `rt_sigaction` 在 trap 前恢复 `SIG_DFL`~~ **← 此结论已被推翻，见 `BREAKTHROUGH.md`**。真实原因：壳用 `rt_sigprocmask` 屏蔽 SIGILL，同步信号无法投递，内核只能执行默认动作 |

**第 7 条是最关键的推理**：SIGILL 是**我们自己的 seccomp 造成的次生现象**，
说明 seccomp **确实拦住了壳的 `exit_group`**——即原始死因就是一次干净的系统调用退出。

---

## 3. 已尝试的手段与结果

| 手段 | 代码位置 | 结果 | 原因 |
|---|---|---|---|
| Java hook（Toast/进程退出/类名/文件/包管理器/堆栈） | `Guards.java` `Hiders.java` | ❌ 无效 | 判定发生在 `Application.onCreate` 之前，Java 层没有机会 |
| KernelSU「卸载模块」+ Zygisk Next「遵守排除列表」 | — | ❌ 无效 | UMOUNT 只还原**文件挂载**，管不到 zygote 注入 |
| GOT 补丁 hook `exit`/`_exit`/`abort`/`kill`/`syscall` | `hupushield.c` + xHook | ⚠️ 装上但从未触发 | 调用发生在 `JNI_OnLoad` 内，而 GOT 补丁只能在 dlopen **返回后**执行 → 结构性来不及 |
| GOT 补丁 hook `open`/`openat`/`fopen`/`readlink` | 同上 | 无输出 | 同上，或壳不调用这些符号 |
| GOT 补丁 hook `sigaction`/`signal` | 同上 | 无输出 | 壳用**内联** `rt_sigaction`，绕过 libc |
| seccomp 拦 `exit_group`/`exit`/`tgkill`/`kill` | `install_seccomp_block()` | ✅ **成功拦住退出**，但后续触发 SIGILL | 调用方在系统调用失败后进入未定义路径，撞上 `udf` |
| seccomp 额外精确拦 `rt_sigaction`（仅 `args[0]==SIGILL`） | 同上 | ✅ 生效 | 阻止壳撤销我们的处理器 |
| SIGILL 处理器 + PC 跳过 4 字节 | `sigill_handler()` | ⚠️ 安装成功但未触发 | 2.2 版因**顺序错误**（seccomp 先装，把自己的 `sigaction` 也拦了，报 `EPERM`）；2.3 修正顺序后仍未触发，说明还有其他未覆盖的路径 |

---

## 4. 当前代码状态

工程：`module/`（Java + native，AGP 8.5.2 / Gradle 8.7 / NDK r26d / CMake 3.22.1）

```
app/src/main/java/com/dsh/hupushield/
  ShieldEntry.java   入口，按 Scope 只对 com.hupu.games 生效
  Cfg.java           开关：probe / blockToast / blockKill / hideFramework / blockNative
  Ctx.java           免 Context 初始化（直接拼 /sdcard/Android/data/<pkg>/files）
  XLog.java          双通道日志：logcat + 文件（logcat 会被应用配额挤掉）
  Probe.java         调用栈探测
  Forensics.java     毫秒级时间轴：Application/Provider/类加载/库加载/文件访问
  Guards.java        Toast 拦截 + 进程退出拦截
  Hiders.java        Xposed/su/包管理器/堆栈隐藏
  Native.java        native 桥接（含从 APK 解压 .so 的兜底加载）
app/src/main/cpp/
  hupushield.c       全部 native 逻辑
  xhook/             iqiyi xHook（GOT 补丁）
```

**运行时配置**（免重新编译，改完重启应用即生效）：
`/sdcard/Android/data/com.hupu.games/files/hupushield.conf`

**坑位警告（本项目踩过的，务必遵守）**：
1. **绝不要 hook `@CallerSensitive` 方法**：`System.loadLibrary(String)`、`Class.forName(String)`。
   它们用 `Reflection.getCallerClass()` 定位 classloader，被 hook 后调用者变成桥接类，
   库/类会在错误命名空间查找 → `UnsatisfiedLinkError` → 应用直接 FATAL。
   要拦类加载就 hook 三参数重载 `Class.forName(String, boolean, ClassLoader)`。
2. `XposedHelpers.findMethodExact` 用 `getDeclaredMethod`，**不查父类**。
   `Application.attachBaseContext` 实际在 `ContextWrapper` 上。
3. LSPosed 给模块建 `LspModuleClassLoader`，只认 **APK 内**的库路径
   （`base.apk!/lib/arm64-v8a`）→ `useLegacyPackaging` 必须为 **false**（.so 不压缩）。
4. xhook 的 `xhook_register` 必须在任何 `xhook_refresh` **之前**调用，
   否则报 `do not register hook after refresh()`。
5. 钩子里不要用 `_exit()` 兜底（xhook 会 patch 自己的 GOT → 无限递归），
   改用 `syscall(__NR_exit_group, ...)`，并 `xhook_ignore` 自身。
6. seccomp 与信号处理器的**安装顺序**：必须**先装 SIGILL 处理器，再装 seccomp**，
   否则 seccomp 会拦掉自己的 `rt_sigaction(SIGILL)`，报 `Operation not permitted`。

---

## 5. seccomp 用户态通知阶段（路线 1）—— 已验证有效，但受内核限制

### 5.1 拿到的东西

`traceOpenat=1` 用 seccomp user notification 拦截全部 `openat`，实测**一次启动 4119 次调用**，
其中壳的行为一目了然：

```
[openat 48]  /proc/self/maps
[openat 60]  /data/app/.../lib/arm64/libnesec.so     ← 加载易盾
[openat 62]  /proc/self/maps
[openat 63]  /proc/self/maps
[openat 66]  /proc/30529/maps                        ← 用自己的 pid 查
[openat 73~87] /proc/self/maps ×15 …
```

**判定入口是 `/proc/self/maps` 扫描**，已确认。

### 5.2 伪造已成功

`fakeMaps=1` 用 `SECCOMP_IOCTL_NOTIF_ADDFD` 把一份过滤过的 memfd 直接注入 `openat` 的返回值：

```
MAPS FAKED (#1, /proc/self/maps, dropped=7, newfd=83)
maps survey: raw=316234 bytes, data_app_lines=9, dropped=7
```

**实测效果：主进程存活时间从约 200 ms 提升到约 11 秒（同一 PID，约 55 倍）。**

对照实验（同样开追踪、只关伪造）主进程每次采样都抓不到，**证明提升来自伪造本身，而不是追踪开销**。

### 5.3 关键发现：LSPosed 在 maps 里没有名字

maps 全量扫描显示，**非系统路径的 `.so` 只有虎扑自己的 `libnesec.so`**，完全没有
`liblspd.so` / `liblsplant.so`——因为 Zygisk 是用 **memfd 从内存加载**的，映射**不带文件路径**。

所以检测不可能靠"找 liblspd.so 这个名字"，它找的是**行结构特征**：`r-xp` 但**没有路径**的
匿名可执行映射（以及 `/memfd:` 路径）。过滤逻辑据此改为按行字段结构判断，一次删掉 **7 条**。
（合法的 ART JIT 区域带 `[bracket]` 伪名，因此"要求完全无路径"不会误伤。）

### 5.4 尚未跨越的坎

| 问题 | 状态 |
|---|---|
| 内核**不允许** `SECCOMP_FILTER_FLAG_NEW_LISTENER \| TSYNC`（返回 EINVAL） | 只能覆盖**主线程**。**但见 5.5：实测所有 maps 读取都来自主线程**，所以这并非瓶颈 |
| 监听线程不能调用 `openat`（会自锁） | 已解决：过滤器安装**前**就打开 `/proc/self/maps` 并保留 fd，之后只用 `lseek + read` |
| **存活约 11 秒后仍被终结** | **当前真正的瓶颈，原因未明** |

**结论：maps 伪造已经被打穿（11 秒的存活即为证据），11 秒之后必然还有第二个判定通道。**
它不在 maps 读取上（线程已确认），也不在 `openat` 之外我们观测过的网络路径上（拦截开销反而伤害性能）。
下一步应当是**扩大观测面而非继续加拦截**：用 seccomp 通知（只记录）覆盖 `mmap`、`openat` 之外的
`faccessat`/`newfstatat`、以及来自**其他线程**的 `openat`，找出 11 秒那一刻到底发生了什么。

### 5.5 两个被否证的假设（省下了大量弯路）

**假设 A：壳在后台线程里读 maps，所以需要逐线程装过滤器 → 否证。**
seccomp 通知自带被阻塞线程的 TID（`req.pid`），打出来一看：

```
maps read from tid=20780 (distinct so far: 1)
```

**自始至终只有主线程一个线程读 maps**，而主线程正是我们已经覆盖的那个。所以"hook `pthread_create`、
让每个新线程自装 listener"这套复杂机制**完全没必要**——幸好先花一轮验证，没有直接去写。

**假设 B：每次 ADDFD 在目标进程新建 fd 会泄漏，需用 SETFD 固定 fd 号 → 否证且有害。**
改成固定 `newfd=1000` 后，存活时间**从约 11 秒掉回约 2 秒**。原因是壳会**同时持有多个 maps fd**，
固定号互相覆盖 → 它读到不一致的内容 → 反而更快被判定。**自动分配才是对的。**

顺带也测掉了另一个改动：把 `connect`/`sendto`/`readlinkat` 一并纳入追踪（想查是否存在
"上报服务器后由服务端裁决"的击杀），观测到壳确实在反复 `connect` 重试、并用 `readlinkat`
读 `/proc/self/fd/*`，但**拦截这三个系统调用的往返开销把 11 秒的成果吃回了 2 秒**，故过滤器
保持只拦 `openat`。

### 5.6 当前最优配置（已固化进 v4.2）

```
traceOpenat=0
fakeMaps=1        # 仅拦 openat + ADDFD 自动分配 fd + 按行结构过滤
```

效果：主进程存活约 **11 秒**（同一 PID），而原始状态约 **200 毫秒**。

---

### 5.8 ⚠️ 重要更正：所谓"存活 11~21 秒"是**卡死**，不是战果

早期结论把"主进程存活时间从 200ms 提升到 11~21 秒"当成进展。**后续取证推翻了它：**

```
PID     USER      %CPU  STAT  NAME
23090   u0_a452   0.0   S<    com.hupu.games
```

- **CPU 占用 0.0%，状态 `S<`（可中断睡眠）** → 进程在**阻塞**，不是在被检测前多跑了一会儿
- 心跳线程本应每 250 ms 打一行，12.7 秒内应约 50 行，**实测只有 11 行** → 连模块自己的线程都被饿死
- 全程**从未出现 `Application.onCreate`** → 应用根本没有往前走

**真实因果：被拦截的 `openat` 通知存在未被应答的情况，导致线程永久阻塞在系统调用上。**
所以那段时间是**我们把它卡住了**，而不是我们骗过了检测。

**含义：**
1. 对照实验（只拦截不伪造）确实心跳为 0、200 ms 快循环；开伪造确实变成阻塞 —— 差异是真的，
   但**差异的内容是"从快速被杀"变成"被挂起"，不是"变成可用"**。
2. 这个方向若要继续，第一个要修的不是检测对抗，而是**监听端的健壮性**：必须保证每个通知
   都被应答（`poll` 多路复用 + 超时 + 对 `ENOENT`/并发情形兜底），否则一定死锁。
3. **在修好这个之前，任何"存活时间变长"的读数都不能当作有效性证据。**

### 5.9 本项目踩到的三个"教科书级"陷阱

1. **`/proc` 是惰性生成的**：单次 `read()` 只返回约一页（实测 4030 字节）。必须循环读到 EOF，
   否则 maps 永远只有开头 4 KB——里面既没有应用库，也就永远删不掉任何东西。
2. **`ioctl` 的序号与方向必须与内核完全一致**：
   `NOTIF_RECV=IOWR(0)`、`NOTIF_SEND=IOWR(1)`、`NOTIF_ID_VALID=IOW(2)`、**`NOTIF_ADDFD=IOW(3)`**。
   把 ADDFD 写成 `IOWR(2)` 会得到 EINVAL。
3. **`ADDFD` 成功时返回的是新 fd 号，不是 0**。按 `==0` 判断成功会把成功误判为失败
   （日志显示 `ADDFD failed: Success`），并继续对已被消费的通知发 SEND，引发一串 ENOENT。


## 6. 继续攻克的候选路线

**路线 1：把 seccomp 的拦截点从"退出"前移到"检测输入"**
壳的判定必然要读取某些证据（`/proc/self/maps`、su 路径、属性、JNI 类查找）。
用 seccomp 的 `SECCOMP_RET_TRAP` + `SECCOMP_IOCTL_NOTIF`（用户态通知，
需要 `SECCOMP_FILTER_FLAG_NEW_LISTENER`）重定向 `openat`/`readlink`，
对指定路径返回伪造内容。这是现代的、精确度最高的做法，不需要 GOT 补丁、不受内联影响。

**路线 2：让 SIGILL 处理器真正生效**
2.3 仍未捕获到 trap，需要确认：壳是否用 `rt_sigaction` 之外的方式（如
`SECCOMP`/`prctl`/多线程竞态）绕过；可先用 `SECCOMP_RET_TRAP` 让内核把所有
exit 族系统调用转成 SIGSYS，并在 SIGSYS 处理器里打印 `si_syscall`，
彻底确认壳的完整终止路径清单。

**路线 3：系统层替换 `libnesec.so`**
用 KernelSU 模块在 `post-fs-data` 阶段 bind-mount 一个打过补丁的 `libnesec.so`，
直接 nop 掉判定分支。成本最高（需要逆向该 .so 的检测函数），但一旦成功最稳定。

---

## 7. 环境与工具链（复现用）

- 设备：OnePlus PJX110 / Android 14 (SDK 34) / arm64-v8a，序列号 `<DEVICE_SERIAL>`（USB）
- root 栈：KernelSU v1.0.1 (LKM) + Zygisk Next 1.1.0 + Shamiko + LSPosed
- 本机工具（`<TOOLS>\`）：
  - `platform-tools\adb.exe`（37.0.1）
  - `android-sdk\`（platform 34 / build-tools 34.0.0 / **ndk 26.3.11579264** / cmake 3.22.1）
  - `gradle\gradle-8.7\`
  - `dl\api-82.jar`（Xposed API）
- JDK：`C:\Program Files\Microsoft\jdk-17.0.10.7-hotspot`
- 构建：`gradle.bat -p <REPO>\module assembleDebug --no-daemon`
- **网络**：`services.gradle.org` 在本机不可达（超时），Gradle 走腾讯镜像
  `https://mirrors.cloud.tencent.com/gradle/`；NDK 走
  `https://mirrors.cloud.tencent.com/AndroidSDK/`

## 8. 设备侧注意事项

- **Zygisk Next 的「遵守排除列表」若开启且 `com.android.shell` 在列表内**，会让
  LSPosed 管理器进程 `org.lsposed.manager` 因缺少 SELinux `seapp_contexts` 规则而 abort，
  表现为"管理器卡启动 + 所有模块失效"。旧版 LSPosed 只豁免进程名 `com.android.shell`。
- ColorOS 的「应用分身」会让 `adb install` 的 commit 阶段**极慢（可达数分钟）**，
  不是失败，需后台长等待。
- ColorOS 的「不稳定应用」机制会对反复崩溃的应用追加强停。
