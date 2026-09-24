# 虎扑 Xposed 检测屏蔽模块 —— 可行性验证报告

日期：2026-09-24
目标设备：`<DEVICE_HOST>:<PORT>`
结论：**可行（FEASIBLE）**，但需你配合完成 2 个手动步骤，并存在 1 项中等风险。

---

## 1. 设备与框架环境（已验证）

| 项目 | 实测结果 |
|---|---|
| 连接 | `adb connect <DEVICE_HOST>:<PORT>` 成功，TCP 端口可达 |
| 机型 / 系统 | OnePlus **PJX110**，Android **14**（SDK 34），arm64-v8a |
| 编译版本 | `PJX110_14.1.0.403(CN01)` |
| Root 方案 | **KernelSU**（`/proc/mounts` 中挂载点标记为 `KSU`，lowerdir 指向 `/data/adb/modules/...`） |
| Zygisk | **Zygisk Next**（root 进程 `zygiskd64`） |
| 隐藏模块 | **Shamiko**（root 进程 `zygiskd64-zygisk_shamiko`，`/debug_ramdisk/shamiko/`） |
| LSPosed | **已安装且正在运行**（进程 `org.lsposed.manager`）——因启用了"隐藏管理器"，`pm list packages` 查不到 |
| 其他 | `me.weishu.kernelsu` 管理器、`scene_systemless` 模块；已装多个 Xposed 模块（微X、`com.jy.xposed.skip` 等） |

> 注意：`adb shell` 拿不到 root（`su` 不存在于 `/system/bin`，`/data/adb` 被 SELinux 拒绝）。
> 这是 Shamiko 正常工作的表现，但意味着**模块的启用/作用域配置必须在手机上的 LSPosed 管理器里手动完成**。

## 2. 目标应用

| 项目 | 值 |
|---|---|
| 包名 | `com.hupu.games` |
| 版本 | **8.2.62.09111**（versionCode 12310） |
| SDK | minSdk 24 / targetSdk 30 |
| ABI | arm64-v8a |
| 主 Activity | `com.hupu.games/.main.MainActivity` |
| 副进程 | `com.hupu.games:pushcore`（PushService）、MqttService |
| APK | 77,445,213 字节，sha256 `1A4213FC39B6EF6DF774D177C00032BD74EF91D9BD0AC81523E8352990BAF763` |

### 2.1 加固情况（重要）

APK 内 `classes.dex` 名义大小 100 MB，但 **DEX 头部只描述一个 66 KB / 30 个类的空壳**：

- 壳类：`com.netease.nis.wrapper.{Entry, MyApplication, MyJni, NEDialog, Utils, plugin/*}`，版本串 `7.6.3_943`
- 结论：**网易易盾（NetEase Yidun）加固**
- 运行时真实代码被解密写入应用私有目录：`/data/user/0/com.hupu.games/.cache/classes.dex`
  （由日志 `NoSuchMethodError ... appears in /data/user/0/com.hupu.games/.cache/classes.dex` 证实）
- 影响：**静态反编译真实逻辑受阻**（文件头被剥离），但**不影响 LSPosed 运行期 hook**

## 3. 检测行为（已实证复现）

### 3.1 实测症状

清空日志 → 启动 App → 观察，得到完整时间线：

| 时刻 | 事件 |
|---|---|
| 18:53:28.925 | `Start proc 1354:com.hupu.games` |
| 18:53:29.484 | `Start proc 2213:com.hupu.games:pushcore` |
| 18:53:30.227 | **弹出 Toast 窗口**（`addWindow ... window=Window{... Toast}`） |
| 18:53:31.243 | **`Process com.hupu.games (pid 1354) has died: fg TOP`** |
| 18:53:32.267 | MqttService 拉起新进程 4735 |
| 18:53:35.012 | `Process com.hupu.games (pid 4735) has died: svc SVC` |

Toast 原文（另一轮运行中由系统日志捕获）：

```
W/NotificationService: Package com.hupu.games is above allowed toast quota,
  the following toast was blocked and discarded: TextToastRecord{... 
  text=检测到Xposed环境 duration=0}
```

### 3.2 关键判定：这是"主动自杀"，不是崩溃

日志中**没有** `FATAL EXCEPTION`、`signal`、`SIGABRT/SIGSEGV`、`tombstone`。
→ 说明应用是**主动调用** `Process.killProcess()` / `System.exit()` 结束自身。

**净效果：在当前的 KernelSU + LSPosed 环境下，虎扑一启动就"弹提示 + 自杀"，完全无法使用。**

## 4. 检测发生在哪一层？（决定方案可行性）

对 APK 内 **69 个 `.so`** 与 `classes.dex` 做全量字节扫描（ASCII + UTF-16LE 双编码）：

| 特征串 | 出现在 |
|---|---|
| `de.robv.android.xposed.XposedBridge` | ✅ 仅 `classes.dex`（3 处） |
| `de.robv.android.xposed.XposedHelpers` | ✅ 仅 `classes.dex` |
| `com.elderdrivers.riru.edxp.config.EdXpConfigGlobal`（EdXposed） | ✅ 仅 `classes.dex` |
| `isInstallXposed` / `isRooted` | ✅ 仅 `classes.dex` |
| `com.topjohnwu.magisk`、`xposedmodule` / `xposedminversion`（扫模块清单） | ✅ 仅 `classes.dex` |
| 成套 su 路径表（`/system/bin/su`、`/su/bin/su`、`/sbin/su` …） | ✅ 仅 `classes.dex` |
| **`Xposed` / `xposed` / `magisk` / `frida` / `substrate`** | ❌ **69 个 .so 中一个都没有**（含 UTF-16） |

> `libnesec.so`、`libmsaoaidsec.so` 确实引用了 `/proc/self/maps`（可疑，属易盾/阿里 SecurityGuard 的通用反调试检查），
> 但**没有任何 Xposed 相关字符串存在于 native 层**。

**结论：触发"检测到Xposed环境"并导致自杀的判定逻辑位于 Java 层 → LSPosed 模块可以在运行期拦截。**

## 5. 可行性结论

| 前提条件 | 状态 |
|---|---|
| 设备可远程 adb 控制 | ✅ |
| LSPosed 框架可用 | ✅ 已安装运行 |
| 目标应用可被 hook | ✅ Java 层检测，LSPosed 在 fork 阶段注入，早于 `Application.onCreate`，**时序无忧** |
| 检测点可定位 | ⚠️ 需运行期探测（因加固，静态反编译受阻） |
| 无需 root 即可安装模块 APK | ✅ `adb install` 即可 |
| 启用模块 / 配置作用域 | ❌ **必须你在手机上手动操作**（adb 无 root） |

## 6. 建议的模块设计

**模块名：** `HupuShield`（作用域限定 `com.hupu.games`，不影响其他应用）

分三层，先做定位、再做拦截、最后收口：

### 第 0 层 · 探测（先导）
- 带 `DEBUG_PROBE` 开关：对可疑 API（`Class.forName`、`File.exists`、`PackageManager.getPackageInfo`、
  `Process.killProcess`）做**只记录不拦截**的 hook，把调用方堆栈写入 `/sdcard/HupuShield.log`。
- 目的：把易盾壳里真正的检测方法（形如 `com.netease.nis.wrapper.*`）钉出来，后续精准 hook，减少副作用。

### 第 1 层 · 保命（行为拦截）
- Hook `android.widget.Toast.makeText/show` → 丢弃文案含 `检测到Xposed环境` 的 Toast。
- Hook `android.os.Process.killProcess` / `System.exit` / `Runtime.halt` → 当调用栈来自易盾壳类时**阻止自杀**。

### 第 2 层 · 治本（检测原语屏蔽）
| Hook 目标 | 处理 |
|---|---|
| `Class.forName` / `ClassLoader.loadClass` | 对 `de.robv.android.xposed.*`、`com.elderdrivers.riru.edxp.*`、`org.lsposed.*` 抛 `ClassNotFoundException` |
| `Throwable.getStackTrace` / `Thread.getStackTrace` | 过滤含 `LSPHooker_`、`lspd`、`XposedBridge` 的栈帧 |
| `java.io.File.exists` | 对 su 路径表返回 `false` |
| `Runtime.exec` / `ProcessBuilder.start` | 拦截 `su`、`which su`、`mount`、`ps` 等侦察命令 |
| `PackageManager.getPackageInfo/getInstalledPackages/getInstalledApplications` | 隐藏 `com.topjohnwu.magisk`、`me.weishu.kernelsu`、`org.lsposed.manager`、`com.fkzhang.*` 等；并剥离清单里的 `xposedmodule` meta-data |
| `SystemProperties.get`（反射） | 隐藏 `ro.debuggable`、`ro.secure`、`init.svc.*` |
| `android.os.Build.TAGS` | 归一为 `release-keys` |

## 7. 风险与备选方案

### 风险（中等）
易盾 native 层（`libnesec.so`）若也做 hook 检测并触发自杀，**纯 Java hook 无法覆盖**。
缓解：Shamiko 已在本机运行，通常能隐藏 `liblspd.so` / zygisk 痕迹；必要时需把虎扑加入 Shamiko 白名单。

### ⭐ 备选方案（零代码，可能直接解决）
如果**你并不需要任何 Xposed 模块去 hook 虎扑**，那么把 `com.hupu.games` 加入
**Zygisk denylist / Shamiko 白名单**即可让 LSPosed 不对它注入 —— 应用看不到 Xposed，检测自然不触发。
代价：其他模块（去广告等）也不能再作用于虎扑。

## 8. 需要你确认/配合的事项

1. **确认目标**：是否就是"让虎扑在本机正常启动、不再自杀"？还是你在意的是别的现象？
2. **手动启用模块**：构建出 APK 后，需你在手机 LSPosed 管理器中启用并勾选作用域 `com.hupu.games`。
3. **构建环境**：本机已有 JDK 17，但**缺 Android SDK**，我需要下载 command-line tools+build-tools（约 150 MB）才能出包。

## 9. 素材与工具位置

```
<REPO>\
  work\hupu-8.2.62.apk      # 从设备拉取的原始 APK
  work\classes.dex          # 抽出的 100MB 加固 DEX
  work\apk\                 # APK 解包结果（6106 个文件）
  work\logcat-launch.txt    # 首次启动全量日志（含 Toast 原文）
  work\logcat-run2.txt      # 干净复现日志（含自杀时间线）
  work\dexscan.js           # DEX 解析器
  work\locate.js / u16scan.js # 全 APK 特征串扫描（ASCII/UTF-16）

<TOOLS>\platform-tools\adb.exe   # 本次安装的 adb 37.0.1
```
