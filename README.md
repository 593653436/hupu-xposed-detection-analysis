# 虎扑 Xposed 检测机制 逆向分析记录

对虎扑（`com.hupu.games`）Android 客户端的 **Xposed 环境检测机制**做的完整逆向分析记录，
包含：加固壳行为、检测路径清单、被复现的检测分支、8 个假设的验证与否证过程、
以及一套自制的 Android/arm64 分析工具源码。

> **一句话结论**：虎扑会报**三句不同的话**，对应**三个完全不同的原因**。
> 排查时**先看它报的是哪一句**。

---

## 核心结论

| # | 提示文案 | 触发条件 | 验证状态 |
|---|---|---|---|
| 1 | **「检测到root权限」** | KernelSU 给该应用授予了 root（`allow: 1`）→ `/system/bin/su` 对它可见 | 已复现 |
| 2 | **「检测到该应用在hook环境中运行」** | LSPosed 往该应用进程里**注入任何东西**（不论被注入的模块是否加载成功） | 已复现 3 次 |
| 3 | **「检测到Xposed环境」** | 系统里存在 Xposed / Riru / Magisk 的**残留文件**（清单见下） | 仅历史记录中出现，未能复现 |

第 2 句**不区分注入内容** —— 实测「模块加载失败」和「模块正常加载」两种情况报的都是它。
所以第 3 句来自另一条独立判定，与注入无关。

### 历史现场的关键证据

在一次**尚未安装任何自研模块**的抓包中（`work/logcat-launch.txt`，见正文）：

```
LSPosed 注入该应用次数 = 0
18:52:11.053  W/NotificationService: ... the following toast was blocked
              and discarded: TextToastRecord{... text=检测到Xposed环境 duration=0}
```

**注入 = 0、未授 root，却报了 Xposed 环境** → 它查的是**文件 / 包清单**，不是注入痕迹。

---

## 一些值得记录的实测事实

- **检测是三段式的**：Java 层文件/包查询 + `/proc/self/maps` 扫描（启动期 68 次）
  + `stat` 系列探文件存在性。
- **native 层没有 Xposed 字样**：对 APK 内 69 个 `.so` 与 `classes.dex` 做 ASCII + UTF-16LE
  双编码全量扫描，`Xposed` / `magisk` / `frida` / `substrate` **在 native 层一处都没有**，
  全部出现在 Java 层（含 `xposedmodule` / `xposedminversion` —— **扫描已安装模块的清单**）。
- **它从不执行命令**：启动期实测 `faccessat` 947 次、`newfstatat` 459 次、`openat` 462 次、
  `readlinkat` 94 次，而 **`execve` / `execveat` = 0 次**。纯 `stat` 探测。
- **`/data/adb` 是 `0700`**，所以应用探任何 `/data/adb/...` 永远只得到 `EACCES`，
  而 `EACCES` 是被容忍的 → **这一整类路径在结构上不可能成为触发点**（已用 `chmod 0755` 实验否证）。
- **KernelSU 的 su 隐藏按 `allow` 决定**，不是"名单内/名单外"：
  不在名单里的 uid 同样得到 `ENOENT`，只有 `allow=1` 的应用看得到 `/system/bin/su`。
- **自毁是"干净退出"**：不是崩溃，日志里没有 `FATAL` / `signal` / `tombstone`。

---

## 检测清单（第 3 句「检测到Xposed环境」相关）

<details>
<summary>展开完整路径清单</summary>

```
/system/xposed.prop
/system/framework/XposedBridge.jar
/system/lib/libxposed_art.so
/system/lib/libxposed_art.so.no_orig
/system/lib64/libxposed_art.so
/system/lib64/libxposed_art.so.no_orig
/system/lib64/libriruloader.so          ← Riru 分支会写在这里
/system/lib64/libriru_edxp.so           ← EdXposed
/data/data/de.robv.android.xposed.installer
/data/data/com.virtualprotect.exposed
/data/data/com.topjohnwu.magisk
/data/adb/riru/modules/lspd             （注：/data/adb 是 0700，
/data/adb/riru/modules/edxp.prop         应用只能拿到 EACCES，
/data/adb/riru/modules/dreamland         而 EACCES 被容忍 → 这一组实际无关）
/data/adb/lspd
/data/misc/riru/modules/edxp
/data/misc/riru/modules/dreamland
/data/misc/taichi
/sbin/.magisk/modules/riru-core
/sbin/.magisk/modules/riru_lsposed
/sbin/.magisk/modules/riru_edxposed
/sbin/.magisk/modules/taichi
/sdcard/Download/magisk_patched.img
/data/fart   /sdcard/fart   /data/dexname
/data/local/tmp/frida-server
/data/local/tmp/re.frida.server
```

另有成套的 su 路径探测表（34 条，RootBeer 风格）：

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

</details>

---

## 仓库内容

```
BREAKTHROUGH.md      主记录：全部实验、数据与否证过程（23 节，最完整）
LESSONS.md           收尾与教训：三句话对照表、自查命令、复发预判、方法复盘
FEASIBILITY.md       最早的分析报告（含对 APK 的全量字节扫描结果，结论至今有效）
FINDINGS.md          早期发现（部分结论已被后续实验推翻，文中已标注）
YIDUN-REFERENCE.md   网易易盾加固的行为参考

tools/               自制的 Android/arm64 分析工具（C 源码，NDK 26.3 编译）
  hs-trace.c           arm64 ptrace 系统调用追踪器，带返回值聚合表
  hs-su.c              降权到指定 uid 实测路径可见性（KernelSU 权限对照）
  hs-acctest.c         降权 + 清空能力位后的文件访问实测
  hs-dexdump.c         从 /proc/<pid>/mem 扫描 dex 镜像并转储
  hs-nshide.c          setns 进入目标挂载命名空间并 overmount
  hs-nshide-daemon.c   轮询目标进程、对每个 pid 做 setns+overmount
  hs-as.c              以指定应用 uid/能力读取文件

module/               自研 LSPosed 模块 HupuShield 的源码
                      （⚠️ 方向已被证明错误：它去挡"注入痕迹"，
                        而判定实际与注入无关。此处仅作存档。）
```

### 编译工具

```bash
# NDK 26.3，动态链接（静态链接会触发 ARM64 Bionic 的 TLS 对齐问题）
aarch64-linux-android26-clang -O2 -fPIE -pie -o hs-trace hs-trace.c
```

---

## 自查：出问题时先跑这个

```bash
# 1) 是否被注入
adb shell "logcat -c; am force-stop com.hupu.games; \
  am start -n com.hupu.games/com.hupu.games.main.MainActivity; sleep 8; \
  logcat -d | grep -c 'Loading xposed for com.hupu.games'"

# 2) 是否被杀
adb shell "logcat -d | grep 'com.hupu.games.*has died' | tail -n 3"

# 3) 环境快照
adb shell "su -c 'getenforce; stat -c %a /data/adb'"

# 4) LSPosed 作用域里有没有它
adb shell "su -c 'cat /data/adb/lspd/config/modules_config.db > /sdcard/mc.db'"
adb pull /sdcard/mc.db
sqlite3 mc.db "select m.module_pkg_name,m.enabled from scope s \
  join modules m on m.mid=s.mid where s.app_pkg_name='com.hupu.games';"
```

### 复发预判

LSPosed 更新/重装后作用域被重置 · 手滑把目标应用圈进某模块作用域 · 给目标应用授权 root ·
装了新模块往 `/system` 或 `/data/data` 写清单里的文件 ·
换回旧版 LSPosed（1.8.x/1.9.x 带 `system.prop`；Riru 分支会写 `/system/lib{,64}`）·
目标应用再次大版本更新。

---

## 未包含的内容（有意排除）

- **虎扑官方 APK、解包产物、加固壳 dex** —— 属于第三方版权内容，不适应公开分发。
- **设备分区备份** —— 个人设备固件。
- **第三方模块 APK** —— 版权归属他人。
- **原始 logcat** —— 含设备标识与个人应用列表（正文中仅引用结论性片段）。

---

## 第三方组件归属

`module/` 中随源码保留了两个被引用的开源库头文件/源码：

- **ShadowHook** — © ByteDance，MIT License
- **xHook** — © iQiyi，MIT License

它们遵循各自原始许可证。

---

## 许可证

本项目采用 **MIT License** —— 见 [`LICENSE`](LICENSE)。

`module/` 中随源码保留的第三方组件遵循各自原始许可证（均为 MIT，见上）。

---

## 免责声明

本项目为**安全研究与兼容性分析**用途：理解一款应用自身的环境检测逻辑是如何工作的。
文中所有实验均在**作者本人拥有的设备**上进行。请遵守当地法律与相关服务条款。
