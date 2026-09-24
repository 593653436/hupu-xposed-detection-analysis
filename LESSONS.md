# 虎扑 Xposed 检测 —— 收尾、教训与复发预判

> 日期：2026-09-25 凌晨
> 设备：OnePlus PJX110 / Android 14 / KernelSU + Zygisk Next + Shamiko + LSPosed
> 结论状态：**虎扑 8.2.63 当前完全正常**；根因已定位到"两条可复现分支 + 一条被抹掉现场的历史分支"

---

## 一、虎扑会报三句话，对应三个完全不同的原因

**这是整套排查里唯一真正重要的一件事。以后出问题，先看它报的是哪一句。**

| # | 文案 | 触发条件 | 验证状态 | 怎么修 |
|---|---|---|---|---|
| 1 | **「检测到root权限」** | KernelSU 给虎扑授予了 root（`allow: 1`）→ `/system/bin/su` 对它可见 | **已复现** | KernelSU 管理器里关掉虎扑的 root 授权 |
| 2 | **「检测到该应用在hook环境中运行」** | LSPosed 往虎扑进程里**注入任何东西**（不管模块是否加载成功） | **已复现 3 次** | LSPosed 里逐个模块检查作用域，把虎扑取消勾选 |
| 3 | **「检测到Xposed环境」** | 系统里存在 Xposed / Riru / Magisk 的**残留文件**（清单见附录 A） | **最初那次（18:52）**，当前无法复现 | 按附录 A 清单逐条查，删残留 |

> 第 2 条不区分"注入的是什么"——实测过：模块加载失败的 `YumyHook` 和正常加载的
> `LuckyTool`，报的都是第 2 句。所以第 3 句必然来自另一条独立判定，与注入无关。

**第 3 句最初那次的关键证据**（`work/logcat-launch.txt`，09-24 18:52，**我还没写任何模块时**）：

```
LSPosed 注入虎扑次数 = 0
18:52:11.053  W/NotificationService: ... text=检测到Xposed环境 duration=0
```

→ **注入 = 0、未授 root，却报了 Xposed。** 所以它查的是**文件/包**，不是注入。

---

## 二、现在这套环境为什么能用（快照，出问题时照着对比）

```
SELinux                    = Enforcing
/data/adb 权限             = 700
dalvik.vm.dex2oat-flags    = (空)
denylist_enforce           = 0
HMA (hma_oss_zygisk)       = 停用（disable 文件存在；且从未有配置，本就无效）
LSPosed 版本               = v1.11.0 (7209)  JingMatrix 分支
LSPosed 作用域含虎扑的模块  = 仅 com.yumito.yumyhook，enabled=0          ← 关键
KernelSU 对虎扑授权         = allow: 0（未授权）                          ← 关键
虎扑进程 LSPosed 注入       = 0 次
```

**能用的充分必要条件只有两条：**

1. **LSPosed 作用域里没有"已启用"的模块指向虎扑**
2. **KernelSU 不把 root 授给虎扑**

其余全部无关（见第五节否证清单）。

---

## 三、之后会不会再出现？—— 会，而且能预判

### 3.1 最可能的复发场景

| 场景 | 会报哪句 | 为什么 |
|---|---|---|
| **LSPosed 更新 / 重装 / 恢复备份后，某个模块的作用域被重置** | 第 2 句 | 作用域库 `modules_config.db` 会重建；被重新圈进去的模块立刻开始注入 |
| **某次手滑把虎扑加进了某个模块的作用域** | 第 2 句 | 同上 |
| **KernelSU 里给虎扑授权了 root**（弹窗点了"允许"） | 第 1 句 | `/system/bin/su` 对 `allow=1` 的应用可见 |
| **装了新的 root/Xposed 相关模块，往 `/system` 或 `/data/data` 写了易盾清单里的文件** | 第 3 句 | 附录 A 的清单 |
| **换回旧版 LSPosed（1.8.x / 1.9.x）或 Riru 分支** | 第 3 句 | 老版本带 `system.prop`；**Riru 分支会往 `/system/lib{,64}` 写 `libriruloader.so` / `libriru_*.so`** —— 正是易盾清单里的两条 |
| **虎扑再次大版本更新，检查项变多** | 任意 | 历史上你两次遇到问题都伴随虎扑升级；这是最不可控的一条 |

### 3.2 一键自查（出问题时先跑这个）

```powershell
$adb = "<TOOLS>\platform-tools\adb.exe"
# 1) 是否被注入
& $adb shell "logcat -c; am force-stop com.hupu.games; am start -n com.hupu.games/com.hupu.games.main.MainActivity; sleep 8; logcat -d | grep -c 'Loading xposed for com.hupu.games'"
# 2) 是否被杀
& $adb shell "logcat -d | grep 'com.hupu.games.*has died' | tail -n 3"
# 3) 环境快照
& $adb shell "su -c 'getenforce; stat -c %a /data/adb; getprop dalvik.vm.dex2oat-flags'"
# 4) 作用域里有没有虎扑（需先把库拷到 /sdcard）
& $adb shell "su -c 'cat /data/adb/lspd/config/modules_config.db > /sdcard/mc.db'"
& $adb pull /sdcard/mc.db work\mc.db
& "<TOOLS>\platform-tools\sqlite3.exe" work\mc.db "select m.module_pkg_name,m.enabled from scope s join modules m on m.mid=s.mid where s.app_pkg_name='com.hupu.games';"
```

**第 3 句（Xposed 残留）的自查清单见附录 A。**

### 3.3 缓释建议

- **别再用那个"一键过环境"整合包**（理由见第五节 5.3）——它会把现场抹掉，导致下次出问题仍然查不出原因。
- **LSPosed 每次更新/重装之后，打开模块页检查一遍作用域**，特别是虎扑有没有被圈进去。
- **不要给虎扑授 root。**
- 如果以后想彻底不操心：**保持不在虎扑上用任何 Xposed 模块**，这就是最稳的状态。

---

## 四、技术教训（这次真正学到的东西）

1. **易盾的检测是"三段式"，而且 native 层没有 Xposed 字样。**
   对 69 个 `.so` + `classes.dex` 做 ASCII/UTF-16 双编码全量扫描：`Xposed` / `magisk` /
   `frida` / `substrate` **在 native 层一处都没有**；全部出现在 Java 层
   （`XposedBridge`、`XposedHelpers`、`EdXpConfigGlobal`、`isInstallXposed`、`isRooted`、
   **`xposedmodule` / `xposedminversion`**、成套 su 路径表）。
   → 纯 Java 层拦截在原理上可行。

2. **"注入"与"root"是两条独立分支，文案不同。** 不要把两条混着谈。
   （`/system/bin/su` 的可见性实测：`allow=0` → ENOENT；`allow=1` → EXISTS。）

3. **`/data/adb` 是 `0700`，所以应用探任何 `/data/adb/...` 永远只会得到 `EACCES`，
   而 `EACCES` 是被容忍的。**
   → **所有 `/data/adb/*` 路径在结构上不可能成为触发点**，这一整类假设可以直接划掉。
   （实测：临时 `chmod 0755 /data/adb` 让 `/data/adb/lspd` 对应用变成 `EXISTS`，虎扑照样正常。）

4. **KernelSU 的 su 隐藏是按 `allow` 决定的，不是"名单内/名单外"。**
   对完全不在名单里的 uid 同样隐藏（实测 uid 10999/10500/10666 全部 ENOENT）。

5. **LSPosed 的作用域记录会随模块卸载级联删除** —— 所以"历史上哪个模块圈过虎扑"
   事后无法回查。这也是最初那次无法从数据库还原的原因之一。

6. **LSPosed 老版本与新版本的文件差别**（这条差点就是答案）：
   | | 1.8.6 / 1.9.2 | 1.11.0 |
   |---|---|---|
   | `system.prop` | **有**（`dalvik.vm.dex2oat-flags=--inline-max-code-units=0`） | **没有** |
   | Riru 分支 | 会写 `/system/lib{,64}/libriru*.so` | 无（Zygisk 分支不碰 `/system`） |
   其中 `dalvik.vm.dex2oat-flags` 那条**已实测否证**（设回旧值不触发）。

7. **`/proc/self/maps` 只是它检查的一部分。** 启动期实测：
   `faccessat` 947 次、`newfstatat` 459 次、`openat` 462 次、`readlinkat` 94 次、
   打开 `/proc/self/maps` 68 次，**`execve` / `execveat` = 0 次**
   —— 它**从不执行** `su` 或任何命令，纯靠 stat 探文件存在性。

---

## 五、方法教训（我做得不好的地方，逐条记账）

### 5.1 最严重：没有第一时间读自己写的报告

**我 18:54 写的第一份 `FEASIBILITY.md` 第 4 节，已经写明了正确方向：**
"Xposed 特征串只在 Java 层，`native 层 69 个 .so 一处都没有`"，并且列了
**`xposedmodule` / `xposedminversion`（扫模块清单）**。

同一份报告第 7 节我还写了"把虎扑加进 Zygisk denylist / Shamiko 白名单让 LSPosed 不注入"
作为备选方案 —— **而这条在当时就注定无效，因为本来就没有注入**。

**这两件事只要回头读一遍自己 5 小时前的报告就能发现。我花了七个小时用实测才确认。**

### 5.2 统计一下历史日志的"注入次数"，一条命令就能排除整条注入线

`work/logcat-launch.txt`（18:52）和 `logcat-run2.txt`（18:54）一直躺在硬盘上。
**只要对它们 `grep -c 'Loading xposed for com.hupu.games'`，就能立刻看到 0。**
我是到最后你提醒"回到最开始留的记录"才去查的。

### 5.3 提了 8 个假设，被否证 7 个 —— 而且多数本可以先验证再下结论

| 假设 | 结论 | 本可以怎样更快否证 |
|---|---|---|
| `umount modules` 是关键（§11） | ❌ 否证 | 让用户关掉重启即可（确实这么做了） |
| HMA 隐藏应用列表是关键（§17） | ❌ 否证 | 先看 HMA 到底有没有配置文件 —— 它**从来没有配置** |
| 应用列表/包名可见性是关键 | ❌ 否证 | 11 个 Xposed 包完全可见时仍正常 |
| `/data/adb` 可见性是关键 | ❌ 否证 | 一条 `chmod` 就能测 |
| LSPosed 更新导致注入（§19） | ❌ 否证 | 统计历史日志的注入次数 |
| 能正常加载的旧 API 模块会报"Xposed" | ❌ 否证 | 加一次作用域就能测 |
| 老版 `system.prop` 的 dex2oat 属性 | ❌ 否证 | 一条 `setprop` 就能测 |
| Riru 分支往 `/system` 写文件 | ⚠️ 未验证（机制能对上，但需要 2 次重启） | — |

**教训：假设必须配一条"一条命令就能否证"的实验；能先测的不要先写结论。**
我过早把结论写进文档（§11 / §17 / §19 都被我自己推翻），浪费了你的信任和时间。

### 5.4 操作事故：把手机搞重启了

**对 `/data/adb` 做递归 `grep -r`，撞上 `ksu/modules.img` —— 那是个 1 TB 的稀疏文件，
`grep` 试图把整个 1 TB 当文本读，I/O 打满触发看门狗，手机直接重启。**

**规矩：永远不要对 `/data/adb`（或任何可能含巨大稀疏文件/镜像的目录）做递归搜索。
要查就指名具体文件。**

### 5.5 差点动了不该动的东西

LSPosed 的实时数据库 `modules_config.db`（WAL + 运行中的 lspd）—— 全程只读拷贝，
没有直接写入。**这类"应用正在使用的数据库"不要在它运行时替换文件。**

### 5.6 根源性的方法错误

正确的顺序应该是：

```
① 先看最早的现场记录（日志/报告/时间线）
② 再统计一切可量化的证据（注入次数、死亡次数、文件清单、属性值）
③ 然后才提假设
④ 每个假设配一条能一键否证的实验
⑤ 结论要标注"已实测 / 推测"
```

我实际做的是 **③→④→①**，把最有力、最便宜的证据留到了最后。

---

## 六、给你的运维提醒

### 6.1 那个"一键过环境"整合包，建议永不使用

解包 + 解码它的两份脚本（hex 加密 + 随机路径 + 5 秒自删）后确认，它会：

- **`rm -rf /data/system/dropbox/* /data/anr/* /data/log/* /data/tombstones/*`**
  ← **这次正是它把 18:00 那次的现场彻底抹掉了**，导致后面所有排查都缺证据
- **整个删除 `/sdcard/Download`**，以及内部存储根目录的 `*.apk` / `*.zip` / `*.img` / `*.txt` / `*.sh` / `*.xml`
- **清空 `/data/local/tmp`**
- 删除各"环境检测"App 的外部数据
- 清空 iptables、改 inotify 上限
- 用 `resetprop` 伪造约 21 条 boot/verified-boot 属性（**内存级，重启即失效**）
- 执行完 **`mkdir /data/adb/modules/XJYYDS91*/remove` 然后 `reboot`** —— 自毁重启
  （所以你觉得"装不上"，其实是"装完就消失"）

它是个正当的"过环境"工具，但它**以删除现场为设计目标**。
在你需要排查问题的场景下，它是有害的。

### 6.2 日常两条铁律

1. **LSPosed 作用域里，永远不要有"已启用"的模块指向虎扑。**
2. **KernelSU 里永远不要给虎扑授权 root。**

做到这两条，虎扑就是稳定的。

---

## 附录 A：易盾 Xposed 专项检查的文件清单

出第 3 句「检测到Xposed环境」时，逐条查这些路径（当前全部不存在）：

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

**尚未验证的一条**（机制能对上、但需要 2 次重启）：
临时做一个 KernelSU 模块，里面放 `system/lib64/libriruloader.so`（空文件即可）→ 重启
→ 启动虎扑。若报「检测到Xposed环境」则根因确认；验证后删模块再重启恢复。
这是唯一一条"机制与清单能对上、又能直接验证"的路径。

---

## 附录 B：这次留下的资产

**设备（`/data/local/tmp`，共 ~783 MB）**

| 文件 | 说明 |
|---|---|
| `boot_a_backup.img` / `boot_b_backup.img` / `init_boot_a_backup.img` | **刷机前备份，务必保留**（本次全程未刷任何分区） |
| `hupu-data-backup.tgz`（408 MB） | 清数据前的虎扑应用数据 —— **需要恢复登录状态时用** |

**电脑（`<REPO>`，共 ~879 MB）**

| 路径 | 说明 |
|---|---|
| `BREAKTHROUGH.md` | 主记录，第 1–22 节含全部实验与否证过程 |
| `FINDINGS.md` / `FEASIBILITY.md` / `YIDUN-REFERENCE.md` | 早期分析（**FEASIBILITY 第 4 节的字节扫描结论仍然有效**） |
| `LESSONS.md` | 本文件 |
| `module/` | HupuShield 模块源码（**方向已被证明错误，仅作存档**） |
| `work/hs-*.c` + 二进制 | 自制工具：`hs-trace`(ptrace 追踪)、`hs-su`(权限对照)、`hs-acctest`、`hs-dexdump`、`hs-nshide` |
| `work/logcat-launch.txt` / `logcat-run2.txt` | **最初那次的原始现场日志（最有价值的历史证据，勿删）** |
| `work/new/`、`work/old/`、`work/classes.dex` | 虎扑 8.2.62 / 8.1.12 的解包产物与加固壳 dex |
| `work/boot-backup/` | boot 分区备份（电脑侧副本） |
| `work/hupu-8.2.63.apk` / `hupu-old.apk` | 当前版与降级版 APK |

**已清理**：约 1.1 GB 的中间产物（应用数据解包 482 MB、截图、旧 LSPosed 解包、
集成包解包、数据库副本、PC 侧 408 MB 备份副本等）。
