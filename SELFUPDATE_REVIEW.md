# Komari Zig Agent 自更新调查与实测报告

## 结论

**会替换本机正在运行的 agent 二进制；本地编译、手改版本没有特殊保护，更新不会合并或保留其修改。** 更新只比较版本，不识别“本地定制版”。源码目录和普通配置、数据、其他文件不是更新目标。

修复前确认四项缺陷，均已局部修复并实测通过：更新辅助文件冲突导致数据破坏、明确 CLI 禁用被 env/JSON 覆盖、版本前缀不一致导致回滚失效、正常 HTTP POST 上报后的健康版本被误回滚。未发现 SHA256 校验缺失或校验失败仍替换的问题。

修复后，明确传入 `--disable-auto-update` 能禁止启动及定时的新更新，即使 env/JSON 设置 false；**它不是文件不可修改保证**：已经发生更新的安全回滚仍会执行，受信任服务端的通用远程 `exec`、terminal，以及人工更新脚本也不受此开关限制。

## 本次修复：自动更新源切换到本仓库

- 原默认仓库为 `src/version.zig` 中硬编码的 `luodaoyi/komari-zig-agent`；`src/update.zig` 的 `repo = version.repo` 用它构造 latest Release API。现改为本仓库 `Moyucharm/komari-zig-agent`，默认端点为 `https://api.github.com/repos/Moyucharm/komari-zig-agent/releases/latest`。
- 目的：防止上游 Zig 仓库发布更高版本后，将我们编译部署的定制二进制覆盖为上游原版。没有关闭或删除自动更新；启动检查、6 小时定时检查、版本比较、校验及回滚逻辑不变。
- 本仓库当前没有 Release，所以暂时不会自动更新二进制；检查仍执行，无 Release 时可能记录检查失败。代理回退只代理同一个本仓库 URL，不会切换回上游仓库。
- 将来本仓库发布更高版本、具备当前平台匹配资产及有效 SHA256 校验信息的 Release 后，后续检查就能正常更新到本仓库改版，无需再次改代码。
- `KOMARI_RELEASE_API_URL` 非空时仍可覆盖端点；缺失或空值使用本仓库。默认不查询上游的保证不涵盖人为指向上游的覆盖配置；部署时应清理这种旧配置，并重新编译、部署本次修复后的二进制。
- `test/update_test.zig` 的永久回归直接调用生产 URL 解析函数，断言完整端点等于本仓库 URL 且不含上游 owner。改常量前真实失败（实际为上游 URL），改常量后 `All 1 tests passed.`；原来只复制覆盖字符串的辅助函数及对应测试已替换，bootstrap 中只固定旧仓库字符串的断言已移除。
- 独立临时可执行程序通过 `runtime.init` 捕获真实进程环境，调用同一个生产 URL 解析函数并断言结果；按“变量缺失、空值、非空覆盖”顺序得到以下真实输出。没有下载 Release 或覆盖部署中的二进制，也未等待 6 小时。

```text
PASS release URL: https://api.github.com/repos/Moyucharm/komari-zig-agent/releases/latest
PASS release URL: https://api.github.com/repos/Moyucharm/komari-zig-agent/releases/latest
PASS release URL: http://127.0.0.1/release/latest
```

本次全量测试使用指定 Zig 0.16.0 路径执行，真实结果如下；临时 URL 实测源码和可执行文件已清理。改动保留在工作区，未提交 commit。

```sh
export PATH=/tmp/zig-x86_64-linux-0.16.0:$PATH
zig build test --summary all
```

```text
Build Summary: 66/66 steps succeeded; 229/232 tests passed (3 skipped)
test success
```

以下调查与多场景实测记录属于此前的更新安全修复，保留为背景；本次没有重跑这些历史场景。

## 调查范围和验证方法

- 用户指定基线：`main` / `186327c`；调查针对任务开始时的实际工作区，保留已有修改，未 reset。
- 实测平台：Linux x86_64，Zig 0.16.0；未在 Windows/macOS/FreeBSD 实机验证。
- 旧/新二进制分别以 `-Dversion=v0.0.1`、`-Dversion=v9.9.9` 和 `ReleaseSmall` 构建；构建输出使用隔离的 `/tmp/komari-selfupdate-review/` 前缀，不对部署中的 agent 做更新。
- Release API、资产和校验文件来自本机 mock HTTP server，通过 `KOMARI_RELEASE_API_URL` 指向 mock，独立探针清空代理池。没有用真实 GitHub Release 覆盖本机部署。
- 先跑仓库原有 `run_self_update_e2e`，再跑 17 个独立更新场景；修复后重跑同一组场景，以及永久自更新回归、v2 POST 回退/恢复场景。
- 独立探针在旧可执行文件末尾追加 `LOCAL-MODIFICATION-SENTINEL`，证明合法可运行的本地修改版本会被替换，且更新前的精确字节保存在 `.bak`；同时放置普通配置、数据、用户文件和源码哨兵。
- 未替换的长期运行进程由探针观察后发送 SIGTERM；相关 `rc=0` 是受控停止的退出码，不代表没有发生更新检查错误。mock 的连接重置/BrokenPipe 输出来自测试关闭连接，不能作为 agent 更新失败证据。
- 6 小时间隔来自源码检查，**没有声称实际等待 6 小时**。跨平台替换、断电恢复、rename 失败注入也未实测；下文将这些与实测结论区分。

## 1. 触发条件：何时更新，是否默认开启？

**默认开启。** `src/config.zig` 的 `disable_auto_update` 默认 false。

正常运行入口 `src/main.zig/main` 在配置加载后、正常基础信息上报前：

1. 无 endpoint/token 时打印使用说明并返回，不发起新更新检查；`--show-warning` 和诊断命令也不走普通更新检查。
2. 未禁用、且没有待确认更新 marker 时，立即调用 `update.checkAndUpdate`。
3. 未禁用时启动 `update.startBackground`；`src/update.zig/updateLoop` 每次先休眠 6 小时，再检查。待确认 marker 存在时跳过本轮更新。
4. `checkAndUpdate` 读取 GitHub latest Release；只有 Release 版本更高且存在当前 OS/架构匹配的资产才更新。版本比较接受可选 `v`/`V`，按数值及 prerelease 比较，不考虑 build metadata 的排序差异。

本地构建的 `dev` 或低版本定制版不会天然免更新；既有版本测试明确覆盖 `dev` 更新到稳定版。实测同版本 `v0.0.1` Release 不替换；`v9.9.9` Release 默认立即替换并退出 42。

**没有专门的服务端“自更新任务”入口。** `src/protocol/ws_message.zig` / `report_ws.zig` 分派 terminal、exec、ping、message、event；普通 `update` 消息实测被忽略。通用 shell `exec` 能显式执行文件替换，见第 4 节，这与内置定时检查是不同路径。

## 2. 替换方式：如何落盘，失败怎么办？

`src/update.zig/downloadAndReplace` 通过 `compat.selfExePathAlloc` 定位当前实际可执行文件，而不是根据工作目录猜测二进制位置。正常流程是：

```text
读取有效 SHA256 期望值
→ 排他创建 <exe>.update，流式下载并计算 SHA256
→ 校验下载内容
→ 运行 <exe>.update --show-warning，要求成功退出
→ 无覆盖复制当前二进制到 <exe>.bak
→ 排他创建 <exe>.update-state.json，记录旧/目标版本、backup_path、attempts=0
→ rename(<exe>.update, <exe>)
→ exit(42)
```

这是**同目录临时文件 + rename + 旧版备份**，不是直接对运行中的二进制 truncate/覆盖写。Linux 下旧进程随后退出；服务管理器或人工需重新启动路径上的新版。安装脚本里的 systemd 服务使用 `Restart=always`；此次未启动或修改系统服务。

- 实测校验值缺失、digest/校验文件不匹配、预检失败：旧二进制字节不变，没有有效备份或 pending marker，旧进程继续尝试业务上报。
- 实测修复后的 `.update`/`.bak` 预存普通文件、符号链接冲突：中止更新，旧二进制、冲突文件/链接及其目标保持原样；本次临时文件被清理。
- 对普通写入/rename 错误，源码使用 `errdefer` 清理本次创建的临时文件、备份和 marker，并将错误返回到主入口记录。最终 rename 未成功时不会由此流程替换旧路径。这一错误分支是源码结论，未做最终 rename 故障注入。
- 不声称具备断电事务保证；没有实测突然断电，也没有完整 fsync/目录持久化事务机制。成功创建之后的外部路径替换竞态不在此次已复现的预存文件冲突修复范围内。

## 3. 会覆盖什么？校验是否可靠？

### 二进制本身及本地修改

**会。** 只要 Release 版本更高，已通过 SHA256 和预检，当前二进制会完整替换成 Release 字节。本地手改逻辑、补丁、嵌入资源不会合并。

独立探针的旧二进制附加本地修改哨兵后仍能正常执行；默认更新后 `binary=new`，`.bak` 与附加哨兵后的旧字节精确相等。新版健康确认会删除 `.bak`，所以这不是长期保留本地修改的备份方案。

### 配置、数据、源码和其他文件

自更新不下载配置包、不解压仓库、不执行安装脚本，不主动写普通配置或数据文件。17 个场景中旁置的 `config.json`、`traffic.json`、`user-file.txt`、`source.zig` 内容均保持不变。

**不能把“其他文件”说成完全无例外：** `<exe>.update`、`<exe>.bak`、`<exe>.update-state.json` 是更新内部保留路径。修复前前两者存在真实覆盖/删除风险；修复后 `.update` 和 `.bak` 冲突会拒绝更新。状态文件仍由启动恢复和健康确认逻辑管理：合法状态会更新/删除，无法解析或版本真正不匹配的 marker 仍按既有策略清理。不要用这些内部名称保存用户文件；禁用新更新也不会停止处理已有 marker。

### digest / SHA256SUMS

`expectedSha256` 优先使用 Release API 的有效 `sha256:<64 hex>` digest；没有有效 digest 则读取同 Release 的 `SHA256SUMS`，匹配当前资产名称。没有可用校验值时 `downloadReleaseAssetToFile` 返回 `ReleaseChecksumMissing`，并非无校验下载后替换。

流式下载计算 SHA256 后比较，不匹配返回 `ReleaseChecksumMismatch`；只有校验和预检都通过才备份/替换。实测有效 digest、有效 SHA256SUMS 都能更新；错误 digest、错误 sums 和两者缺失均不能替换。

SHA256 是下载内容的完整性校验，**不是独立发行签名**。API/digest/sums 的来源同属 Release/代理信任链；本次没有发现或证明这条信任链遭到攻击，也没有将“没有独立签名”冒充校验缺失缺陷。

## 4. 可以彻底关闭吗？有没有服务端绕过？

### 新更新检查

修复后的推荐方式是明确传入：

```sh
komari-agent --endpoint <url> --token <token> --disable-auto-update
```

主入口保存 CLI 解析得到的禁用值，在环境变量和 JSON 加载后以 OR 合并；**明确 CLI true 不再被后加载的 false 重启更新**。未改变默认开启行为，也未改变其他配置字段的优先级。

实测正常启动并继续上报：单独禁用、加 `AGENT_DISABLE_AUTO_UPDATE=false`、加 JSON `disable_auto_update:false`，三种情况均为 Release 请求 0、旧二进制不变。定时线程由同一禁用分支控制，代码确认不会启动；未等待 6 小时验证定时行为。

还可使用 `AGENT_DISABLE_AUTO_UPDATE=true` 或 JSON `"disable_auto_update": true`。仅用 env/JSON 时仍需注意既有 env → JSON 加载优先级；本次安全优先级修复只针对明确 CLI 禁用。`-autoUpdate` / `--autoUpdate` 已废弃并忽略；实测 `--autoUpdate false` 仍会更新。

### 已经发生更新的恢复

`recoverPendingUpdate` 在新更新开关判断之前执行，`confirmPendingUpdate` 在报告成功路径执行。禁用新更新**仍可能因已有 marker 将二进制回滚到 `.bak`**，也可能清理备份和状态。这是保留的安全恢复语义，不是后台继续下载新版本。实测第二次未确认启动即使带禁用开关，仍恢复旧字节并退出 42。

### 服务端通用命令和人工脚本

没有发现独立内置更新任务绕过开关，普通 `update` 消息实测无效果。但远程 `exec` 的原有能力是用 agent 权限执行 shell，开关不限制命令内容。隔离 mock 在禁用状态下发送 `cp 新版 临时文件 && mv 临时文件 agent`，执行成功、二进制字节变为新版，Release API 请求仍为 0：

```text
REMOTE_PROBE_OK update_message_ignored=true disable_release_requests=0 exec_result=e2e-exec-ok binary_replaced_by_generic_exec=true
```

这证明“禁用自更新”不是远程命令权限沙箱；没有把受信任远程执行的既有功能改成命令黑名单。terminal 和人工执行 `install.sh`、`replace.sh`、`update-binary.sh` 也不由 agent 内部开关控制；这些脚本不是自更新流程调用的子步骤。本次未修改或重新执行安装/替换脚本。

## 5. 回滚：能否恢复，正确性和边界？

`src/update.zig/recoverPendingUpdate`、`pendingAction`、`confirmPendingUpdate` 实现的是**持久化尝试次数 + 下次启动恢复**：

1. 替换成功产生 `attempts=0`。
2. 新版首次正常启动时、若目标版本匹配，写成 `attempts=1`，允许运行。
3. 成功发送普通 WebSocket 报告，或修复后成功完成 v2 POST 报告，才确认并删除备份和 marker。单独 `--show-warning` 预检不会确认。
4. 若没有确认就再次启动，`attempts>=1` 导致 `.bak` rename 回可执行路径，删除 marker，退出 42；随后需再次启动旧版。

实测正常回滚恢复的是旧二进制的精确字节，而非仅检查退出码。修复后的无前缀 Release tag `9.9.9` 与二进制 `v9.9.9` 也可回滚；永久 e2e 另验证 `V9.9.9` 正常确认。

**不是通用健康监控：** 新版若运行着但不健康，不会在进程内因超时自动回滚；需要再次启动。任何确认前重启（包括网络不通或人为重启）都可能触发恢复；健康确认后 `.bak` 已删除，之后的业务缺陷不能靠这个机制回滚。缺失备份、损坏 marker、真正的发行包版本/tag 不一致和突然断电不保证恢复；这些是源码/机制边界，不冒充此次实测新增缺陷。已回滚旧版若仍开启更新、且坏 Release 仍是 latest，下一次正常启动仍可能再次下载；没有发行版本隔离/黑名单机制，本次未擅自增加。

## 确认的问题及修复

| 编号 | 严重程度 | 修复前已确认的问题 | 修复和验证 |
|---|---|---|---|
| U1 | 高：数据完整性 | 固定 `.update` truncate 已有文件，失败清理又删除它；符号链接目标被写坏。`.bak` 使用 replace=true，覆盖普通文件或替换已有链接。 | `.update` 排他创建；只有成功创建后才注册清理；本地备份复制 replace=false。新 marker 初次创建也排他。四种文件/链接冲突均实测保留原内容及链接目标。 |
| U2 | 高：违反明确禁用、意外替换 | CLI `--disable-auto-update` 经 env/JSON false 覆盖后，仍请求 Release、替换旧版、退出 42。 | `main` 保留明确 CLI true 并在加载完成后合并；两种覆盖场景都继续正常上报且请求数 0、旧字节不变。 |
| U3 | 高：失败版本无法回滚 | 更新比较接受 `v`/`V`，但恢复/确认用原始字符串。tag `9.9.9` / binary `v9.9.9` 首启动删除 marker，两次未确认启动仍不回滚。 | 恢复和确认都通过既有 `parseVersionPrefixless` 归一化双方后精确比较；实测两次启动后恢复旧字节、退出 42。 |
| U4 | 中：健康版本误降级 | v2 POST 回退成功报告和 ping 后 marker/backup 仍存在；下次启动把健康新版回滚。 | `runPostFallback` 仅在 POST 报告成功时确认更新；健康场景清理后重启 0、不回滚；POST 503 场景保留恢复材料、下次重启仍正确回滚。 |

默认替换本地定制二进制是自更新设计行为，不误报为第五项缺陷。未发现校验缺失、校验失败仍替换或专用服务端更新任务绕过的问题。

## 实测关键输出

### 修复前

仓库原有正向 e2e 本身成功，说明它原先不足以发现上述边界：

```text
mock komari self-update e2e ok
```

独立探针的关键字段摘录（临时目录、普通业务输出省略）：

```text
default-sums: rc=42, binary=new, backup_is_old=true, ordinary_files_unchanged=true
digest: rc=42, binary=new, backup_is_old=true
digest-mismatch / sums-mismatch / checksum-missing / failed-preflight: binary=old
not-newer: binary=old
disabled: release_requests=0, binary=old
disabled-env-overridden: rc=42, release_requests=1, binary=new
disabled-json-overridden: rc=42, release_requests=1, binary=new
deprecated-false: rc=42, release_requests=1, binary=new
update-file-collision: sidecar_preserved=false
update-symlink-collision: sidecar_preserved=false, victim_unchanged=false
backup-file-collision: rc=42, sidecar_preserved=false
backup-symlink-collision: rc=42, sidecar_preserved=false, victim_unchanged=true
prefix-mismatch: restart_rcs=[0, 0], state_after_first_restart=false, rollback_restored_old=false
normal-rollback: restart_rcs=[0, 42], attempts_after_first_restart=1, rollback_restored_old=true
PROBE_ASSERTIONS_OK
```

v2 POST 健康版本误回滚的原始输出：

```text
POST_HEALTH report_count=1 ping_seen=True pending_after_healthy_report=True backup_after_healthy_report=True
POST_RESTART rc=42 rolled_back_healthy_version=True
POST_PROBE_ASSERTIONS_OK
```

### 修复后

17 个独立场景全部断言通过。以下摘自实际探针汇总及 agent 日志：

```text
fixed cases 17
disabled rc=0 binary=old release_requests=0
disabled-env-overridden rc=0 binary=old release_requests=0
disabled-json-overridden rc=0 binary=old release_requests=0
update-file-collision rc=0 binary=old sidecar_preserved=true victim_unchanged=true
update-symlink-collision rc=0 binary=old sidecar_preserved=true victim_unchanged=true
backup-file-collision rc=0 binary=old sidecar_preserved=true victim_unchanged=true
backup-symlink-collision rc=0 binary=old sidecar_preserved=true victim_unchanged=true
prefix-mismatch restart_rcs=[0, 42] rollback_restored_old=true
normal-rollback restart_rcs=[0, 42] rollback_restored_old=true
Auto update asset download failed: ReleaseChecksumMismatch
Auto update asset download failed: ReleaseChecksumMissing
Auto update preflight failed: UpdatePreflightFailed
PROBE_ASSERTIONS_OK
```

正常更新仍 `rc=42, binary=new, backup_is_old=true`；四个普通哨兵文件在所有 17 个场景中均未修改。POST 成功/失败边界、永久回归和协议恢复输出：

```text
POST_HEALTH report_count=1 ping_seen=True pending_after_healthy_report=False backup_after_healthy_report=False
POST_RESTART rc=0 rolled_back_healthy_version=False
POST_PROBE_ASSERTIONS_OK
POST_FAILED_REPORT pending_preserved=true backup_preserved=true attempts=1
POST_FAILED_REPORT_RESTART rc=42 old_binary_restored=true
mock komari self-update e2e ok
post fallback pending update confirmed; restart rc=0
mock komari v2 post fallback e2e ok
mock komari v2 post recovery e2e ok
```

指定测试命令以所需 PATH 运行，仅加输出汇总参数：

```sh
export PATH=/tmp/zig-x86_64-linux-0.16.0:$PATH
zig build test --summary all
```

关键结果：

```text
Build Summary: 66/66 steps succeeded; 229/232 tests passed (3 skipped)
test success
```

## 工作区修复文件及复现命令

- `src/main.zig`：明确 CLI 禁用的安全优先级；默认开启不变。
- `src/update.zig`：辅助文件无覆盖创建/复制和对应错误清理；恢复及确认的 `v`/`V` 前缀匹配。
- `src/protocol/report_ws.zig`：成功 POST 报告的健康确认；失败 POST 不确认。
- `scripts/mock_komari_business_e2e.py`：保留正常更新/报告确认/回滚，加入四种辅助文件冲突、两种禁用覆盖、无前缀回滚、`V` 前缀确认的真实进程回归。
- `scripts/mock_komari_v2_e2e.py`：POST fallback 在隔离二进制及真实 pending 状态下运行，检查健康报告清理材料和正常重启；既有 exec/ping 业务断言保留。
- `README.md`：说明覆盖范围、默认启动/定时更新、关闭和回滚边界、冲突处理；纠正同一自更新段落中的代理优先顺序描述。
- `SELFUPDATE_REVIEW.md`：本报告。本次提交范围为上述代码、测试、README 和调查报告，不包含其他已有资料、任务说明或生成缓存。

永久回归可用以下命令重新构建并运行（临时独立探针已清理，不作为仓库运行依赖）：

```sh
export PATH=/tmp/zig-x86_64-linux-0.16.0:$PATH
zig build -Doptimize=ReleaseSmall -Dversion=v0.0.1 --prefix /tmp/komari-review-old
zig build -Doptimize=ReleaseSmall -Dversion=v9.9.9 --prefix /tmp/komari-review-new
python3 scripts/mock_komari_business_e2e.py self-update \
  --old-agent /tmp/komari-review-old/bin/komari-agent \
  --new-agent /tmp/komari-review-new/bin/komari-agent
python3 scripts/mock_komari_v2_e2e.py post-fallback /tmp/komari-review-new/bin/komari-agent
python3 scripts/mock_komari_v2_e2e.py post-recover /tmp/komari-review-new/bin/komari-agent
zig build test --summary all
```

**保留本地定制版本的操作建议：** 重新编译并部署本次修复后，保持默认本仓库更新源即可避免上游 Release 覆盖，无需关闭自动更新；检查并移除指向上游的 `KOMARI_RELEASE_API_URL`。如果还需要禁止本仓库的新更新，可将 `--disable-auto-update` 固定写进实际服务的启动参数，不用废弃的 `--autoUpdate false`；另外自行保留定制二进制备份。若存在历史 pending marker，先检查备份和目标版本，不要以为改更新源或加开关就会取消已开始的回滚。需要防止服务端通用命令改文件时，应另行限制远程管理权限和操作系统写权限，而不是依赖更新源或自更新开关。
