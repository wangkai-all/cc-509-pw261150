# Audit evidence workbench

按指标（metric）或报表（report）收集审计证据包：输入快照、转换版本、质量结果、权限记录、发布日志。
证据包可校验、可重放、按工作区与密级隔离，并在页面上展示收集进度、缺口、哈希与下载审计。

## 快速开始

```bash
npm run seed        # 生成演示数据（指标/报表、快照、转换、质量、权限、发布）
npm start           # http://localhost:4173
npm test            # 25 个测试：收集、缺口、校验和、中断恢复、采集失败、权限隔离
```

命令行构建（无需启动页面）：

```bash
node src/cli.js --subject metric.activation_rate --out pack.zip
# 退出码 0=complete，2=incomplete（已披露缺口），1=错误
```

演示身份（页面右上角切换，仅演示用明文 key）：

| 主体 | 角色 | 工作区 | 密级 |
|---|---|---|---|
| Ada Auditor | auditor | analytics | restricted |
| Sam Steward | steward | analytics | internal |
| Vera Viewer | viewer | analytics | internal |
| Priya Platform | steward | platform | internal |
| Omar Outsider | auditor | external | restricted |

## 证据模型

每个维度是一个独立阶段，取自各自的记录系统（`snapshots` / `transforms` / `quality_runs` /
`permission_records` / `publish_logs`），产出一个 JSON 工件：

- **inputs** — 快照身份、捕获时间、原始输入哈希、数据集与查询。
- **transforms** — 每个转换版本、引擎、工件哈希、评审状态、SQL。
- **quality** — 质量套件执行结果，含失败/告警检查与阈值。
- **permissions** — 截至 `as_of` 已生效的授权与撤销记录。
- **publish** — 发布事件、通道、执行人、回滚状态。

`manifest.json` 汇总五个维度、缺口清单与每个工件的 SHA-256；`checksum.root` 是对
“去除 `checksum` 字段后的 manifest”做递归键排序（canonical JSON）后的 SHA-256。

## 缺口与“伪完整”防护

任何来源缺失都会写入 `pack_gaps`，并在 `manifest.gaps` 中标为 `blocking`：

| 缺口 | 触发条件 |
|---|---|
| `snapshot_missing` | 快照不存在 |
| `transforms_missing` / `quality_missing` / `publish_missing` | 该快照无对应记录 |
| `permissions_missing` | `as_of` 之前无生效授权 |
| `restricted_grants_missing` | 受限主体无生效的受限密级授权 |
| `quality_not_passed` | 质量运行为 failed/errored |
| `publish_rolled_back` / `publish_never_succeeded` | 最新发布被回滚 / 从未成功 |

缺失的维度仍会生成文件，但内容是显式的 `gap_placeholder`（说明“此文件记录缺失，不构成合规证据”），
`record_count` 为 0。只要有 blocking 缺口，manifest 的 `status` 就是 `incomplete`，
归档内的 README 与页面也都明示“不可当作完整证据”。告警类缺口（未评审的转换、带 warning 的质量运行）
标为 `advisory`，会披露但不阻断。

## 一致校验和

- 同一 `(subject, snapshot, as_of, generator, redaction)` 重复生成复用同一个 pack id，
  未变化的来源重新收集后得到**完全相同的 root checksum**；来源变化则 checksum 随之变化。
- `as_of` 默认取快照的捕获时间（显式缺失时取该主体最新捕获时间，再退化为固定 epoch），
  因此不会随系统时钟漂移。
- ZIP 归档使用固定时间戳（1980-01-01）、固定压缩级别、按路径排序、无额外字段，
  因此同一内容重复下载得到的归档字节与 SHA-256 完全一致。
- `GET /api/packs/:id/verify` 重新计算所有工件摘要与 manifest root，并报告任何不一致。

## 中断与恢复

每个维度在自己的事务内提交，`packs.next_stage` 是持久化检查点：

- `POST /api/packs/:id/interrupt` 模拟进程退出：已完成阶段保留，状态置为 `interrupted`。
- 中断状态下调用 `advance` 或下载返回 409；必须显式 `POST /api/packs/:id/resume`。
- 恢复只补未完成阶段，最终 checksum 与一次性完整构建相同。
- 采集器抛错时阶段与 pack 标记为 `failed` 并保留错误信息，同样返回 409，修复来源后 `resume` 可继续。

## 权限与下载审计

- 认证：所有数据接口要求 `X-Api-Key`（健康检查、主体/对象发现接口除外）。
- 隔离：pack 列表、详情、校验、manifest、下载均按**工作区**过滤；工作区不符直接 403。
- 密级：`restricted` 主体只有 `auditor` 角色或 `restricted` 许可可构建/读取/下载；
  受限主体的证据中授权对象、执行人、工单等标识会被**可复现的伪名化**（`pseudonym:<hash>`）。
- 审计：允许与拒绝都会写入 `downloads` 表（主体、角色、动作、结果、字节数、原因、时间），
  页面“Download audit”表格按 pack 展示。下载响应头带 `X-Evidence-Root` 与 `X-Evidence-Archive-Sha256`。

## 页面

单页控制台（无构建步骤）：

1. **Scope** — 选择主体/快照、可选地覆盖生效日期、是否脱敏。
2. **Collection** — 进度条（同色系轨道 + 状态色填充）、五阶段列表、Interrupt/Resume/Download/Verify。
3. **Evidence summary** — 状态、已收集来源、blocking/advisory 缺口数、工件数、root hash。
4. **Gaps** — 按严重度排序，含维度、引用、原因。
5. **Checksums** — root hash 与每个工件的记录数/字节数/SHA-256。
6. **Download audit** — 允许/拒绝记录。
7. **Recent packs** — 最近构建的 pack。

状态色（good / warning / critical）始终与图标和文字标签一起出现，不单靠颜色传达含义；
`warning` 在浅色背景上对比度不足 3:1，因此阶段标签与缺口徽章都带可见文字。

## HTTP API

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/packs` | 创建或复用（幂等）pack |
| POST | `/api/packs/build` | 一次性构建到完成 |
| POST | `/api/packs/:id/advance` | 收集下一个维度（单步） |
| POST | `/api/packs/:id/interrupt` / `resume` | 中断 / 恢复 |
| GET | `/api/packs` | 当前工作区的 pack 列表 |
| GET | `/api/packs/:id` | 进度、阶段、工件、缺口、下载记录 |
| GET | `/api/packs/:id/manifest` | 封存的 manifest（记审计） |
| GET | `/api/packs/:id/verify` | 重新校验所有哈希 |
| GET | `/api/packs/:id/download` | 下载确定性 ZIP（记审计） |
| GET | `/api/packs/:id/downloads` | 该 pack 的下载审计 |
| GET | `/api/audit/downloads` | 当前工作区的下载审计 |

## 结构

```
src/canonical.js   canonical JSON 与 SHA-256
src/db.js          SQLite schema（node:sqlite，无外部依赖）
src/evidence.js    维度收集、缺口规则、manifest 与 root checksum
src/packs.js       阶段状态机、中断/恢复、重封存、归档、校验
src/zip.js         确定性 ZIP 写入
src/views.js       展示层 DTO 与下载鉴权
src/server.js      HTTP 路由、认证、安全响应头
src/cli.js         命令行构建
src/fixtures.js    演示数据（含故意缺失/失败/回滚场景）
public/            单页控制台
test/run.js        端到端测试（含真实 HTTP 服务器）
```

演示数据刻意包含：无快照的指标、质量失败的报表、已回滚的发布、未评审的转换、
已撤销与缺失的授权，用于验证缺口不会被“伪完整”地掩盖。
