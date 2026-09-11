# fileencrypt

`fileencrypt` 是一个用于目录的轻量批量加密工具。它递归处理选定类型的文件、保留子目录，并把每个文件转换成独立、标准的 [age](https://age-encryption.org/) 密码加密文件。默认范围包括 Markdown 和常见图片，因此既适合私人文档、私人照片等普通目录，也适合 Obsidian Vault。

[English](../README.md)

```text
Documents/证件照.jpg  -> Documents/证件照.jpg.age
Notes/旅行.md         -> Notes/旅行.md.age
Public/...           -> 可通过 .ageconfig 排除
```

## 核心思路

- 同一个批次只输入一次密码，但每个文件都由 age 独立生成 salt、文件密钥和 nonce。
- 每次传入的目标目录（包括其子目录，但不包括 `.ageconfig` 明确排除的路径）被视为一个密码域；工具假设其中所有 `.age` 文件使用同一个密码。
- `.age` 文件是标准 age 格式，不含自定义 header；可被官方 `age`、Go age 库以及 TypeScript `age-encryption` 解密。
- 默认使用 scrypt work factor `14`。这是针对大量小文件的性能取舍，比 age 的高强度默认设置更容易遭受离线密码猜测。
- 文件名、目录结构、原始扩展名、数量和近似大小不会隐藏。
- 相同明文加密两次会得到不同密文。

任何一个 `.age` 文件都足以让攻击者离线猜密码。建议仍然使用密码管理器生成的长密码。短密码只适合防止偶然查看，不适合抵抗有意破解。

## 适合什么场景

`fileencrypt` 适合把一整个目录当成一个需要统一管理的加密范围，例如：

- 批量保护私人照片、扫描件、Markdown 笔记或其他选定类型的文件；
- 第一次加密一个已有目录，并在以后只处理其中新增的文件；
- 预览哪些文件会被处理、统一修改整个目录的密码，或批量恢复文件；
- 需要保留原来的子目录和文件名，并让每个结果仍是标准 `.age` 文件。

对于普通目录，建议先备份，在目录根部按需创建 [`.ageconfig`](#目录加密策略-ageconfig)，然后先预览再加密：

```bash
./fileencrypt preview ~/PrivateFiles
./fileencrypt encrypt ~/PrivateFiles
```

### Obsidian 使用场景

Obsidian Vault 是一个主要使用场景，但不是工具的唯一用途。首次保护已有 Vault 时，请先备份并完全退出 Obsidian，再用 `preview` 检查范围并运行 `encrypt`。完成首次批量加密后，可以安装 [Vault in Vault Obsidian 插件](https://github.com/feifangit/obsidian-vault-in-vault)，在 Obsidian 中按需解密、正常编辑或预览，再重新加密。

Go 工具和插件都读取 Vault 根目录的 `.ageconfig`，并使用兼容的标准 age 密码加密文件，因此适合共用同一套文件范围和密码。Go 工具更适合首次批处理、Obsidian 完全退出后的离线维护和修改密码；插件更适合日常在 Obsidian 中打开和重新锁定文件。

## 和官方 `age` 命令有什么区别

`fileencrypt` 没有发明新的加密格式，也不是 `age` 的替代实现。它使用官方 Go age 库，在标准 age 密码加密之上增加了面向目录的批处理流程。

| | 官方 `age` CLI | `fileencrypt` |
|---|---|---|
| 主要用途 | 加密或解密一个输入文件/数据流 | 递归处理一个目录中的许多文件 |
| 加密方式 | 支持密码、recipient 和 identity | 有意只提供“一个目录、一份密码”的工作流 |
| 文件选择 | 由用户逐次指定输入 | 按扩展名、`.ageconfig` 和命令行参数选择 |
| Obsidian 规则 | 不认识 Vault 结构 | 默认保护 Markdown 和常见图片，并跳过 `.obsidian` |
| 输出与源文件 | 默认写到标准输出；指定 `-o` 时写到目标文件 | 自动使用 `原文件名.age`；密文完成并通过验证后才删除明文源文件 |
| 批量密码 | 每次调用独立处理 | 一次操作输入一次，并检查目录中已有 `.age` 文件是否属于同一密码域 |
| 检查与维护 | 交给 shell 或用户组织 | 提供 `preview`、并发处理、重复运行保护、失败恢复和 `change-password` |

两者生成的密码加密文件可以互相解密。例如，单个文件仍可运行：

```bash
age -d note.md.age > note.md
```

需要注意，`fileencrypt` 为了批量处理大量小文件，把 scrypt work factor 固定为 `14`；这低于所用 age 库的默认值，是性能优先的明确取舍。它不会调用系统中的 `age` 可执行文件，因此运行时不要求另外安装 `age`。

## 安装或构建

安装了 Go 1.25 或更新版本时，可以直接从源码安装当前 release：

```bash
go install github.com/feifangit/file-encryption/cmd/fileencrypt@latest
```

也可以在源码目录构建：

```bash
cd /path/to/fileencrypt
go build -o fileencrypt ./cmd/fileencrypt
```

带 tag 的 [GitHub Releases](https://github.com/feifangit/file-encryption/releases) 会附带 macOS 和 Linux 的预编译压缩包。当前密码输入依赖 Unix terminal，因此暂不支持 Windows。

生成的 `fileencrypt` 是独立可执行文件；运行时不需要系统安装 `age` 命令。Release 压缩包还会包含校验和与第三方许可证说明。

## 默认处理范围

默认扩展名大小写不敏感：

```text
.md
.avif .bmp .gif .jpeg .jpg .png .svg .webp
```

始终跳过：

- 所有名为 `.obsidian` 的目录及其内容；
- 加密策略文件 `.ageconfig`；
- 已以 `.age` 结尾的文件；
- symbolic link、socket、FIFO、device 等特殊文件；
- 工具自己的临时文件。

## 目录加密策略 `.ageconfig`

目标目录根部可以放置一个隐藏的 `.ageconfig`：

```json
{
  "extensions": [".md", ".png", ".jpg", ".wav"],
  "exclude": ["Public", "Templates/daily.md", "attachments/shared"]
}
```

它只保存加密范围，不保存密码或密钥：

- `extensions` 是可选的扩展名数组。省略时使用内置默认类型；如果显式提供，则不能为空。扩展名大小写不敏感，工具会规范化并去重；不允许 `all`、`*`、`.age`、`.tar.gz` 或路径。
- `exclude` 是可选的目标目录相对路径数组。可以写单个文件，也可以写目录；目录本身及其全部子目录都会跳过。上例会跳过整个 `Public`、一个模板文件和整个 `attachments/shared`。
- 排除路径区分大小写，不支持 `*`、`?` 等 glob，也不允许绝对路径或 `..`。明文路径被排除时，对应的 `.age` 文件也会在解密和修改密码时跳过。
- 未知 JSON 字段会报错，配置文件本身永远不会被加密。

只需要排除路径时，可以省略 `extensions`：

```json
{
  "exclude": ["Public", "Templates"]
}
```

此时仍会保护默认的 Markdown 和常见图片类型。

策略优先级：

```text
--ext  >  .ageconfig  >  内置默认类型
```

`--include` 在最终基础策略上追加类型。存在 `.ageconfig` 时，交互式 `encrypt` 会明确显示配置路径、扩展名和排除路径；直接按 Enter 接受，也可以输入新的扩展名列表覆盖本次运行。`--ext` 只覆盖扩展名，不修改配置文件，`exclude` 仍然生效。

如果 `.ageconfig` 内容无效，工具会停止，即使同时提供了 `--ext`。这样一个写错的排除项不会被命令行扩展名覆盖悄悄绕过。

交互运行 `encrypt` 时，工具会用分隔线显示策略问题：

```text
-------------------- ENCRYPTION POLICY --------------------
Policy source: .ageconfig (/Users/me/PrivateFiles/.ageconfig)
Files matching .jpg, .md, .png, .wav will be encrypted.
Excluded paths: Public, Templates/daily.md, attachments/shared
Press Enter to use this policy, or enter a replacement list (for example .md,.wav):
```

直接按 Enter 使用显示的策略；输入 `.md,.wav` 会**覆盖**该策略，本次只处理 Markdown 和 WAV。非交互脚本可用 `--ext` 得到相同效果：

```bash
./fileencrypt encrypt --ext .md,.wav ~/PrivateFiles
```

`--include` 则是在配置、默认值或 `--ext` 的基础上增加类型：

```bash
./fileencrypt encrypt --include .pdf,.canvas ~/PrivateFiles
```

扩展名匹配不区分大小写。`encrypt --ext all` 被刻意禁止，以免误加密目标目录中的程序、配置或其他不相关文件。

## Preview

`preview` 只扫描，不询问密码、不修改文件，也不需要确认：

```bash
./fileencrypt preview ~/PrivateFiles
./fileencrypt preview --ext .md,.wav ~/PrivateFiles
./fileencrypt preview --include .pdf ~/PrivateFiles
```

它会显示当前策略来源、每种扩展名的文件数量和大小，以及其中多少会加密、多少会跳过：

```text
-------------------- PREVIEW --------------------
Directory: /Users/me/PrivateFiles
Policy source: .ageconfig (/Users/me/PrivateFiles/.ageconfig)
Selected file types: .jpg, .md, .png
Excluded paths: Public, Templates/daily.md, attachments/shared
-------------------- FILE TYPE STATISTICS --------------------
Type                  Files         Size    Encrypt       Skip
.age                     20      8.1 MiB          0         20
.jpg                       5     12.4 MiB          5          0
.md                      120      3.2 MiB        120          0
.pdf                       2      6.0 MiB          0          2
-------------------- SUMMARY --------------------
Would encrypt: 125 file(s), 15.6 MiB
Would skip: 22 scanned regular file(s), 14.1 MiB
Existing .age files: 20
Excluded from scan: 2 item(s)
```

`.obsidian`、`.ageconfig`、配置的 `exclude`、symbolic link 和特殊文件会作为“Excluded from scan”单独统计，不会假装成已经逐个扫描的普通文件。

交互式终端会用颜色区分标题、警告、错误和成功结果；输出被重定向时自动关闭颜色。也可以显式禁用：

```bash
NO_COLOR=1 ./fileencrypt preview ~/PrivateFiles
```

## 加密

请先关闭所有可能正在编辑目标目录的程序；如果目标是 Obsidian Vault，请完全退出 Obsidian：

```bash
./fileencrypt encrypt ~/PrivateFiles
```

工具显示文件数量和总大小，确认后要求输入密码。目标范围中还没有 `.age` 文件时，需要输入两遍新密码；如果已经存在 `.age` 文件，则用其中一个文件验证密码，然后只加密新增内容。

密码验证会考虑目标目录内所有未被 `exclude` 排除的 `.age` 文件，而不只考虑本次 `--ext` 选中的类型。例如目录已有一个使用“密码 1”的 `document.pdf.age`，再运行 `encrypt --ext .jpg` 时也必须输入“密码 1”。这样可以防止同一个策略范围不知不觉出现多套密码；验证失败时不会加密新的 JPG。

如果确实要使用不同密码，请把文件分在不同目录，并分别把较小的子目录作为命令的目标目录，或用 `exclude` 明确划出不参与本策略的目录。未排除且并非由本工具生成的 `.age` 文件同样会参与检查。

```text
-------------------- ENCRYPTION POLICY --------------------
Policy source: built-in defaults
Files matching .avif, .bmp, .gif, .jpeg, .jpg, .md, .png, .svg, .webp will be encrypted.
Press Enter to use this policy, or enter a replacement list (for example .md,.wav):
-------------------- PLAN --------------------
Encrypt: /Users/me/PrivateFiles
Policy source: built-in defaults
Selected original file types: .avif, .bmp, .gif, .jpeg, .jpg, .md, .png, .svg, .webp
Pending: 842 file(s), 516.2 MiB
Existing .age files: 0 (0 selected, 0 outside selection)
Warning: close applications that are editing this directory before continuing.
-------------------- CONFIRMATION --------------------
Proceed with encrypt? [y/N]: y
-------------------- PASSWORD --------------------
Create password:
Confirm password:
```

重复运行不会生成 `.age.age`。如果没有新增文件，会显示 `Nothing to do.`。

跳过操作确认：

```bash
./fileencrypt encrypt --yes --workers 4 ~/PrivateFiles
```

`--yes` 不会绕过密码输入或弱密码警告。

## 解密

```bash
./fileencrypt decrypt ~/PrivateFiles
```

工具会扫描所有未被 `exclude` 排除的 `.age` 文件。如果发现原始扩展名不在当前范围，例如之前用 `--ext .wav` 加密过文件，会显示类似提示：

```text
-------------------- ENCRYPTED FILE SELECTION --------------------
Policy source: built-in defaults
Selected original types: .avif, ..., .webp
Also found outside this selection: .pdf (2), .wav (5).
Press Enter to keep this selection, type 'all' for every non-excluded .age file, or enter a replacement list:
```

- Enter：只解密当前选择的类型；
- `all`：解密目标目录中发现的全部未排除 `.age` 文件；
- `.md,.wav`：覆盖选择，只解密这两类。

非交互模式对应写法：

```bash
./fileencrypt decrypt --ext all --yes ~/PrivateFiles
./fileencrypt decrypt --ext .md,.wav --yes ~/PrivateFiles
```

使用 `--yes` 时不会弹出扩展名问题；工具仍会打印未选中的 `.age` 类型，不会擅自包含它们。

它把 `note.md.age` 恢复为 `note.md`。如果明文和密文因为上次中断而同时存在，工具会完整解密、比较内容；相同则安全清理重复文件，不同则停止且不覆盖。

单个文件也可以使用官方 age 解密：

```bash
age -d note.md.age > note.md
```

官方 age 只恢复内容；本工具还会尽力从 `.age` 文件的文件系统属性恢复权限和修改时间。

## 加密后在 Obsidian 中的表现

Vault 仍能被 Obsidian 打开，因为目录本身和 `.obsidian` 都保留不动。不过 `note.md` 已变成 `note.md.age`，所以未安装专用插件时，Obsidian 不会把它当作 Markdown 笔记：笔记会从文件列表、Search、Graph 和 Backlinks 中消失，指向已加密图片的嵌入也会失效。这不是解密失败提示，而是 Obsidian 默认不认识 `.age` 文件。

需要在 Obsidian 内按需访问时，可以使用 [Vault in Vault 插件](https://github.com/feifangit/obsidian-vault-in-vault)。

## 修改密码

```bash
./fileencrypt change-password ~/PrivateFiles
```

工具依次询问旧密码和新密码。每个文件会从旧 age 流直接解密到新 age 流，明文不会作为正式文件写入磁盘。

`change-password` 也会提示是否包含范围外的 `.age` 文件。如果过去加密过 WAV、PDF 等非默认类型，通常应选择 `all`，避免同一个目录留下两套密码。脚本中可使用 `change-password --ext all`。

修改中断时，部分文件可能已经使用新密码，其余仍使用旧密码。使用相同的旧密码和新密码再次运行，工具会跳过已经迁移的文件并继续。

## 安全与失败恢复

- 每个目标先写入同目录临时文件，完整认证、关闭并同步后才发布。
- 发布目标后才删除源文件；突然断电最多留下明文和密文两份，不会有意先删除唯一副本。
- 重跑会识别并处理内容一致的明密文对。
- 如果目标路径已有不同内容，工具停止，不覆盖。
- 同一目标目录同时只能运行一个 `fileencrypt` 操作。
- 操作期间源文件被其他程序修改时，工具保留源文件并报告失败。
- 不保留 owner、ACL、xattr、硬链接关系和稀疏文件布局。
- 本工具不会清理应用程序缓存、备份历史、云端版本历史，或 Obsidian 位于 Vault 外的 metadata cache、IndexedDB 和 File Recovery 快照。

## 测试

```bash
go test ./...
go test -race ./...
go test -run '^$' -bench BenchmarkStatedWorkload -benchtime=1x ./internal/crypttool
```

测试覆盖 Unicode 路径、嵌套目录、全部默认扩展名、`.ageconfig` 扩展名与文件/目录排除、策略优先级、Preview 只读统计、`.obsidian` 排除、symlink、重复加密、错误密码、密文损坏、标准 age 兼容、官方 `age` 命令解密、修改密码和中断恢复。

最后一个 benchmark 会创建并加密 900 个 100 KiB Markdown 和 100 个 5 MiB 图片，总量约 588 MiB；会消耗明显的 CPU、内存和临时磁盘空间。

本项目开发时在 Apple M5 Pro、默认 4 workers 下测得约 `11.43 s`、`53.9 MB/s`。这个数字包含创建测试文件的时间，只能作为量级参考；磁盘、CPU、文件系统以及 worker 数都会影响结果。

## 安全问题报告与许可证

发现可能的安全问题时，请按照 [SECURITY.md](../SECURITY.md) 私下报告，不要在 issue 中附带真实私人数据。

本项目使用 [MIT License](../LICENSE)。Release binary 包含的第三方组件列在 [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md)。
