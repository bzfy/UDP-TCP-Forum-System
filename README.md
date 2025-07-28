# UDP-TCP-Forum-System

# 简易 UDP/TCP 论坛系统

本仓库包含 **客户端 (Client.py)** 与 **服务器 (Serve.py)** 两个 Python 3 脚本，构成一个轻量级的 C/S 论坛。用户可通过命令行创建主题帖、发布/编辑/删除留言，上传下载附件，并在同一端口上同时使用 UDP（控制通道）和 TCP（文件传输）。


---

## 功能概览

| 功能       | 说明                                   |
| -------- | ------------------------------------ |
| 多线程主题管理  | `CRT/LST/RDT/RMV` 创建、列出、读取、删除主题帖     |
| 留言操作     | `MSG/DLT/EDT` 发表、删除、编辑留言（仅作者可操作）     |
| 文件传输     | `UPD/DWN` 在帖子内上传或下载附件，TCP 可靠传输       |
| 用户认证     | 首次输入用户名自动注册，其后需密码登录                  |
| 简易 TLS\* | 可选 Diffie‑Hellman + RSA 证书链握手，生成共享密钥 |
| UDP 重传   | `Retransmission=True` 时客户端对超时请求自动重试  |

\* **启用方法**：在 *Serve.py* 与 *Client.py* 中将 `TLS_1 = True`。

---

## 目录结构

```
├── Client.py          # 客户端脚本
├── Serve.py           # 服务器脚本（同端口 UDP+TCP）
├── credentials.txt    # 用户名/密码存储，服务器首次运行自动生成
└── <thread files>     # 运行时按主题名生成的文本文件
```

---

## 环境要求

* Python ≥ 3.8（已在 3.11 测试）
* 标准库（无需额外依赖）

---

## 启动示例

### 1. 启动服务器

```bash
python Serve.py 12345   # 监听 12345 端口
```

### 2. 启动客户端

```bash
python Client.py 12345  # 连接本机 12345 端口
```

> 默认使用 127.0.0.1。如需远程部署，请修改脚本中的地址或通过参数传入。

---

## 登录流程

1. 运行客户端后，输入用户名。

   * 若服务器不存在该用户，将提示 `New user` 并要求设置密码。
   * 已存在用户需输入正确密码才能登入。
2. 登录成功后显示 `Welcome to the forum` 并进入命令循环。

> 账号数据保存在服务器工作目录下的 **credentials.txt**。如需重置，可删除该文件。

---

## 指令速查

| 指令   | 用法                                            | 说明             |
| ---- | --------------------------------------------- | -------------- |
| CRT  | `CRT <threadtitle>`                           | 新建主题帖          |
| MSG  | `MSG <threadtitle> <message>`                 | 在主题中发布留言       |
| DLT  | `DLT <threadtitle> <messagenumber>`           | 删除自己发布的留言并重新编号 |
| EDT  | `EDT <threadtitle> <messagenumber> <message>` | 编辑自己发布的留言      |
| LST  | `LST`                                         | 列出全部主题         |
| RDT  | `RDT <threadtitle>`                           | 读取指定主题全部内容     |
| RMV  | `RMV <threadtitle>`                           | 删除自己创建的主题及附件   |
| UPD  | `UPD <threadtitle> <filename>`                | 向主题上传本地文件（TCP） |
| DWN  | `DWN <threadtitle> <filename>`                | 下载主题内文件（TCP）   |
| XIT  | `XIT`                                         | 注销并退出客户端       |
| HELP | `HELP`                                        | 客户端本地帮助菜单      |

> 上传/下载命令先通过 UDP 交换 `READY` 信号，再由客户端主动建立 TCP 连接完成文件流传输。

---

## 重要实现细节

* **控制通道**：所有文本命令与回复均走 UDP；客户端可配置自动重传、超时重试。
* **文件通道**：传输开始后客户端调用 `socket.connect()` 在同一端口创建 TCP 会话。
* **并发模型**：服务器使用 `threading.Thread` 对每个 UDP 地址维持独立会话队列，同时监听 TCP 连接用于文件操作。
* **锁机制**：细粒度 `threading.Lock` 保证多线程读写同一主题文件时的原子性。
* **TLS**：

  1. Diffie‑Hellman 握手 (p = 7919, g = 2) 生成会话密钥；
  2. 服务器返回含自签 RootCA → IntermediateCA → Server 三级证书链；
  3. 客户端验证 RSA 签名与信任锚，随后所有数据可选 `xor_encrypt_decrypt()` 对称加解密。

---

## 常见问题

1. **为何客户端收不到回复？**
   检查服务器是否在同一端口监听；或调整 `udp_send()` 的 `timeout`/`retries` 参数。
2. **上传文件后无法下载？**
   需确保上传命令返回成功，并在相同主题内下载同名文件。
3. **如何清空所有数据？**
   停止服务器后删除线程文件、附件及 `credentials.txt` 即可。

---

## 许可证

MIT License – 仅对本仓库源码授权，不涵盖上传到论坛的任何第三方文件。
