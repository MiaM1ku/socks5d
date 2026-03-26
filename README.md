# 简单的 SOCKS5 Server
一个简单的 SOCKS5 服务器，实现一键启动本机代理服务，同时支持：

- TCP `CONNECT`
- UDP `ASSOCIATE`，支持标准 SOCKS5 UDP 封装，当前仅支持 `FRAG=0`
- 可选用户名密码鉴权

```
./socks5d 

./socks5d 0.0.0.0:8080 username password
```

默认监听 `:1080`。在系统支持的情况下会同时接收 IPv4/IPv6 连接（双栈）。

## GitHub Actions 静态编译

仓库内置了 GitHub Actions 工作流，会使用 `CGO_ENABLED=0` 对 Go 官方支持的常见非移动端目标做静态交叉编译，并产出对应平台压缩包。

- 触发方式：`workflow_dispatch`
- 发布方式：推送 `v*` 标签时同时创建 Release 并上传构建产物
