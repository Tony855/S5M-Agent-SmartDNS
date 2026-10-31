# S5M Agent 稳定版本发布与长期保存

本项目采用手动稳定版发布，不会因为每次推送 `dev` 自动创建 Release。

## 发布前检查

1. 在 `dev` 上完成修改并确认 `S5M CI` 与 `S5M Agent multi-arch images` 检查通过。
2. 确认 Agent 与 Mihomo 同容器运行的改动已完成验证。
3. 记录准备发布的提交 SHA；只对已验证的提交发布稳定版本。

## 手动发布

从准备发布的提交创建并推送带前缀的版本标签，例如：

```bash
git checkout dev
git pull --ff-only origin dev
git tag -a s5m-agent-v1.0.0 -m "S5M Agent v1.0.0"
git push origin s5m-agent-v1.0.0
```

标签指向的提交就是本次稳定版的源码基线。发布新版本时递增版本号，**不要移动或复用已发布标签**。

推送标签后，GitHub Actions 将会：
- 构建并推送 amd64/arm64 多架构镜像到 GHCR；
- 发布 GitHub Release；
- 将两个架构的 Docker 镜像归档及 SHA-256 校验文件作为 Release 附件上传。

## 稳定版保存位置

- Releases: https://github.com/Tony855/S5M/releases
- GHCR package: https://github.com/Tony855/S5M/pkgs/container/s5m-agent

GitHub Actions 的 run artifacts 只作为临时下载副本（本工作流配置 90 天，仍受仓库/组织策略限制）；长期保存请从对应的 GitHub Release 下载附件。删除 Release、附件、仓库或相关版本标签可能影响找回能力，因此不要删除已发布的稳定版资产。

## 镜像标签

- 推送 `dev` 分支：`ghcr.io/tony855/s5m-agent:dev`
- 推送稳定标签 `s5m-agent-v1.0.0`：`ghcr.io/tony855/s5m-agent:v1.0.0` 和 `ghcr.io/tony855/s5m-agent:latest`
- 每次构建还会生成不可混淆的 `sha-<commit>` 标签。

## 验证校验和

下载 tar 与对应的 `.sha256` 文件到同一目录后执行：

```bash
sha256sum -c s5m-agent-linux-amd64.tar.sha256
# 或
sha256sum -c s5m-agent-linux-arm64.tar.sha256
```

注意：这些是 Docker 镜像归档；RouterOS 是否可导入和运行仍取决于 RouterOS 版本、CPU 架构及容器功能限制，需要在目标设备上单独验证。
