# installIPA

局域网 iOS IPA OTA 安装工具。把任意一个 `.ipa` 放进 `ipas/`，执行脚本后，用 iPhone Safari 打开页面即可安装。

## 使用方式

1. 删除 `ipas/` 里旧的 `.ipa`，放入新的 `.ipa`。目录里只保留一个 IPA。
2. 在 Mac 终端执行：

```bash
cd ~/OneDrive/Document/workspace/Xcode_wks/study/installIPA
./serve-ios-ota.command
```

3. 终端会输出类似：

```text
page: https://你的内网IP:8443/install.html
```

4. iPhone 和 Mac 连同一个 Wi-Fi，用 Safari 打开这个 `page` 地址。
5. 第一次使用本地 HTTPS 时，先点页面里的 `Install certificate profile`，安装并信任证书。
6. 回到安装页，点 `Install App`。

## 首次证书信任

iPhone 安装描述文件后，还需要打开完全信任：

`设置` -> `通用` -> `关于本机` -> `证书信任设置`

打开 `Local iOS OTA HTTPS Certificate` 的完全信任。

如果 iPhone 没有出现描述文件安装入口，直接用 Safari 打开：

```text
https://你的内网IP:8443/.certs/local-ota-cert.mobileconfig
```

## 替换 IPA

停止当前 server：

```text
Ctrl-C
```

然后替换 `ipas/` 里的 IPA，再执行：

```bash
./serve-ios-ota.command
```

脚本会自动重新生成：

- `manifest.plist`
- `install.html`
- `app-icon.png`
- `app-icon-full.png`
- `.certs/local-ota-cert.mobileconfig`

## 常见问题

如果终端日志只有：

```text
GET /manifest.plist 200
```

但没有：

```text
GET /DistSchool.ipa 200
```

通常是证书没有被 iPhone 系统完全信任，或不是 Safari 打开的。

如果已经出现：

```text
GET /ipas/xxx.ipa 200
```

但手机仍提示无法安装，通常是 IPA 签名、Ad Hoc UDID、描述文件过期或 iOS 版本不满足。

## 指定 IPA

默认会在项目根目录和 `ipas/` 目录中查找唯一一个 `.ipa`。也可以显式指定：

```bash
./serve-ios-ota.command --ipa /path/to/app.ipa
```

注意：如果 IPA 不在当前项目目录内，局域网 server 无法直接提供这个文件。推荐始终放在 `ipas/`。

## OSS 上传

本地局域网安装不需要 OSS。需要公网安装时再配置 `.env.oss`：

```bash
cp oss.env.example .env.oss
```

填好 bucket、endpoint、AccessKey 后执行：

```bash
./serve-ios-ota.command --upload-oss
```
