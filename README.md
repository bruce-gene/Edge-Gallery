# Edge-Gallery 🖼️ - 单文件版

一个极致简洁、安全、运行在单个 Cloudflare Worker 上的私人图床/相册。所有代码都在一个 `worker.js` 文件中，部署极其简单。

![image](https://github.com/user-attachments/assets/ad30e8ca-5acd-445c-b825-d27566cf77bb)


## ✨ 功能特性

-   **极致简单**: 整个应用就是一个 `worker.js` 文件。
-   **安全登录**: 使用密码保护，会话通过安全的 `HttpOnly` Cookie 管理。
-   **层级视图**: 像桌面文件浏览器一样逐级进入文件夹。
-   **批量上传**: 支持文件和整个文件夹的上传。
-   **图片预览**: 图像文件可以直接在浏览器中打开预览。
-   **文件删除**: 轻松删除不再需要的文件。

## 🚀 部署指南

部署此项目只需要复制粘贴，无需任何命令行工具。

### 第 1 步：创建 R2 存储桶

1.  登录到您的 [Cloudflare Dashboard](https://dash.cloudflare.com/)。
2.  在左侧菜单中，转到 **R2**。
3.  点击 **创建存储桶**，给您的存储桶起个名字（例如 `my-gallery`），然后创建。

### 第 2 步：创建 Worker

1.  在左侧菜单中，转到 **Workers & Pages**。
2.  点击 **创建应用程序** -> **创建 Worker**。
3.  给您的 Worker 起个名字（例如 `edge-gallery-worker`），选择hello work模板，点击部署，然后修改代码，把把worker.js文件复制进去部署即可。

### 第 3 步：配置 Worker

1.  进入您刚刚创建的 Worker 的设置页面。
2.  点击 **设置 (Settings)** -> **变量 (Variables)**。
3.  **添加 R2 存储桶绑定**:
    *   在 **R2 存储桶绑定 (R2 Bucket Bindings)** 部分，点击 **添加绑定**。
    *   **变量名称**: `MY_BUCKET` (自定义变量名称)
    *   **R2 存储桶**: 选择您在第 1 步中创建的那个存储桶。
    *   保存。
4.  **添加密钥 (Secrets)**:
    *   在 **Worker 密钥 (Secrets)** 部分，点击 **添加密钥**，添加以下两个密钥：
    *   **第一个密钥 (您的登录密码)**:
        *   密钥名称: `ACCESS_KEY`
        *   密钥值: 输入您想设置的登录密码 (例如 `MySuperSecretPassword123`)
    *   **第二个密钥 (用于加密)**:
        *   密钥名称: `JWT_SECRET`
        *   密钥值: 输入一个**长而随机的字符串** (您可以用在线密码生成器创建一个)
    *   保存所有更改。

### 第 4 步：粘贴代码并部署

1.  回到您的 Worker，点击 **快速编辑 (Quick Edit)**。
2.  删除编辑器里所有的默认代码。
3.  打开本项目中的 `worker.js` 文件，复制其**全部内容**。
4.  将复制的内容粘贴到 Cloudflare 的编辑器中。
5.  点击 **保存并部署 (Save and Deploy)**。

部署成功后，访问您的 Worker URL (`xxx.workers.dev`)，就可以开始使用您的私人相册了！

## 📄 许可证

本项目采用 [MIT](LICENSE) 许可证。
