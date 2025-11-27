## 📄 README.md: IP Vendor Identifier (IP 厂商识别工具)

这是一个基于 Python Flask/Gunicorn 的 Web 应用，专注于**查询域名解析的 IP 地址并识别其所属的厂商或服务提供商**。该工具允许用户指定 DNS 服务器进行查询，并将解析到的 IP 地址与内部数据库中的厂商 IP 范围进行比对，以实现快速的 IP 归属识别。该项目使用 Docker Compose 进行容器化部署。

## ✨ 核心特性

  * **指定 DNS 查询:** 允许用户指定权威 DNS 或递归 DNS 服务器进行精确查询。
  * **IP 归属识别:** 将域名解析到的 IP 地址与内部数据库中的厂商 IP 范围进行匹配。
  * **厂商 IP 映射管理：** 支持对内部 IP 范围（CIDR）和厂商名称、描述进行**增、删、改、查**全生命周期管理。
  * **智能 IP 筛选：** 在厂商管理界面，支持输入 **IP 地址** 进行 CIDR 范围的**精确匹配查询**，也支持模糊匹配厂商名称和描述。
  * **解析结果验证:** 方便快速验证 IP 地址的实际归属和运营商信息。
  * **容器化部署:** 通过 Docker Compose 一键启动应用和数据库服务。
  * **安全认证:** 基于密码哈希的环境变量管理管理员登录凭据。

## 🛠️ 技术栈

| 组件 | 最终使用的稳定版本/配置 | 备注 |
| :--- | :--- | :--- |
| **后端** | Python 3.11, Flask, Gunicorn | 应用代码语言环境。 |
| **应用基础镜像** | `python:3.11-alpine` | 解决了系统依赖安装的网络和权限兼容性问题。 |
| **数据库** | MariaDB 10.11 | **稳定选择**：解决了 MySQL 8.0/5.7 在 CentOS 8 宿主机上的启动兼容性问题。 |
| **数据库镜像** | `yobasystems/alpine-mariadb:10.11.10-x86_64` | **关键:** 这是一个经过验证的、能在旧内核上稳定运行的 MariaDB 镜像。 |
| **容器化** | Docker, Docker Compose | |

## 🚀 部署指南

### 1\. 先决条件

在开始部署之前，请确保您的系统已安装以下工具：

  * **Docker:** (版本 20.10 或更高)
  * **Docker Compose:** (版本 v2 或更高)

### 2\. 获取项目文件

克隆本 GitHub 仓库到您的本地机器：

```bash
git clone https://github.com/kinfang/IP_Vendor_Identifier.git
cd IP_Vendor_Identifier
```

### 3\. 配置环境变量

**安全警告：** 密钥和密码等敏感信息必须通过环境变量管理。本项目使用一个 `.env` 文件来同时配置应用和数据库。

1.  **创建配置文件：**
    在项目根目录下，创建一个名为 `.env` 的配置文件，并将所有环境变量（包括应用配置和数据库配置）集中写入其中。

2.  **生成密钥和哈希:**

| 变量 | 目的 | 生成方式 (在终端运行 Python) |
| :--- | :--- | :--- |
| `FLASK_SECRET_KEY` | Flask 会话和安全 | `python -c "import os; print(os.urandom(32).hex())"` |
| `ADMIN_PASSWORD_HASH` | 管理员密码哈希 | `python -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('your_secure_password', method='scrypt'))"` |

3.  **编辑 `.env` 文件:**

    ```dotenv
    # .env 文件内容示例 (包含所有配置)

    # --- 1. Flask 应用配置 ---
    FLASK_SECRET_KEY=YOUR_GENERATED_SECRET_KEY

    # ⚠️ 管理员认证配置
    ADMIN_USERNAME=admin
    # 使用 Python/Werkzeug 生成的 scrypt 哈希，**必须使用单引号 ' ' 包裹**，以避免 $ 符号被 shell 错误解析。
    ADMIN_PASSWORD_HASH='YOUR_SECURE_SCRYPT_HASH_HERE_INCLUDING_DOLLAR_SIGNS' 

    # --- 2. 数据库连接配置 (供应用和db服务使用) ---
    DB_HOST=db
    DB_PORT=3306
    DB_USER=ip_vendor_user
    DB_PASSWORD=YOUR_APP_DB_PASSWORD
    DB_NAME=ip_vendor_db

    # --- 3. MariaDB 服务初始化配置 ---\r
    # MySQL Root 密码 (用于数据库初始化和管理)
    MYSQL_ROOT_PASSWORD=YOUR_ROOT_PASSWORD 
    MYSQL_USER=ip_vendor_user      # 必须与 DB_USER 匹配
    MYSQL_PASSWORD=YOUR_APP_DB_PASSWORD # 必须与 DB_PASSWORD 匹配
    MYSQL_DATABASE=ip_vendor_db    # 必须与 DB_NAME 匹配
    ```

### 4\. 启动服务

**重要说明：** 由于项目在 CentOS 环境下存在兼容性问题，首次构建和后续更新都推荐使用**强制无缓存**方式构建应用镜像。

1.  **构建应用镜像（强制无缓存）：**
    此步骤使用 `python:3.11-alpine` 构建，并安装 `mariadb-dev` 依赖。

    ```bash
    docker-compose build --no-cache
    ```

2.  **启动所有服务：**
    此步骤会拉取并启动 MariaDB 容器，然后启动应用容器。

    ```bash
    docker-compose up -d
    ```

### 5\. 访问应用

应用服务默认监听容器的 **5000** 端口。如果您的 `docker-compose.yml` 中已将此端口映射到宿主机的 55556 端口 (`55556:5000`)：

打开浏览器，访问：

```
http://localhost:55556
```

使用您在 `.env` 中配置的 `ADMIN_USERNAME` 和对应密码进行登录。

## 💻 维护、更新与日志

### 查看实时日志

要查看应用服务 (`app`) 的输出和错误日志：

```bash
docker-compose logs -f app
```

### 更新应用代码或配置

当您修改了 Python 代码 (`realtime_dns_checker.py`) 或 HTML 模板文件 (`templates/*.html`) 后，必须执行以下命令来强制 Docker 重新构建和部署新代码，以避免缓存问题：

1.  **停止并移除旧容器：**
    ```bash
    docker-compose down
    ```
2.  **强制无缓存重新构建镜像：**
    ```bash
    docker-compose build --no-cache
    ```
3.  **重新启动服务：**
    ```bash
    docker-compose up -d
    ```

### 停止和移除服务

要停止并移除所有容器、网络和卷（数据卷不会被移除，以保留数据）：

```bash
docker-compose down
```

要停止并彻底删除所有容器、网络和数据卷（**慎用，将丢失所有数据库数据**）：

```bash
docker-compose down -v
```

> **关于数据持久性:** 数据库数据存储在 Docker 自动管理的命名卷 (`db_data`) 中，位于您的宿主机上。运行 `docker-compose down -v` 会删除此卷，导致数据丢失。