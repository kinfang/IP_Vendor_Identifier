# Use a slim Python image for a smaller final size
FROM python:3.11-slim-centos

# Set environment variables
ENV PYTHONUNBUFFERED 1
ENV APP_PORT 5000

# Install necessary system libraries for robust database connection
# 替换 apt-get 为 dnf/yum
# 安装 build-essential 的替代品（Development Tools）和 MySQL 开发库
# ⚠️ 使用阿里云 Vault 源修复 CentOS 8 EOL 错误
# 1. 备份并移除原有的官方配置文件
RUN mv /etc/yum.repos.d/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo.backup && \
# 2. 从阿里云下载新的 Vault 源配置文件
    curl -o /etc/yum.repos.d/CentOS-Base.repo https://mirrors.aliyun.com/repo/centos-stream/8/CentOS-Stream-BaseOS.repo && \
# # 3. 将新的配置文件重命名为 CentOS-Base.repo
#     mv /etc/yum.repos.d/Centos-vault-8.5.2111.repo /etc/yum.repos.d/CentOS-Base.repo && \
# 4. 清理缓存，确保使用新的源
    yum clean all && yum makecache
RUN dnf update -y && \
    dnf install -y python3-devel gcc && \
    dnf install -y mysql-devel && \
    dnf group install -y "Development Tools" && \
    dnf clean all

# Create working directory
WORKDIR /app

# Copy requirements file and install dependencies
COPY requirements.txt /app/
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy application code and templates
COPY realtime_dns_checker.py /app/
COPY templates /app/templates

# Gunicorn startup command (Production WSGI server)
# -w 4: 4 worker processes (adjust based on CPU cores, typically 2*cores + 1)
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "realtime_dns_checker:APP"]