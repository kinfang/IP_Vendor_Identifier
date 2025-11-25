# Use a slim Python image for a smaller final size
FROM centos:8

# Set environment variables
ENV PYTHONUNBUFFERED 1
ENV APP_PORT 5000

# ⚠️ 修复 CentOS 8 EOL 错误，并安装 curl (如果未预装)
# 1. 安装 curl 和基础工具 (如果需要)
RUN yum update -y && \
    yum install -y curl && \
    yum clean all

# 2. 替换为阿里云的 Vault 归档源配置文件
#    使用 Centos-vault-8.5.2111.repo 解决 EOL 问题
RUN mv /etc/yum.repos.d/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo.backup && \
    curl -o /etc/yum.repos.d/CentOS-Base.repo http://mirrors.aliyun.com/repo/Centos-vault-8.5.2111.repo && \
    yum clean all && yum makecache

# [3/8] 现在执行软件包安装
RUN yum install -y python3 python3-pip && \
    yum groupinstall -y 'Development Tools' && \
    yum install -y mysql-devel && \
    yum clean all

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