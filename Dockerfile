# Use a slim Python image for a smaller final size
FROM centos:8

# Set environment variables
ENV PYTHONUNBUFFERED 1
ENV APP_PORT 5000

# 1. ⚠️ 第一步：使用 sed 替换配置文件，强制指向 Vault 归档源
#    注意：此步骤不依赖网络连接和 curl，因此应该能成功执行
RUN sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-* && \
    sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-* && \
    yum clean all

# 2. 第二步：现在源已修复，执行更新和安装 curl
RUN yum update -y && \
    yum install -y curl && \
    yum clean all

# 3. 第三步：安装应用所需的其他依赖
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