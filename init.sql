-- 文件: init.sql (修正后)

-- 显式选择要操作的数据库
USE ip_vendor_db;

-- 确保使用utf8mb4字符集支持中文描述
CREATE TABLE IF NOT EXISTS ip_vendor_map (
    id INT AUTO_INCREMENT PRIMARY KEY,
    cidr_range VARCHAR(45) NOT NULL UNIQUE,
    vendor_name VARCHAR(255) NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 新增：用于存储应用系统配置和缓存同步信号的表
CREATE TABLE IF NOT EXISTS system_config (
    config_key VARCHAR(100) PRIMARY KEY,
    config_value VARCHAR(255)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 初始化厂商 IP 映射的最后更新时间为 0，确保所有 Worker 在启动时都会加载缓存
INSERT INTO system_config (config_key, config_value) VALUES ('last_vendor_update', '0')
ON DUPLICATE KEY UPDATE config_value = config_value;