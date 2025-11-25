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