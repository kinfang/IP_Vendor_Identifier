# -*- coding: utf-8 -*-
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, make_response
import mysql.connector
import dns.resolver
import ipaddress
import time
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash 
import os
import sys
from functools import wraps
import csv
from io import StringIO # 用于在内存中创建 CSV 文件

# ====================================================================
#                   !!! 安全配置区 !!!
# ====================================================================

# 从环境变量加载敏感配置 (默认值设置为None或空字符串，强制通过环境变量设置)
ADMIN_PASSWORD_HASH = os.environ.get('ADMIN_PASSWORD_HASH', '') 
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin') 

# Flask 密钥
APP = Flask(__name__)
# 生产环境密钥必须从环境变量加载
APP.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'default_key_FOR_DEV_ONLY') 

# MySQL 数据库配置
DB_CONFIG = {
   # host 默认为 Docker Compose 服务名 'db'
   "host": os.environ.get("DB_HOST", "db"), 
   "user": os.environ.get("DB_USER", ""),
   "password": os.environ.get("DB_PASSWORD", ""),    
   "database": os.environ.get("DB_NAME", "ip_vendor_db"),
   "port": int(os.environ.get("DB_PORT", 3306)),
}
# ⚠️ 全局变量。每个 Gunicorn Worker 进程都有独立的副本。
IP_VENDOR_MAP_CACHE = []
# 新增：记录当前 Worker 进程最近一次成功加载缓存的时间戳
LAST_CACHE_LOAD_TIME = 0.0 


# ====================================================================
#                   Flask-Login 配置
# ====================================================================

login_manager = LoginManager()
login_manager.init_app(APP)
login_manager.login_view = 'login' 
login_manager.login_message = "请登录以访问此页面。"


class User(UserMixin):
   def __init__(self, id):
      self.id = id

@login_manager.user_loader
def load_user(user_id):
   if user_id == ADMIN_USERNAME:
      return User(user_id)
   return None

# ====================================================================
#                   核心功能和工具函数
# ====================================================================

def get_db_connection():
   try:
      return mysql.connector.connect(**DB_CONFIG)
   except mysql.connector.Error as e:
      # print(f"❌ DEBUG: 数据库连接失败: {e}", file=sys.stderr)
      return None

def get_last_db_update_time():
   """从数据库的 system_config 表中获取共享的最后更新时间戳。"""
   conn = get_db_connection()
   if not conn:
      return 0.0 # 数据库连接失败时返回 0，避免频繁尝试加载
   
   cursor = conn.cursor()
   sql = "SELECT config_value FROM system_config WHERE config_key = 'last_vendor_update'"
   
   try:
      cursor.execute(sql)
      result = cursor.fetchone()
      if result:
         return float(result[0])
      return 0.0
   except Exception as e:
      print(f"❌ 获取数据库更新时间失败: {e}", file=sys.stderr)
      return 0.0
   finally:
      cursor.close()
      conn.close()

def set_db_update_time(timestamp):
   """将当前的 Unix 时间戳写入数据库，作为共享的更新信号。"""
   conn = get_db_connection()
   if not conn:
      print("❌ 警告: 无法连接数据库设置更新时间。", file=sys.stderr)
      return False 
   
   cursor = conn.cursor()
   sql = """
      INSERT INTO system_config (config_key, config_value) VALUES ('last_vendor_update', %s)
      ON DUPLICATE KEY UPDATE config_value = %s
   """
   try:
      cursor.execute(sql, (str(timestamp), str(timestamp)))
      conn.commit()
      return True
   except Exception as e:
      print(f"❌ 设置数据库更新时间失败: {e}", file=sys.stderr)
      return False
   finally:
      cursor.close()
      conn.close()

def load_cidr_map_from_db():
   """从数据库加载 IP 厂商映射，按 CIDR 长度降序排序，并更新 Worker 的加载时间。"""
   conn = get_db_connection()
   if not conn:
      print("❌ 警告: 无法连接数据库，厂商映射无法加载。", file=sys.stderr)
      return False 
   
   global IP_VENDOR_MAP_CACHE
   global LAST_CACHE_LOAD_TIME
   
   cursor = conn.cursor()
   sql = "SELECT cidr_range, vendor_name FROM ip_vendor_map" 
   
   success = False
   try:
      cursor.execute(sql)
      rows = cursor.fetchall()
      IP_VENDOR_MAP_CACHE = [] # 清除旧缓存
      
      for cidr_str, vendor_name in rows:
         try:
            network = ipaddress.ip_network(cidr_str, strict=False) 
            IP_VENDOR_MAP_CACHE.append((network, vendor_name))
         except ValueError:
            print(f"❌ 警告: 跳过数据库中无效的 CIDR 字符串: {cidr_str}", file=sys.stderr)
            pass 
            
      # 按 CIDR 长度（前缀长度）降序排序，确保最精确匹配优先
      IP_VENDOR_MAP_CACHE.sort(key=lambda x: x[0].prefixlen, reverse=True)
      
      # 只有成功加载后才更新本 Worker 的加载时间戳
      LAST_CACHE_LOAD_TIME = time.time()
            
      print(f"✅ 厂商映射加载成功，共 {len(IP_VENDOR_MAP_CACHE)} 条记录。Worker 缓存时间: {LAST_CACHE_LOAD_TIME}", file=sys.stderr)
      success = True
   except Exception as e:
      print(f"❌ 加载 CIDR 映射失败: {e}", file=sys.stderr)
   finally:
      cursor.close()
      conn.close()
   return success 

def check_and_reload_cache():
   """检查共享的数据库更新时间戳，如果比本 Worker 的缓存时间新，则触发重新加载。"""
   global LAST_CACHE_LOAD_TIME
   
   # 1. 检查数据库的共享时间戳
   db_update_time = get_last_db_update_time()
   
   # 2. 比较时间戳，或检查缓存是否从未加载过
   if db_update_time > LAST_CACHE_LOAD_TIME or LAST_CACHE_LOAD_TIME == 0.0:
      print(f"💡 INFO: 发现数据更新信号 (DB: {db_update_time} > Worker: {LAST_CACHE_LOAD_TIME})，正在重新加载缓存...", file=sys.stderr)
      load_cidr_map_from_db()

def lookup_vendor(ip_address_str):
   try:
      # 确保在查询前，当前 Worker 的缓存已同步
      check_and_reload_cache()
      
      # 将输入 IP 地址转换为 IP 地址对象
      ip_obj = ipaddress.ip_address(ip_address_str) 
      
      # 遍历内存缓存。由于缓存已排序，第一个匹配到的就是最精确的。
      for network, vendor_name in IP_VENDOR_MAP_CACHE:
         # 核心查找逻辑：检查 IP 对象是否在 network 范围内
         if ip_obj in network:
            return vendor_name
            
      return "未知/未匹配"
   except ValueError:
      return "IP格式错误"
   except Exception:
      return "查询异常"

def resolve_domain_with_custom_dns(domain, custom_servers):
   resolver = dns.resolver.Resolver()
   resolver.nameservers = custom_servers
   resolver.timeout = 5.0
   resolver.lifetime = 5.0
   results = []
   
   try:
      answers = resolver.resolve(domain, 'A')
      for rdata in answers:
         ip_str = rdata.address
         vendor = lookup_vendor(ip_str)
         results.append({
            'domain': domain,
            'type': 'A',
            'value': ip_str,
            'vendor': vendor,
            'status': 'OK'
         })
   except dns.resolver.NXDOMAIN:
      results.append({'domain': domain, 'type': 'A', 'value': 'N/A', 'vendor': 'N/A', 'status': 'NXDOMAIN'})
   except dns.exception.Timeout:
      results.append({'domain': domain, 'type': 'A', 'value': 'N/A', 'vendor': 'N/A', 'status': 'TIMEOUT'})
   except Exception as e:
      results.append({'domain': domain, 'type': 'A', 'value': 'N/A', 'vendor': 'N/A', 'status': f'ERROR: {e}'})
      
   return results

# ====================================================================
#                   认证和视图路由
# ====================================================================

@APP.route('/login', methods=['GET', 'POST'])
def login():
   if current_user.is_authenticated:
      return redirect(url_for('index'))

   if request.method == 'POST':
      username = request.form.get('username')
      password = request.form.get('password')
      
      if username == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, password):
         user = load_user(username)
         login_user(user)
         flash('登录成功！', 'success')
         
         # 首次登录时，强制当前 Worker 加载缓存，确保登录后的第一个查询是准确的。
         load_cidr_map_from_db()
            
         return redirect(url_for('index'))
      else:
         flash('用户名或密码错误。', 'danger')

   return render_template('login.html')

@APP.route('/logout')
@login_required 
def logout():
   logout_user()
   flash('您已成功登出。', 'success')
   return redirect(url_for('login'))

@APP.route('/')
@login_required
def index():
   return render_template('query_form.html')

# ----------------- 厂商管理模块 -----------------

@APP.route('/vendor_manage')
@login_required
def vendor_manage_page():
   return render_template('vendor_manage.html')

@APP.route('/api/vendors', methods=['GET'])
@login_required
def get_vendors():
   # 在展示列表前，先检查并同步当前 Worker 的缓存
   check_and_reload_cache()
   
   conn = get_db_connection()
   if not conn:
      # DB 连接失败时，返回 500 错误
      return jsonify({'status': 'error', 'message': '无法连接数据库。'}), 500
   
   cursor = conn.cursor(dictionary=True) 
   sql = "SELECT id, cidr_range, vendor_name, description FROM ip_vendor_map ORDER BY id DESC"
   
   try:
      cursor.execute(sql)
      vendors = cursor.fetchall()
      return jsonify({'status': 'success', 'vendors': vendors})
   except Exception as e:
      return jsonify({'status': 'error', 'message': f'查询厂商数据失败: {e}'}), 500
   finally:
      cursor.close()
      conn.close()

@APP.route('/delete_vendor/<int:vendor_id>', methods=['POST'])
@login_required
def delete_vendor(vendor_id):
   conn = get_db_connection()
   if not conn:
      return jsonify({'status': 'error', 'message': '无法连接数据库。'}), 500

   cursor = conn.cursor()
   sql = "DELETE FROM ip_vendor_map WHERE id = %s"
   
   try:
      cursor.execute(sql, (vendor_id,))
      rows_affected = cursor.rowcount
      conn.commit()

      if rows_affected == 0:
         return jsonify({'status': 'error', 'message': '厂商记录不存在。'}), 404

      # 关键操作 1：删除后刷新当前 worker 的内存缓存
      load_cidr_map_from_db()
      # 关键操作 2：更新数据库中的共享时间戳，通知其他 Worker 
      set_db_update_time(time.time())
      
      return jsonify({'status': 'success', 'message': f'厂商记录 ID {vendor_id} 删除成功，缓存已同步。'})
   
   except mysql.connector.Error as err:
      return jsonify({'status': 'error', 'message': f'数据库删除失败: {err.msg}'}), 500
   finally:
      cursor.close()
      conn.close()

@APP.route('/update_vendor/<int:vendor_id>', methods=['POST'])
@login_required 
def update_vendor(vendor_id):
   data = request.json
   
   vendor_name = data.get('vendor_name')
   cidr_range = data.get('cidr_range')
   description = data.get('description', '')

   if not vendor_name or not cidr_range:
      return jsonify({'status': 'error', 'message': '厂商名称和 CIDR 范围不能为空。'}), 400
      
   try:
      # 验证 CIDR 范围格式
      ipaddress.ip_network(cidr_range, strict=False) 
   except ValueError:
      return jsonify({'status': 'error', 'message': 'CIDR 范围格式无效，请检查。'}), 400

   conn = get_db_connection()
   if not conn:
      return jsonify({'status': 'error', 'message': '无法连接数据库进行更新操作。'}), 500
   
   cursor = conn.cursor()
   # 使用 UPDATE 语句
   sql = """
      UPDATE ip_vendor_map 
      SET vendor_name = %s, cidr_range = %s, description = %s
      WHERE id = %s
   """
   
   try:
      cursor.execute(sql, (vendor_name, cidr_range, description, vendor_id))
      rows_affected = cursor.rowcount
      conn.commit()
      
      if rows_affected == 0:
         # 如果数据未更改，不需要刷新缓存
         return jsonify({'status': 'success', 'message': f'厂商记录 ID {vendor_id} 未更改。'})

      # 关键操作 1：更新后刷新当前 worker 的内存缓存
      load_cidr_map_from_db()
      # 关键操作 2：更新数据库中的共享时间戳，通知其他 Worker 
      set_db_update_time(time.time())
      
      return jsonify({'status': 'success', 'message': f'厂商记录 ID {vendor_id} 更新成功，缓存已同步。'})
   
   except mysql.connector.IntegrityError:
      # 可能是新的 cidr_range 与其他记录重复
      return jsonify({'status': 'error', 'message': f'CIDR 范围 "{cidr_range}" 已存在于其他记录中，请检查。'}), 409
   except mysql.connector.Error as err:
      return jsonify({'status': 'error', 'message': f'数据库更新失败: {err.msg}'}), 500
   finally:
      cursor.close()
      conn.close()


# ----------------- 保持原有 API -----------------

@APP.route('/query', methods=['POST'])
@login_required 
def handle_query():
   # 核心修复点：在每次查询开始时，检查并同步当前 Worker 的缓存
   check_and_reload_cache()
   
   data = request.json
   
   domains_input = data.get('domains', '')
   dns_input = data.get('dns_servers', '')
   
   domains = [d.strip() for d in domains_input.split('\n') if d.strip()]
   
   # 过滤掉以 '#' 开头（忽略前后空格）的行
   custom_servers = [
       ip.strip() 
       for ip in dns_input.split('\n') 
       if ip.strip() and not ip.strip().startswith('#')
   ]

   if not custom_servers:
      return jsonify({'error': '请至少提供一个 DNS 服务器 IP 地址（非注释行）。'}), 400
   if not domains:
      return jsonify({'error': '请提供域名列表。'}), 400

   all_results = []
   start_time = time.time()
   
   for domain in domains:
      results = resolve_domain_with_custom_dns(domain, custom_servers)
      all_results.extend(results)
   
   end_time = time.time()
   
   return jsonify({
      'status': 'success',
      'time_taken': f"{(end_time - start_time):.3f} 秒",
      'results': all_results
   })


@APP.route('/export_query', methods=['POST'])
@login_required
def export_query_results():
    """接收查询结果的 JSON 数据，并将其转换为 CSV 文件进行下载。"""
    try:
        # 获取前端发送的 JSON 数据
        data = request.json
        results = data.get('results', [])
        
        if not results:
            return jsonify({'status': 'error', 'message': '没有查询结果可以导出。'}), 400

        # 定义 CSV 头部和字段
        fieldnames = ['domain', 'type', 'value', 'vendor', 'status']
        
        # 使用 StringIO 在内存中构建 CSV 文件
        output = StringIO()
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        
        # 写入头部
        writer.writeheader()
        
        # 写入数据行
        writer.writerows(results)
        
        csv_output = output.getvalue()
        
        # 创建 Flask 响应对象，设置 MIME 类型和文件名
        response = make_response(csv_output)
        response.headers["Content-Disposition"] = "attachment; filename=dns_query_results.csv"
        # 设置正确的 CSV MIME 类型，并指定 UTF-8 编码以支持中文
        response.headers["Content-type"] = "text/csv; charset=utf-8"
        
        return response
        
    except Exception as e:
        print(f"❌ 导出查询结果失败: {e}", file=sys.stderr)
        return jsonify({'status': 'error', 'message': f'导出过程中发生错误: {e}'}), 500


@APP.route('/add_vendor', methods=['POST'])
@login_required 
def add_vendor():
   data = request.json
   
   vendor_name = data.get('vendor_name')
   cidr_range = data.get('cidr_range')
   description = data.get('description', '')

   if not vendor_name or not cidr_range:
      return jsonify({'status': 'error', 'message': '厂商名称和 CIDR 范围不能为空。'}), 400
      
   try:
      # 允许用户输入非标准网络地址，并在内部将其视为标准网络地址
      ipaddress.ip_network(cidr_range, strict=False) 
   except ValueError:
      return jsonify({'status': 'error', 'message': 'CIDR 范围格式无效，请检查。'}), 400

   conn = get_db_connection()
   if not conn:
      return jsonify({'status': 'error', 'message': '无法连接数据库进行写入操作。'}), 500
   
   cursor = conn.cursor()
   sql = "INSERT INTO ip_vendor_map (cidr_range, vendor_name, description) VALUES (%s, %s, %s)"
   
   try:
      cursor.execute(sql, (cidr_range, vendor_name, description))
      conn.commit()
      
      # 关键操作 1：添加后刷新当前 worker 的内存缓存
      load_cidr_map_from_db()
      # 关键操作 2：更新数据库中的共享时间戳，通知其他 Worker 
      set_db_update_time(time.time())
      
      return jsonify({'status': 'success', 'message': f'厂商 "{vendor_name}" (CIDR: {cidr_range}) 添加成功，缓存已同步。'})
   
   except mysql.connector.IntegrityError:
      return jsonify({'status': 'error', 'message': f'CIDR 范围 "{cidr_range}" 已存在，请勿重复添加。'}), 409
   except mysql.connector.Error as err:
      return jsonify({'status': 'error', 'message': f'数据库写入失败: {err.msg}'}), 500
   finally:
      cursor.close()
      conn.close()