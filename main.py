import threading
import asyncio
from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
# 导入异步版本的 TelegramClient
from telethon import TelegramClient
# 导入 Telethon 的用户状态类型，用于更精确的判断
from telethon.tl.types import UserStatusOnline, UserStatusOffline, UserStatusLastMonth, UserStatusLastWeek, UserStatusRecently
from datetime import datetime
import sqlite3
from passlib.hash import pbkdf2_sha256
import time # 可能用于启动时的短暂等待
import os # 用于检查 session 文件是否存在

# --- Flask 应用设置 ---
app = Flask(__name__)

# 配置 JWT
# **重要**: 在生产环境中，请务必将 'your_jwt_secret_key' 替换为一个强随机密钥
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key_replace_this'
jwt = JWTManager(app)

# --- Telegram API 配置 ---
# 从 my.telegram.org 获取你的 API ID 和 Hash
api_id = xxx
api_hash = '0xxx'

# 初始化异步版本的 Telethon 客户端 (全局可用)
# 'my_telegram_session' 是会话文件的名称（不包含 .session 扩展名）
# 如果你之前使用过不同的名称登录，请修改此处或删除旧的 .session 文件
session_file_name = 'my_telegram_session'
client = TelegramClient(session_file_name, api_id, api_hash)

# --- SQLite 数据库初始化 ---
DB_NAME = 'telegram_status.db'

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    # 用户表
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                     username TEXT PRIMARY KEY,
                     password TEXT
                   )''')
    # 追踪用户表
    c.execute('''CREATE TABLE IF NOT EXISTS tracked_users (
                     username TEXT,
                     telegram_user_id TEXT,
                     PRIMARY KEY (username, telegram_user_id)
                   )''')
    # 在线时段表
    c.execute('''CREATE TABLE IF NOT EXISTS online_sessions (
                     telegram_user_id TEXT,
                     start_time TEXT, -- ISO 8601 格式的字符串
                     end_time TEXT,   -- ISO 8601 格式的字符串
                     duration_seconds INTEGER
                   )''')
    # 状态和时长表
    c.execute('''CREATE TABLE IF NOT EXISTS user_status (
                     telegram_user_id TEXT PRIMARY KEY,
                     online_duration INTEGER DEFAULT 0, -- 累计在线时长（秒）
                     last_online TEXT, -- 最近一次上线时间的 ISO 8601 字符串，或 Telegram 提供的 last_seen 时间
                     last_status TEXT -- 记录 Telegram 报告的最后状态 (online, offline, hidden, etc.)
                   )''')
    conn.commit()
    conn.close()

init_db()

# --- Flask 路由 (大部分保持不变) ---

# 用户注册
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "用户名和密码不能为空"}), 400

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT username FROM users WHERE username = ?", (username,))
    if c.fetchone():
        conn.close()
        return jsonify({"error": "用户名已存在"}), 400

    hashed_password = pbkdf2_sha256.hash(password)
    c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
    conn.commit()
    conn.close()
    return jsonify({"message": "注册成功"}), 201

# 用户登录
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT password FROM users WHERE username = ?", (username,))
    result = c.fetchone()
    conn.close()

    if result and pbkdf2_sha256.verify(password, result[0]):
        access_token = create_access_token(identity=username)
        return jsonify({"access_token": access_token}), 200
    return jsonify({"error": "用户名或密码错误"}), 401

# 添加追踪用户
@app.route('/track/add', methods=['POST'])
@jwt_required()
def add_tracked_user():
    username = get_jwt_identity()
    data = request.get_json()
    telegram_user_id = data.get('telegram_user_id')

    if not telegram_user_id:
        return jsonify({"error": "用户 ID 不能为空"}), 400

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    try:
        # Attempt to insert, if user/id pair already exists, IntegrityError is raised
        c.execute("INSERT INTO tracked_users (username, telegram_user_id) VALUES (?, ?)",
                  (username, telegram_user_id))
        conn.commit()
    except sqlite3.IntegrityError:
        # User is already being tracked by this username
        conn.close()
        return jsonify({"error": "用户已在追踪列表中"}), 400
    except Exception as e:
         # Catch other potential database errors
         conn.close()
         return jsonify({"error": f"数据库错误: {e}"}), 500
    conn.close()
    return jsonify({"message": "添加成功"}), 200

# 删除追踪用户
@app.route('/track/remove', methods=['POST'])
@jwt_required()
def remove_tracked_user():
    username = get_jwt_identity()
    data = request.get_json()
    telegram_user_id = data.get('telegram_user_id')

    if not telegram_user_id:
         return jsonify({"error": "用户 ID 不能为空"}), 400

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("DELETE FROM tracked_users WHERE username = ? AND telegram_user_id = ?",
              (username, telegram_user_id))
    if c.rowcount == 0:
        conn.close()
        return jsonify({"error": "用户不在追踪列表中"}), 404
    conn.commit()
    conn.close()
    return jsonify({"message": "删除成功"}), 200

# 列出追踪用户
@app.route('/track/list', methods=['GET'])
@jwt_required()
def list_tracked_users():
    username = get_jwt_identity()
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT telegram_user_id FROM tracked_users WHERE username = ?", (username,))
    tracked_users = [row[0] for row in c.fetchall()]
    conn.close()
    return jsonify({"tracked_users": tracked_users}), 200

# --- Async Telethon 客户端管理和任务 ---

# 使用字典存储主 asyncio 事件循环的引用，方便在不同线程中访问
loop_container = {'loop': None}

# 这个异步函数将在主线程的 asyncio 事件循环中运行
async def run_telethon_client(telethon_client, loop_cont):
    # 获取当前正在运行的事件循环，并将其存储到容器中
    loop_cont['loop'] = asyncio.get_running_loop()

    print("Attempting to start Telethon client...")
    # 检查会话文件是否存在，如果存在则尝试恢复会话
    session_path = f"{session_file_name}.session"
    if os.path.exists(session_path):
         print(f"Session file '{session_path}' found. Attempting to resume session.")
    else:
         print(f"Session file '{session_path}' not found. Will require login (enter phone, code).")

    try:
        # 启动 Telethon 客户端并连接到 Telegram
        # await telethon_client.connect() # start() already includes connect() if not connected
        await telethon_client.start()
        print("Telethon client started successfully.")

        # **重要**: 让 asyncio 事件循环保持运行。
        # 如果你有 @client.on(...) 形式的事件处理器，TelegramClient 会在后台自动处理。
        # 对于这个脚本，主要是在 Flask 路由中按需查询状态，所以只需要事件循环保持运行。
        # await asyncio.Future() 是一个简单的方式来让当前协程无限期等待，从而保持事件循环活跃。
        # 如果你需要 Telethon 自动处理断开和重连，可以考虑使用 await telethon_client.run_until_disconnected()
        # 但对于按需查询，Future() 可能更简单。
        await asyncio.Future() # 保持事件循环运行直到取消

    except Exception as e:
        # 捕获 Telethon 启动过程中的错误
        print(f"Error starting Telethon client: {e}")
        # 可以在这里添加逻辑，根据错误类型进行处理
        # 例如，如果是 AuthKeyError，可能需要提示用户删除 session 文件并重新运行进行登录。
        # if isinstance(e, telethon.errors.AuthKeyError):
        #     print("Authentication error. Please delete the session file and try again.")

    finally:
        # 程序退出时断开 Telethon 连接
        print("Telethon client disconnecting...")
        # 确保客户端已连接才尝试断开
        if telethon_client and telethon_client.is_connected():
             await telethon_client.disconnect()
        print("Telethon client disconnected.")
        # 在退出时清除循环引用
        loop_cont['loop'] = None

# 这个异步函数用于从 Telethon 获取用户状态，将在主 asyncio 循环中执行
async def check_user_status_async(telethon_client, user_id):
     try:
         # 在进行 API 调用前，确保客户端已连接
         # 主运行函数 run_telethon_client 应该会保持连接，但多线程环境下检查一下是安全的。
         if not telethon_client or not telethon_client.is_connected():
             print("Client not connected in check_user_status_async.")
             # 如果客户端未连接，返回一个错误状态
             return {"status": "error", "error": "Telethon client is not connected."}

         # Telethon 的 get_entity 可以接受用户 ID (整数) 或用户名 (字符串)
         # 假设 user_id 参数可能是其中之一
         user = await telethon_client.get_entity(user_id)
         status = user.status # 获取用户的状态对象

         # 根据 Telethon 返回的不同状态类型进行判断
         if isinstance(status, UserStatusOnline):
              # 用户在线
              return {"status": "online", "last_seen": None} # 在线状态没有 last_seen 时间

         elif isinstance(status, UserStatusOffline):
              # 用户离线，并且 Telethon 提供了最后上线时间
              # status.was_online 是一个 datetime 对象
              return {"status": "offline", "last_seen": status.was_online.isoformat() if status.was_online else None}

         elif isinstance(status, (UserStatusLastMonth, UserStatusLastWeek, UserStatusRecently)):
              # 用户离线，但只提供了大致的最后上线时间
              # 这些状态通常也包含一个 was_online 属性
              last_seen_time = getattr(status, 'was_online', None) # 尝试获取 was_online 属性
              return {"status": type(status).__name__, "last_seen": last_seen_time.isoformat() if last_seen_time else None}

         elif status is None:
              # Telethon 返回的状态为 None。根据隐私设置，这可能意味着用户在线或最近在线。
              # 如果前面的精确状态类型都没有匹配，并且状态是 None，我们倾向于认为用户在线或最近在线。
              # 简单处理为 'online'，具体取决于你的需求和用户隐私设置。
              return {"status": "online", "last_seen": None}

         else:
              # 捕获 Telethon 返回的任何其他未知状态类型
              print(f"Unknown status type: {type(status).__name__} for user {user_id}")
              return {"status": "unknown", "last_seen": None}


     except Exception as e:
         # 捕获获取用户状态过程中的错误 (如用户不存在 UserNotFoundError)
         print(f"Error in check_user_status_async for {user_id}: {e}")
         return {"status": "error", "error": str(e)}

# --- 数据库操作辅助函数 (使用 DB_NAME) ---

# 保存一次在线时段
def save_session(telegram_user_id, start_time, end_time):
    duration = int((end_time - start_time).total_seconds())
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("INSERT INTO online_sessions (telegram_user_id, start_time, end_time, duration_seconds) VALUES (?, ?, ?, ?)",
              (telegram_user_id, start_time.isoformat(), end_time.isoformat(), duration)) # 存储为 ISO 字符串
    conn.commit()
    conn.close()

# 从数据库获取用户状态信息
def get_user_status(telegram_user_id):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    # last_online 在数据库中存储为 TEXT (ISO 字符串)，直接取出
    c.execute("SELECT online_duration, last_online, last_status FROM user_status WHERE telegram_user_id = ?",
              (telegram_user_id,))
    result = c.fetchone()
    conn.close()
    # 返回: 累计时长 (int), 最近上线时间 (ISO 字符串或 None), 最后状态 (字符串或 None)
    return result if result else (0, None, None)

# 更新数据库中的用户状态信息
def update_user_status(telegram_user_id, online_duration, last_online_dt, last_status):
    # last_online_dt 是一个 datetime 对象或 None，转换为 ISO 字符串用于存储
    last_online_iso = last_online_dt.isoformat() if last_online_dt else None

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    # 使用 INSERT OR REPLACE: 如果 telegram_user_id 已存在则更新，否则插入
    c.execute("INSERT OR REPLACE INTO user_status (telegram_user_id, online_duration, last_online, last_status) VALUES (?, ?, ?, ?)",
              (telegram_user_id, online_duration, last_online_iso, last_status))
    conn.commit()
    conn.close()

# --- 修改后的 /status/<user_id> 路由 ---
@app.route('/status/<user_id>', methods=['GET'])
@jwt_required()
def get_status(user_id):
    username = get_jwt_identity()

    # 1. 验证用户是否正在追踪此 Telegram 用户 ID
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT 1 FROM tracked_users WHERE username = ? AND telegram_user_id = ?",
              (username, user_id))
    is_tracking = c.fetchone() is not None
    conn.close()

    if not is_tracking:
        return jsonify({"error": "用户未在追踪列表中"}), 403

    # 2. 从 Telegram 获取用户当前状态 (这是异步操作，需要在主循环中运行)
    # 从容器中获取主 asyncio 事件循环的引用
    main_loop = loop_container.get('loop')

    # 检查主循环是否存在并且正在运行
    if main_loop and main_loop.is_running():
        try:
            # 使用 asyncio.run_coroutine_threadsafe() 将异步任务提交到主循环中执行
            # 这个函数会阻塞当前线程 (Flask 路由所在的线程)，直到异步任务完成并返回结果
            future = asyncio.run_coroutine_threadsafe(
                check_user_status_async(client, user_id), main_loop
            )
            # future.result() 会获取异步任务的返回值或抛出异常
            status_from_telegram = future.result()
        except Exception as e:
            print(f"Error running async task in Flask route: {e}")
            # 捕获提交或执行异步任务过程中的错误
            return jsonify({"error": f"Failed to get user status from Telegram: {e}"}), 500
    else:
         # 如果主循环未运行，说明 Telethon 客户端不可用
         return jsonify({"error": "Telethon client is not running or initialized."}), 500

    # 检查从异步任务返回的状态是否是错误状态
    if status_from_telegram["status"] == "error":
        return jsonify({"error": status_from_telegram["error"]}), 400

    # 3. 从 SQLite 数据库获取用户上次保存的状态和累计时长
    # get_user_status 返回 (int, ISO 字符串或 None, 字符串或 None)
    online_duration_db, last_online_iso_db, last_status_db = get_user_status(user_id)
    # 将数据库中存储的 ISO 字符串转换为 datetime 对象，方便后续计算
    last_online_dt_db = datetime.fromisoformat(last_online_iso_db) if last_online_iso_db else None

    now = datetime.now() # 获取当前时间

    # 4. 根据从 Telegram 获取的当前状态，更新在线时段和累计时长
    current_telethon_status = status_from_telegram["status"]
    # last_seen_telethon_iso 是从 check_user_status_async 返回的 ISO 字符串或 None
    last_seen_telethon_iso = status_from_telegram.get("last_seen", None)

    # 初始化将要更新到数据库的值
    updated_online_duration = online_duration_db
    updated_last_online_dt = last_online_dt_db
    updated_last_status = last_status_db

    # 逻辑判断：用户状态变化导致在线/离线时段的记录
    if current_telethon_status == "online" and last_status_db != "online":
        # 情况 1: 用户刚刚上线 (Telegram 报告在线，数据库记录不是在线)
        updated_last_online_dt = now # 将当前时间记录为本次在线时段的开始时间
        updated_last_status = "online"
    elif current_telethon_status != "online" and last_status_db == "online" and last_online_dt_db:
        # 情况 2: 用户刚刚离线 (Telegram 报告不是在线，数据库记录是在线，并且有上次的上线时间)
        # 这意味着一个在线时段结束了，保存这个时段
        save_session(user_id, last_online_dt_db, now) # 保存从上次上线到现在的时段
        # 将这个时段的持续时间加到累计总时长中
        updated_online_duration += int((now - last_online_dt_db).total_seconds())
        # 清空最近上线时间，因为该在线时段已经结束
        updated_last_online_dt = None
        # 更新数据库中的状态为 Telethon 报告的当前状态
        updated_last_status = current_telethon_status

    elif current_telethon_status != "online" and last_status_db != "online":
        # 情况 3: 用户一直处于离线或隐藏状态
        # 如果当前状态与数据库记录的状态不同，则更新数据库的状态
        if last_status_db != current_telethon_status:
             updated_last_status = current_telethon_status

        # 如果 Telethon 报告的状态是离线 (offline) 并且提供了 last_seen 时间，
        # 使用这个更精确的时间来更新数据库中的 last_online 字段 (表示最近一次看到的时间)
        if current_telethon_status == "offline" and last_seen_telethon_iso:
             last_seen_dt_telegram = datetime.fromisoformat(last_seen_telethon_iso)
             # 只有当 Telethon 报告的 last_seen 时间比数据库中记录的 last_online 更新，
             # 或者数据库中还没有记录 last_online 时，才进行更新。
             if updated_last_online_dt is None or last_seen_dt_telegram > updated_last_online_dt:
                 updated_last_online_dt = last_seen_dt_telegram


    # 5. 将更新后的状态和累计时长保存回数据库
    # update_user_status 期望一个 datetime 对象或 None 作为 last_online 参数
    update_user_status(user_id, updated_online_duration, updated_last_online_dt, updated_last_status)


    # 6. 从数据库获取历史在线时段记录
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT start_time, end_time, duration_seconds FROM online_sessions WHERE telegram_user_id = ?",
              (user_id,))
    # 提取查询结果，格式化为 JSON 可用的列表
    sessions = [{"start_time": row[0], "end_time": row[1], "duration_seconds": row[2]} for row in c.fetchall()]
    conn.close()

    # 7. 准备最终的 JSON 响应
    # status_from_telegram 字典中已经包含了状态和 last_seen (ISO 字符串或 None)
    return jsonify({
        "user_id": user_id,
        "status": status_from_telegram["status"], # 直接使用从 Telegram API 获取的状态
        "last_seen": status_from_telegram.get("last_seen", None), # 使用从 Telegram API 获取的 last_seen (ISO 字符串或 None)
        "online_duration_minutes": round(updated_online_duration / 60, 2), # 数据库中累计总时长 (分钟)
        "online_sessions": sessions # 历史在线时段列表
    })


# --- 运行 Flask 应用的线程函数 ---
def run_flask():
    print("Starting Flask server...")

    app.run(debug=False, host='127.0.0.1', port=5000)
    print("Flask server stopped.")

# --- 主程序入口 ---
if __name__ == '__main__':

    flask_thread = threading.Thread(target=run_flask)

    flask_thread.daemon = True
    flask_thread.start()

    try:
        
        asyncio.run(run_telethon_client(client, loop_container))
    except (KeyboardInterrupt, SystemExit):
        print("\nProgram interrupted by user (Ctrl+C). Initiating shutdown...")
        

    print("Main program thread finished.")
