from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from telethon.sync import TelegramClient
from datetime import datetime
import sqlite3
from passlib.hash import pbkdf2_sha256
import asyncio

app = Flask(__name__)

# 配置 JWT
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'  # 替换为强随机密钥
jwt = JWTManager(app)

# Telegram API 配置
api_id = 'your_api_id'  # 从 my.telegram.org 获取
api_hash = 'your_api_hash'
client = TelegramClient('session', api_id, api_hash)

# SQLite 数据库初始化
def init_db():
    conn = sqlite3.connect('telegram_status.db')
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
                    start_time TEXT,
                    end_time TEXT,
                    duration_seconds INTEGER
                 )''')
    # 状态和时长表
    c.execute('''CREATE TABLE IF NOT EXISTS user_status (
                    telegram_user_id TEXT PRIMARY KEY,
                    online_duration INTEGER,
                    last_online TEXT,
                    last_status TEXT
                 )''')
    conn.commit()
    conn.close()

init_db()

# 用户注册
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({"error": "用户名和密码不能为空"}), 400
    
    conn = sqlite3.connect('telegram_status.db')
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
    
    conn = sqlite3.connect('telegram_status.db')
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
    
    conn = sqlite3.connect('telegram_status.db')
    c = conn.cursor()
    try:
        c.execute("INSERT INTO tracked_users (username, telegram_user_id) VALUES (?, ?)",
                  (username, telegram_user_id))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "用户已在追踪列表中"}), 400
    conn.close()
    return jsonify({"message": "添加成功"}), 200

# 删除追踪用户
@app.route('/track/remove', methods=['POST'])
@jwt_required()
def remove_tracked_user():
    username = get_jwt_identity()
    data = request.get_json()
    telegram_user_id = data.get('telegram_user_id')
    
    conn = sqlite3.connect('telegram_status.db')
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
    conn = sqlite3.connect('telegram_status.db')
    c = conn.cursor()
    c.execute("SELECT telegram_user_id FROM tracked_users WHERE username = ?", (username,))
    tracked_users = [row[0] for row in c.fetchall()]
    conn.close()
    return jsonify({"tracked_users": tracked_users}), 200

async def check_user_status(user_id):
    async with client:
        try:
            user = await client.get_entity(user_id)
            status = user.status
            if hasattr(status, 'was_online'):
                return {"status": "offline", "last_seen": status.was_online}
            elif status is None:
                return {"status": "online"}
            else:
                return {"status": "hidden"}
        except Exception as e:
            return {"status": "error", "error": str(e)}

def save_session(telegram_user_id, start_time, end_time):
    duration = int((end_time - start_time).total_seconds())
    conn = sqlite3.connect('telegram_status.db')
    c = conn.cursor()
    c.execute("INSERT INTO online_sessions (telegram_user_id, start_time, end_time, duration_seconds) VALUES (?, ?, ?, ?)",
              (telegram_user_id, start_time.isoformat(), end_time.isoformat(), duration))
    conn.commit()
    conn.close()

def get_user_status(telegram_user_id):
    conn = sqlite3.connect('telegram_status.db')
    c = conn.cursor()
    c.execute("SELECT online_duration, last_online, last_status FROM user_status WHERE telegram_user_id = ?",
              (telegram_user_id,))
    result = c.fetchone()
    conn.close()
    return result or (0, None, None)

def update_user_status(telegram_user_id, online_duration, last_online, last_status):
    conn = sqlite3.connect('telegram_status.db')
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO user_status (telegram_user_id, online_duration, last_online, last_status) VALUES (?, ?, ?, ?)",
              (telegram_user_id, online_duration, last_online.isoformat() if last_online else None, last_status))
    conn.commit()
    conn.close()

@app.route('/status/<user_id>', methods=['GET'])
@jwt_required()
def get_status(user_id):
    username = get_jwt_identity()
    
    # 验证用户是否在追踪列表
    conn = sqlite3.connect('telegram_status.db')
    c = conn.cursor()
    c.execute("SELECT 1 FROM tracked_users WHERE username = ? AND telegram_user_id = ?",
              (username, user_id))
    if not c.fetchone():
        conn.close()
        return jsonify({"error": "用户未在追踪列表中"}), 403
    conn.close()

    # 获取状态
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    status = loop.run_until_complete(check_user_status(user_id))
    
    if status["status"] == "error":
        return jsonify({"error": status["error"]}), 400

    # 获取当前状态和时长
    online_duration, last_online, last_status = get_user_status(user_id)
    last_online = datetime.fromisoformat(last_online) if last_online else None
    
    now = datetime.now()
    # 更新在线时段和时长
    if status["status"] == "online" and last_status != "online":
        last_online = now
        last_status = "online"
    elif status["status"] != "online" and last_status == "online" and last_online:
        save_session(user_id, last_online, now)
        online_duration += int((now - last_online).total_seconds())
        last_online = None
        last_status = "offline"
    
    # 保存状态
    update_user_status(user_id, online_duration, last_online, last_status)

    # 获取历史在线时段
    conn = sqlite3.connect('telegram_status.db')
    c = conn.cursor()
    c.execute("SELECT start_time, end_time, duration_seconds FROM online_sessions WHERE telegram_user_id = ?",
              (user_id,))
    sessions = [{"start_time": row[0], "end_time": row[1], "duration_seconds": row[2]} for row in c.fetchall()]
    conn.close()

    return jsonify({
        "user_id": user_id,
        "status": status["status"],
        "last_seen": status.get("last_seen", None),
        "online_duration_minutes": round(online_duration / 60, 2),
        "online_sessions": sessions
    })

if __name__ == '__main__':
    client.start()
    app.run(debug=True)