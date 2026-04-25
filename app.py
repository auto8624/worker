from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from functools import wraps
import json
import requests
import threading
import time
import os
import socket
import secrets
import ipaddress
import re
from datetime import datetime, timedelta
import calendar
from flask_sock import Sock
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from urllib.parse import urlparse
from models import init_db, hash_password, verify_password, needs_password_rehash, load_data, save_data, update_data, default_push_settings, append_push_log, read_push_logs, normalize_notification_record, normalize_week_days_values
from config import Config

app = Flask(__name__)
sock = Sock(app)
app.secret_key = Config.SECRET_KEY
app.config.update(
    SESSION_COOKIE_HTTPONLY=Config.SESSION_COOKIE_HTTPONLY,
    SESSION_COOKIE_SAMESITE=Config.SESSION_COOKIE_SAMESITE,
    SESSION_COOKIE_SECURE=Config.SESSION_COOKIE_SECURE,
    MAX_CONTENT_LENGTH=Config.MAX_CONTENT_LENGTH,
)

_UNSAFE_METHODS = {'POST', 'PUT', 'PATCH', 'DELETE'}
_rate_limit_lock = threading.Lock()
_rate_limit_store = {'login': {}}

_ws_clients = set()
_ws_lock = threading.Lock()


def broadcast_event(event_type, payload=None):
    """向已登录浏览器广播实时事件；发送失败的连接会自动清理。"""
    event = {
        'type': event_type,
        'payload': payload or {},
        'ts': now_str() if 'now_str' in globals() else datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    }
    raw = json.dumps(event, ensure_ascii=False)
    with _ws_lock:
        clients = list(_ws_clients)
    dead = []
    for client in clients:
        try:
            client.send(raw)
        except Exception:
            dead.append(client)
    if dead:
        with _ws_lock:
            for client in dead:
                _ws_clients.discard(client)


@sock.route('/ws')
def websocket_status(ws):
    if 'user_id' not in session:
        ws.close()
        return
    with _ws_lock:
        _ws_clients.add(ws)
    try:
        ws.send(json.dumps({'type': 'connected', 'payload': {'message': '实时状态已连接'}, 'ts': now_str()}, ensure_ascii=False))
        while True:
            message = ws.receive()
            if message is None:
                break
            if message == 'ping':
                ws.send(json.dumps({'type': 'pong', 'ts': now_str()}, ensure_ascii=False))
    finally:
        with _ws_lock:
            _ws_clients.discard(ws)



def get_or_create_csrf_token():
    token = session.get('csrf_token')
    if not token:
        token = secrets.token_urlsafe(32)
        session['csrf_token'] = token
    return token


def get_client_ip():
    forwarded = request.headers.get('X-Forwarded-For', '')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.remote_addr or 'unknown'


def check_rate_limit(scope, key, max_attempts=6, window_seconds=300, block_seconds=900):
    now_ts = time.time()
    with _rate_limit_lock:
        scope_store = _rate_limit_store.setdefault(scope, {})
        record = scope_store.setdefault(key, {'hits': [], 'blocked_until': 0})
        if record['blocked_until'] > now_ts:
            return False, int(record['blocked_until'] - now_ts)
        record['hits'] = [ts for ts in record['hits'] if now_ts - ts <= window_seconds]
        if len(record['hits']) >= max_attempts:
            record['blocked_until'] = now_ts + block_seconds
            record['hits'].clear()
            return False, block_seconds
        return True, 0


def record_rate_limit_failure(scope, key, window_seconds=300):
    now_ts = time.time()
    with _rate_limit_lock:
        record = _rate_limit_store.setdefault(scope, {}).setdefault(key, {'hits': [], 'blocked_until': 0})
        record['hits'] = [ts for ts in record['hits'] if now_ts - ts <= window_seconds]
        record['hits'].append(now_ts)


def clear_rate_limit(scope, key):
    with _rate_limit_lock:
        _rate_limit_store.setdefault(scope, {}).pop(key, None)


def get_local_now():
    return datetime.utcnow() + timedelta(hours=8)


def sanitize_push_url(url):
    value = (url or '').strip()
    if not value:
        return ''
    if value.startswith(('http://', 'https://')):
        protocol, rest = value.split('://', 1)
        stripped_rest = rest.rstrip('/')
        return f'{protocol}://{stripped_rest}' if stripped_rest else value
    return value.rstrip('/')


def normalize_ping_target(target):
    return (target or '').strip().rstrip('/')


def is_safe_outbound_url(raw_url):
    value = sanitize_push_url(raw_url)
    if not value:
        return False, '地址不能为空'
    parsed = urlparse(value)
    if parsed.scheme not in ('http', 'https'):
        return False, '仅支持 HTTP/HTTPS 地址'
    hostname = parsed.hostname
    if not hostname:
        return False, '地址缺少主机名'
    lowered = hostname.lower()
    if lowered in ('localhost',) or lowered.endswith('.localhost'):
        return False, '不允许访问本地地址'
    try:
        addrinfos = socket.getaddrinfo(hostname, parsed.port or (443 if parsed.scheme == 'https' else 80), type=socket.SOCK_STREAM)
    except Exception:
        return False, '地址解析失败，请检查域名'
    for info in addrinfos:
        try:
            ip_obj = ipaddress.ip_address(info[4][0])
        except Exception:
            return False, '地址解析结果无效'
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified:
            return False, '不允许访问内网或保留地址'
    return True, ''


def is_public_host_or_ip(hostname):
    lowered = (hostname or '').strip().lower()
    if not lowered or lowered in ('localhost',) or lowered.endswith('.localhost'):
        return False
    try:
        addrinfos = socket.getaddrinfo(lowered, None)
    except Exception:
        return False
    for info in addrinfos:
        try:
            ip_obj = ipaddress.ip_address(info[4][0])
        except Exception:
            return False
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified:
            return False
    return True


def validate_push_urls(data):
    checks = [
        ('wecom_enabled', 'wecom_webhook', '企业微信 Webhook'),
        ('telegram_enabled', 'telegram_api_url', 'Telegram API 地址'),
        ('xizhi_enabled', 'xizhi_url', '息知 URL'),
        ('pushplus_enabled', 'pushplus_url', 'PushPlus URL'),
        ('custom_webhook1_enabled', 'custom_webhook1_url', 'Webhook1 地址'),
        ('custom_webhook2_enabled', 'custom_webhook2_url', 'Webhook2 地址'),
    ]
    for enabled_field, field, label in checks:
        if not data.get(enabled_field):
            continue
        raw_value = data.get(field, '')
        if raw_value:
            ok, msg = is_safe_outbound_url(raw_value)
            if not ok:
                return False, f'{label} 不合法: {msg}'
    return True, ''


def build_allowed_origins():
    origins = {f'{request.scheme}://{request.host}'}
    forwarded_host = (request.headers.get('X-Forwarded-Host') or '').split(',')[0].strip()
    forwarded_proto = (request.headers.get('X-Forwarded-Proto') or '').split(',')[0].strip() or request.scheme
    if forwarded_host:
        origins.add(f'{forwarded_proto}://{forwarded_host}')
    original_host = (request.headers.get('X-Original-Host') or '').strip()
    if original_host:
        origins.add(f'{forwarded_proto}://{original_host}')
    return origins


def is_allowed_origin(origin_value):
    if not origin_value:
        return True
    parsed = urlparse(origin_value)
    if not parsed.scheme or not parsed.netloc:
        return False
    if origin_value in build_allowed_origins():
        return True
    return (parsed.hostname or '').lower().endswith('.monkeycode-ai.online')


@app.before_request
def enforce_security_guards():
    get_or_create_csrf_token()
    if request.method not in _UNSAFE_METHODS:
        return None
    expected = session.get('csrf_token')
    provided = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token')
    if not expected or not provided or provided != expected:
        if request.path.startswith('/api/'):
            return jsonify({'success': False, 'message': 'CSRF 校验失败'}), 403
        return 'CSRF validation failed', 403
    origin = request.headers.get('Origin')
    if not is_allowed_origin(origin):
        if request.path.startswith('/api/'):
            return jsonify({'success': False, 'message': '非法来源请求'}), 403
        return 'Origin validation failed', 403
    return None


@app.context_processor
def inject_session():
    return dict(session=dict(user_id=session.get('user_id'), username=session.get('username'), is_admin=session.get('is_admin')), csrf_token=get_or_create_csrf_token())


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            if request.path.startswith('/api/'):
                return jsonify({'success': False, 'message': '请先登录'}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


admin_required = login_required


def current_user():
    return load_data().get('user')


def now_str():
    return get_local_now().strftime('%Y-%m-%d %H:%M:%S')


def trim_notification_logs(data, keep_count=50):
    data['notification_logs'] = sorted(data.get('notification_logs', []), key=lambda x: (x.get('pushed_at', ''), x.get('id', 0)), reverse=True)[:keep_count]


def add_notification_log(data, notification_id, status, message):
    notification = get_notification_by_id(data, notification_id)
    log_item = {
        'id': data.get('next_log_id', 1),
        'notification_id': int(notification_id),
        'notification_name': notification.get('name', '') if notification else '',
        'pushed_at': now_str(),
        'status': status,
        'message': (message or '')[:500],
    }
    append_push_log(log_item)
    data.setdefault('notification_logs', []).insert(0, log_item)
    data['next_log_id'] = data.get('next_log_id', 1) + 1
    trim_notification_logs(data, 50)




def iso_now():
    return get_local_now().strftime('%Y-%m-%d %H:%M:%S')


def parse_dt(value):
    try:
        return datetime.strptime((value or '')[:19], '%Y-%m-%d %H:%M:%S')
    except Exception:
        return None


def enqueue_retry(data, notification_id, notification_name, message, error, source='scheduled', attempt=0):
    queue = data.setdefault('retry_queue', [])
    if len(queue) >= 100:
        queue[:] = queue[-80:]
    base_delays = [60, 300, 900]
    next_delay = base_delays[min(max(int(attempt), 0), len(base_delays) - 1)]
    now = get_local_now()
    queue.append({
        'id': f"{int(time.time() * 1000)}-{notification_id}-{attempt}",
        'notification_id': int(notification_id),
        'notification_name': notification_name or '',
        'message': message or '',
        'attempt': int(attempt),
        'max_attempts': 3,
        'next_retry_at': (now + timedelta(seconds=next_delay)).strftime('%Y-%m-%d %H:%M:%S'),
        'last_error': (error or '')[:200],
        'source': source,
        'created_at': now.strftime('%Y-%m-%d %H:%M:%S'),
    })


def send_notification_with_retry(data, notification, message, source='scheduled'):
    sent, msg = send_notification(data.get('push_settings') or default_push_settings(), message)
    status = 'success' if sent else 'failed'
    add_notification_log(data, notification.get('id'), status, message if sent else (msg or '推送失败'))
    if sent:
        broadcast_event('push_status', {'notification_id': notification.get('id'), 'status': 'success', 'message': '推送成功'})
    else:
        enqueue_retry(data, notification.get('id'), notification.get('name'), message, msg or '推送失败', source=source, attempt=0)
        broadcast_event('push_status', {'notification_id': notification.get('id'), 'status': 'failed', 'message': msg or '推送失败，已加入重试队列'})
    return sent, msg


def process_retry_queue():
    now = get_local_now()
    changed = {'count': 0}
    def mutate(data):
        queue = data.setdefault('retry_queue', [])
        remaining = []
        push_settings = data.get('push_settings') or default_push_settings()
        for item in queue:
            due = parse_dt(item.get('next_retry_at'))
            if not due or due > now:
                remaining.append(item)
                continue
            changed['count'] += 1
            notification_id = int(item.get('notification_id') or 0)
            notification = get_notification_by_id(data, notification_id) or {'id': notification_id, 'name': item.get('notification_name', '')}
            sent, msg = send_notification(push_settings, item.get('message') or '')
            attempt = int(item.get('attempt') or 0) + 1
            if sent:
                add_notification_log(data, notification_id, 'success', f"重试成功：{item.get('message') or ''}")
                broadcast_event('push_status', {'notification_id': notification_id, 'status': 'retry_success', 'message': '重试推送成功'})
            elif attempt < int(item.get('max_attempts') or 3):
                item['attempt'] = attempt
                item['last_error'] = (msg or '重试失败')[:200]
                delays = [60, 300, 900]
                item['next_retry_at'] = (now + timedelta(seconds=delays[min(attempt, len(delays)-1)])).strftime('%Y-%m-%d %H:%M:%S')
                remaining.append(item)
                add_notification_log(data, notification_id, 'retrying', f"第{attempt}次重试失败，稍后继续：{msg or '失败'}")
                broadcast_event('push_status', {'notification_id': notification_id, 'status': 'retrying', 'message': f'第{attempt}次重试失败，稍后继续'})
            else:
                add_notification_log(data, notification_id, 'failed', f"重试已达上限：{msg or '失败'}")
                broadcast_event('push_status', {'notification_id': notification_id, 'status': 'retry_failed', 'message': '重试已达上限'})
        data['retry_queue'] = remaining[-100:]
    update_data(mutate)
    if changed['count']:
        broadcast_event('state_update', {'reason': 'retry_queue'})
    return changed['count']

def get_notification_by_id(data, notification_id):
    target = str(notification_id)
    for n in data.get('notifications', []):
        if str(n.get('id')) == target:
            return normalize_notification_record(n)
    try:
        target_id = int(notification_id)
    except (TypeError, ValueError):
        return None
    for n in data.get('notifications', []):
        try:
            if int(n.get('id') or 0) == target_id:
                return normalize_notification_record(n)
        except (TypeError, ValueError):
            continue
    return None


def get_notification_record_ref(data, notification_id):
    """Return the mutable stored notification record, not a normalized copy."""
    target = str(notification_id)
    for n in data.get('notifications', []):
        if str(n.get('id')) == target:
            return n
    try:
        target_id = int(notification_id)
    except (TypeError, ValueError):
        return None
    for n in data.get('notifications', []):
        try:
            if int(n.get('id') or 0) == target_id:
                return n
        except (TypeError, ValueError):
            continue
    return None


def add_months(dt, months):
    """按自然月向后推算，保留时分秒；遇到月底自动落到目标月最后一天。"""
    month_index = dt.month - 1 + int(months)
    year = dt.year + month_index // 12
    month = month_index % 12 + 1
    day = min(dt.day, calendar.monthrange(year, month)[1])
    return dt.replace(year=year, month=month, day=day)


def parse_start_datetime(start_time):
    if not start_time:
        return None
    for fmt in ('%Y-%m-%d %H:%M', '%Y-%m-%d %H:%M:%S'):
        try:
            return datetime.strptime(start_time[:16] if fmt.endswith('%H:%M') else start_time, fmt)
        except Exception:
            pass
    return None


def get_month_interval(config):
    try:
        interval = int(config.get('month_interval') or 0)
    except (TypeError, ValueError):
        interval = 0
    return interval if interval in (1, 2, 3, 6) else 1


def next_monthly_push_datetime(start_time, interval_months, now, advance_days=0):
    start_dt = parse_start_datetime(start_time)
    if not start_dt:
        return None
    interval_months = max(1, int(interval_months or 1))
    advance_days = max(0, int(advance_days or 0))
    candidate = start_dt
    # 从开始时间按自然月周期向后推。提醒时间为事件时间减去提前天数。
    guard = 0
    while guard < 240:
        reminder_dt = candidate - timedelta(days=advance_days)
        if reminder_dt > now:
            return reminder_dt
        candidate = add_months(candidate, interval_months)
        guard += 1
    return None


def normalize_notification_payload(payload, existing=None):
    notify_type = payload.get('notify_type', (existing or {}).get('notify_type', 'normal'))
    config_data = payload.get('config', {}) or {}
    config = {}
    if notify_type in ('normal', 'birthday'):
        repeat_mode = config_data.get('repeat_mode', 'once')
        if notify_type == 'birthday':
            repeat_mode = 'yearly'
        start_time = config_data.get('start_time', '')
        week_values = normalize_week_days_values(config_data.get('week_days', []))
        month_day = config_data.get('month_day')
        if repeat_mode == 'monthly' and not month_day and len(start_time) >= 10:
            try:
                month_day = int(start_time[8:10])
            except Exception:
                month_day = None
        try:
            month_interval = int(config_data.get('month_interval') or 1)
        except (TypeError, ValueError):
            month_interval = 1
        if month_interval not in (1, 2, 3, 6):
            month_interval = 1
        config = {
            'repeat_mode': repeat_mode, 'week_days': week_values, 'month_day': month_day,
            'month_interval': month_interval,
            'start_time': start_time, 'is_lunar': 1 if config_data.get('is_lunar', 0) else 0,
            'advance_days': int(config_data.get('advance_days', 0) or 0),
        }
    elif notify_type == 'shift':
        config = {'cycle_days': int(config_data.get('cycle_days', 1) or 1), 'start_date': config_data.get('start_date', ''), 'schedules': config_data.get('schedules', []) or []}
    elif notify_type == 'ping':
        target = normalize_ping_target(config_data.get('target', ''))
        if not target:
            raise ValueError('Ping 目标不能为空')
        old = (existing or {}).get('config') or {}
        config = {'target': target, 'last_is_online': old.get('last_is_online'), 'last_checked_at': old.get('last_checked_at')}
    elif notify_type == 'stock':
        target_url = sanitize_push_url(config_data.get('target_url', ''))
        keyword = (config_data.get('keyword', '') or '').strip()
        if not target_url:
            raise ValueError('库存通知网址不能为空')
        if not keyword:
            raise ValueError('库存通知关键字不能为空')
        old = (existing or {}).get('config') or {}
        config = {'target_url': target_url, 'keyword': keyword, 'last_in_stock': old.get('last_in_stock'), 'last_checked_at': old.get('last_checked_at')}
    return notify_type, config


def prepare_notification_for_api(n):
    item = normalize_notification_record(n)
    item['config'] = dict(item.get('config') or {})
    item['content_with_age'] = item.get('content') or ''
    now = get_local_now()
    if item.get('notify_type') == 'birthday' and item.get('config'):
        try:
            age_text = build_birthday_age_text(item['config'], now.date())
        except Exception:
            age_text = ''
        if age_text:
            base = item.get('content') or ''
            item['content_with_age'] = f'{base}{age_text}' if base else age_text
    try:
        item['next_push'] = calculate_next_push(item, item.get('config'), now)
    except Exception:
        item['next_push'] = None
    return item

def format_push_message(notification_name, content_text, now=None):
    current = now or get_local_now()
    title = (notification_name or '').strip() or '未命名通知'
    content = (content_text or '').strip() or '无'
    return '\n'.join(['通知提醒', f'名称：{title}', f'内容：{content}', f"时间：{current.strftime('%Y-%m-%d %H:%M')}"])


def sanitize_wecom_content(message):
    text = (message or '').strip()
    if not text:
        return ''
    text = re.sub(r'<at\s+userid="[^"]+"\s*></at>', '', text, flags=re.IGNORECASE)
    text = re.sub(r'<at\s+mobile="[^"]+"\s*></at>', '', text, flags=re.IGNORECASE)
    return re.sub(r'\n{3,}', '\n\n', text).strip()

@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
    return response

@app.route("/healthz")
@app.route("/health")
def healthz():
    return jsonify({"status": "ok", "storage": "json"})

@app.route('/')
def index():

    return redirect(url_for('admin' if 'user_id' in session else 'login'))

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/api/login', methods=['POST'])
def api_login():
    payload = request.get_json() or {}
    username = (payload.get('username') or '').strip()
    password = payload.get('password') or ''
    key = f"{get_client_ip()}:{username.lower()}"
    allowed, retry_after = check_rate_limit('login', key)
    if not allowed:
        return jsonify({'success': False, 'message': f'登录失败次数过多，请 {retry_after} 秒后再试'}), 429
    if not username or not password:
        record_rate_limit_failure('login', key)
        return jsonify({'success': False, 'message': '用户名和密码不能为空'})
    data = load_data()
    user = data.get('user') or {}
    if username == user.get('username') and verify_password(password, user.get('password_hash')):
        if needs_password_rehash(user.get('password_hash')):
            user['password_hash'] = hash_password(password)
            save_data(data)
        clear_rate_limit('login', key)
        session.clear()
        session['user_id'] = 1
        session['username'] = user.get('username')
        session['is_admin'] = 1
        session['csrf_token'] = secrets.token_urlsafe(32)
        return jsonify({'success': True})
    record_rate_limit_failure('login', key)
    return jsonify({'success': False, 'message': '用户名或密码错误'})

@app.route('/api/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/api/user/profile', methods=['PUT'])
@login_required
def update_my_profile():
    payload = request.get_json() or {}
    username = (payload.get('username') or '').strip()
    current_password = payload.get('current_password') or ''
    new_password = payload.get('new_password') or ''
    if not username:
        return jsonify({'success': False, 'message': '用户名不能为空'}), 400
    if not current_password:
        return jsonify({'success': False, 'message': '请输入当前密码'}), 400
    if new_password and len(new_password) < Config.MIN_PASSWORD_LENGTH:
        return jsonify({'success': False, 'message': f'新密码至少{Config.MIN_PASSWORD_LENGTH}位'}), 400
    def mutate(data):
        user = data.get('user') or {}
        if not verify_password(current_password, user.get('password_hash')):
            return 'bad_password'
        user['username'] = username
        if new_password:
            user['password_hash'] = hash_password(new_password)
        data['user'] = user
        return 'ok'
    result = update_data(mutate)
    if result == 'bad_password':
        return jsonify({'success': False, 'message': '当前密码错误'}), 400
    session['username'] = username
    broadcast_event('state_update', {'reason': 'profile_updated'})
    return jsonify({'success': True, 'username': username})

@app.route('/register')
def register_page():
    return redirect(url_for('login'))

@app.route('/api/register', methods=['POST'])
def api_register_disabled():
    return jsonify({'success': False, 'message': '单用户 JSON 版已关闭注册'}), 410

@app.route('/admin')
@login_required
def admin():
    return render_template('admin.html')

@app.route('/admin/config')
@login_required
def config_page():
    return render_template('config.html')

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    return redirect(url_for('admin'))

@app.route('/api/admin/stats')
@login_required
def admin_stats():
    data = load_data()
    logs = []
    for log in read_push_logs(50):
        row = dict(log)
        if not row.get('notification_name'):
            n = get_notification_by_id(data, row.get('notification_id'))
            row['notification_name'] = n.get('name') if n else ''
        logs.append(row)
    notifications = data.get('notifications', [])
    return jsonify({
        'total_users': 1,
        'total_notifications': len(notifications),
        'active_notifications': sum(1 for n in notifications if int(n.get('is_active', 0)) == 1),
        'registration_mode': 'closed',
        'invite_codes': [],
        'recent_logs': logs,
    })

@app.route('/api/logs')
@login_required
def api_logs():
    data = load_data()
    logs = []
    for log in read_push_logs(50):
        row = dict(log)
        if not row.get('notification_name'):
            n = get_notification_by_id(data, row.get('notification_id'))
            row['notification_name'] = n.get('name') if n else ''
        logs.append(row)
    return jsonify({'success': True, 'logs': logs, 'retry_queue': data.get('retry_queue', [])})

@app.route('/api/admin/settings', methods=['GET', 'POST'])
@login_required
def admin_settings():
    return jsonify({'success': True, 'registration_mode': 'closed', 'message': '单用户 JSON 版不支持注册设置'})

@app.route('/api/admin/invite_codes', methods=['POST'])
@login_required
def create_invite_codes():
    return jsonify({'success': False, 'message': '单用户 JSON 版已关闭邀请码'}), 410

@app.route('/api/admin/invite_codes/<code>', methods=['DELETE'])
@login_required
def delete_invite_code(code):
    return jsonify({'success': False, 'message': '单用户 JSON 版已关闭邀请码'}), 410

@app.route('/api/admin/users', methods=['GET', 'POST'])
@login_required
def admin_users_disabled():
    return jsonify({'success': True, 'users': [], 'message': '单用户 JSON 版不提供用户列表'})

@app.route('/api/admin/users/<int:user_id>', methods=['PUT', 'DELETE'])
@login_required
def admin_user_item_disabled(user_id):
    return jsonify({'success': False, 'message': '单用户 JSON 版不支持用户管理'}), 410


def calculate_next_push(notification, config, now):
    if not config or not notification.get('is_active'):
        return None
    current_date = now.date()
    notify_type = notification.get('notify_type')
    if notify_type in ('normal', 'birthday'):
        start_time = config.get('start_time', '')
        if not start_time:
            return None
        notify_time = start_time[11:16] if len(start_time) >= 16 else start_time[:5]
        repeat_mode = config.get('repeat_mode', 'once')
        advance_days = int(config.get('advance_days', 0) or 0)
        try:
            notify_time_obj = datetime.strptime(notify_time[:5], '%H:%M').time()
        except Exception:
            notify_time_obj = None
        def candidate_after(event_date):
            start_date = current_date
            if notify_time_obj and datetime.combine(current_date, notify_time_obj) <= now:
                start_date = current_date + timedelta(days=1)
            reminder = event_date - timedelta(days=advance_days)
            if reminder < start_date:
                reminder = start_date
            if reminder <= event_date:
                return f"{reminder.strftime('%Y-%m-%d')} {notify_time}"
            return None
        try:
            if repeat_mode == 'once':
                return candidate_after(datetime.strptime(start_time[:10], '%Y-%m-%d').date())
            if repeat_mode == 'daily':
                d = current_date if not notify_time_obj or datetime.combine(current_date, notify_time_obj) > now else current_date + timedelta(days=1)
                return f"{d.strftime('%Y-%m-%d')} {notify_time}"
            if repeat_mode == 'weekly':
                days = set(normalize_week_days_values(config.get('week_days'))) or set(range(7))
                for i in range(0, 14):
                    d = current_date + timedelta(days=i)
                    # Project convention: Monday=0 ... Sunday=6, matching Python weekday().
                    if d.weekday() in days:
                        hit = candidate_after(d)
                        if hit:
                            return hit
            if repeat_mode == 'monthly':
                next_dt = next_monthly_push_datetime(start_time, get_month_interval(config), now, advance_days)
                return next_dt.strftime('%Y-%m-%d %H:%M') if next_dt else None
            if repeat_mode == 'yearly':
                md = int(config.get('month_day') or 0)
                if not md and len(start_time) >= 10:
                    md = int(start_time[5:7]) * 100 + int(start_time[8:10])
                target_month = md // 100
                target_day = md % 100
                for i in range(0, 370):
                    d = current_date + timedelta(days=i)
                    if d.month == target_month and d.day == target_day:
                        hit = candidate_after(d)
                        if hit:
                            return hit
        except Exception:
            return None
    if notify_type == 'shift':
        start_date_str = config.get('start_date', '')
        try:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
        except Exception:
            return None
        cycle_days = max(1, int(config.get('cycle_days', 1) or 1))
        for i in range(0, cycle_days * 2 + 1):
            d = current_date + timedelta(days=i)
            if d < start_date:
                continue
            day_of_cycle = ((d - start_date).days % cycle_days) + 1
            events = []
            for schedule in config.get('schedules', []):
                if int(schedule.get('day_of_cycle', 1)) != day_of_cycle:
                    continue
                if schedule.get('notify_on_start', 1):
                    events.append((schedule.get('start_time', '07:55'), '上班'))
                if schedule.get('notify_on_end', 1):
                    events.append((schedule.get('end_time', '16:00'), '下班'))
            for raw_time, label in sorted(events):
                try:
                    event_dt = datetime.combine(d, datetime.strptime(raw_time[:5], '%H:%M').time())
                except Exception:
                    continue
                if event_dt > now:
                    return f"{d.strftime('%Y-%m-%d')} {raw_time[:5]} {label}"
    return None


def build_birthday_age_text(config, current_date):
    if not config:
        return ''
    start_time = config.get('start_time') or ''
    try:
        birth_year = int(start_time[:4])
        age = current_date.year - birth_year
        return f'（{age}周岁）' if age >= 0 else ''
    except Exception:
        return ''

@app.route('/api/notifications')
@login_required
def get_notifications():
    data = load_data()
    result = [prepare_notification_for_api(n) for n in sorted(data.get('notifications', []), key=lambda x: str(x.get('created_at', '')), reverse=True)]
    return jsonify(result)

@app.route('/api/notifications', methods=['POST'])
@login_required
def create_notification():
    payload = request.get_json() or {}
    name = (payload.get('name') or '').strip()
    content = payload.get('content', '')
    if not name:
        return jsonify({'success': False, 'message': '通知名称不能为空'}), 400
    try:
        notify_type, config = normalize_notification_payload(payload)
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 400
    def mutate(data):
        nid = int(data.get('next_notification_id', 1))
        ts = now_str()
        data.setdefault('notifications', []).append({
            'id': nid, 'user_id': 1, 'name': name, 'notify_type': notify_type,
            'content': content, 'is_active': int(payload.get('is_active', 1)),
            'created_at': ts, 'updated_at': ts, 'config': config,
        })
        data['next_notification_id'] = nid + 1
        return nid
    nid = update_data(mutate)
    broadcast_event('state_update', {'reason': 'notification_created', 'id': nid})
    return jsonify({'success': True, 'id': nid})

@app.route('/api/notifications/<int:notification_id>', methods=['GET', 'PUT'])
@login_required
def update_notification(notification_id):
    if request.method == 'GET':
        notification = get_notification_by_id(load_data(), notification_id)
        if not notification:
            return jsonify({'success': False, 'message': '通知不存在'}), 404
        return jsonify({'success': True, 'notification': prepare_notification_for_api(notification)})
    payload = request.get_json() or {}
    name = (payload.get('name') or '').strip()
    if not name:
        return jsonify({'success': False, 'message': '通知名称不能为空'}), 400
    current = get_notification_by_id(load_data(), notification_id)
    if not current:
        return jsonify({'success': False, 'message': '通知不存在'}), 404
    try:
        notify_type, config = normalize_notification_payload(payload, current)
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 400
    if current.get('notify_type') == 'shift' and notify_type != 'shift':
        return jsonify({'success': False, 'message': '倒班通知不支持切换为其他类型'}), 400
    if current.get('notify_type') != 'shift' and notify_type == 'shift':
        return jsonify({'success': False, 'message': '普通/生日通知不支持切换为倒班通知'}), 400
    def mutate(data):
        n = get_notification_record_ref(data, notification_id)
        if not n:
            return False
        n.update({
            'name': name, 'notify_type': notify_type, 'content': payload.get('content', ''),
            'is_active': int(payload.get('is_active', 1)), 'updated_at': now_str(), 'config': config,
        })
        return True
    ok = update_data(mutate)
    if ok:
        broadcast_event('state_update', {'reason': 'notification_updated', 'id': notification_id})
    return jsonify({'success': bool(ok), 'message': '' if ok else '通知不存在'})

@app.route('/api/notifications/<int:notification_id>', methods=['DELETE'])
@login_required
def delete_notification(notification_id):
    def mutate(data):
        before = len(data.get('notifications', []))
        data['notifications'] = [n for n in data.get('notifications', []) if int(n.get('id')) != int(notification_id)]
        data['notification_logs'] = [l for l in data.get('notification_logs', []) if int(l.get('notification_id', 0)) != int(notification_id)]
        return len(data['notifications']) < before
    ok = update_data(mutate)
    if ok:
        broadcast_event('state_update', {'reason': 'notification_deleted', 'id': notification_id})
    return jsonify({'success': bool(ok), 'message': '' if ok else '通知不存在'})

@app.route('/api/notifications/<int:notification_id>/toggle-status', methods=['POST'])
@login_required
def toggle_notification_status(notification_id):
    payload = request.get_json() or {}
    is_active = 1 if payload.get('is_active') else 0
    def mutate(data):
        n = get_notification_record_ref(data, notification_id)
        if not n:
            return False
        n['is_active'] = is_active
        n['updated_at'] = now_str()
        return True
    ok = update_data(mutate)
    if ok:
        broadcast_event('state_update', {'reason': 'notification_status_changed', 'id': notification_id})
    return jsonify({'success': bool(ok), 'message': '' if ok else '通知不存在'})

@app.route('/api/notifications/<int:notification_id>/test-notify', methods=['POST'])
@login_required
def test_notification(notification_id):
    """Send one test notification only.

    The edit modal may submit the current form payload here.  In that case the
    test uses the unsaved form values, but it never writes those form values back
    to config.json.  If no payload is supplied, it falls back to the saved item.
    """
    data = load_data()
    saved_notification = get_notification_by_id(data, notification_id)
    if not saved_notification:
        return jsonify({'success': False, 'message': '通知不存在'}), 404

    payload = request.get_json(silent=True) or {}
    if isinstance(payload.get('notification'), dict):
        payload = payload['notification']

    if payload:
        name = (payload.get('name') or '').strip()
        if not name:
            return jsonify({'success': False, 'message': '通知名称不能为空'}), 400
        try:
            notify_type, config = normalize_notification_payload(payload, saved_notification)
        except ValueError as e:
            return jsonify({'success': False, 'message': str(e)}), 400
        notification = dict(saved_notification)
        notification.update({
            'name': name,
            'notify_type': notify_type,
            'content': payload.get('content', ''),
            'config': config,
        })
    else:
        notification = saved_notification

    content = notification.get('content') or ''
    if notification.get('notify_type') == 'birthday':
        age_text = build_birthday_age_text(notification.get('config'), get_local_now().date())
        if age_text:
            content = f'{content}{age_text}' if content else age_text

    message = format_push_message(notification.get('name'), content)
    push_settings = data.get('push_settings') or default_push_settings()
    sent, msg = send_notification(push_settings, message)

    def mutate(d):
        # Test notification should record only this notification's test result.
        add_notification_log(d, notification_id, 'success' if sent else 'failed', message if sent else (msg or message))
        return True

    update_data(mutate)
    broadcast_event('push_status', {
        'notification_id': notification_id,
        'status': 'test_success' if sent else 'test_failed',
        'message': '当前通知测试推送成功' if sent else (msg or '当前通知测试推送失败')
    })
    broadcast_event('state_update', {'reason': 'test_notification', 'id': notification_id})
    return jsonify({'success': sent, 'message': '当前通知测试推送成功' if sent else (msg or '当前通知测试推送失败')})


def normalize_push_settings_payload(payload):
    sanitized = default_push_settings()
    sanitized.update(payload or {})
    for field in ['wecom_webhook', 'telegram_api_url', 'xizhi_url', 'pushplus_url', 'custom_webhook1_url', 'custom_webhook2_url']:
        sanitized[field] = sanitize_push_url(sanitized.get(field, ''))
    sanitized['telegram_api_url'] = sanitized.get('telegram_api_url') or 'https://api.telegram.org'
    sanitized['pushplus_url'] = sanitized.get('pushplus_url') or 'https://www.pushplus.plus/send'
    for field in ['wecom_enabled','telegram_enabled','xizhi_enabled','pushplus_enabled','custom_webhook1_enabled','custom_webhook2_enabled']:
        sanitized[field] = 1 if sanitized.get(field) else 0
    return sanitized


def force_single_push_channel(settings, channel):
    channel_map = {
        'wecom': 'wecom_enabled',
        'telegram': 'telegram_enabled',
        'xizhi': 'xizhi_enabled',
        'pushplus': 'pushplus_enabled',
        'webhook1': 'custom_webhook1_enabled',
        'webhook2': 'custom_webhook2_enabled',
    }
    if channel not in channel_map:
        return None
    isolated = dict(settings)
    for field in channel_map.values():
        isolated[field] = 0
    isolated[channel_map[channel]] = 1
    return isolated

@app.route('/api/push-settings', methods=['GET', 'POST'])
@login_required
def get_push_settings():
    if request.method == 'GET':
        return jsonify(load_data().get('push_settings') or default_push_settings())
    payload = request.get_json() or {}
    sanitized = normalize_push_settings_payload(payload)
    ok, msg = validate_push_urls(sanitized)
    if not ok:
        return jsonify({'success': False, 'message': msg}), 400
    def mutate(data):
        data['push_settings'] = sanitized
    update_data(mutate)
    broadcast_event('state_update', {'reason': 'push_settings_updated'})
    return jsonify({'success': True})

@app.route('/api/push-settings/test', methods=['POST'])
@login_required
def test_push_settings():
    payload = request.get_json() or {}
    channel = (payload.get('channel') or '').strip()
    settings = normalize_push_settings_payload(payload if payload else (load_data().get('push_settings') or {}))
    if channel:
        isolated = force_single_push_channel(settings, channel)
        if isolated is None:
            return jsonify({'success': False, 'message': '未知推送渠道'}), 400
        settings = isolated
    ok, msg = validate_push_urls(settings)
    if not ok:
        return jsonify({'success': False, 'message': msg}), 400
    sent, message = send_notification(settings, format_push_message('测试通知', '这是一条测试通知'))
    if sent:
        broadcast_event('push_status', {'status': 'success', 'message': '测试推送成功'})
    return jsonify({'success': sent, 'message': '测试推送成功' if sent else message})


def get_system_setting(key, default=None):
    return load_data().get('system_settings', {}).get(key, default)

def send_notification(push_settings, message):
    if not push_settings:
        return False, '推送设置未配置'
    success = True
    errors = []
    enabled_channels = 0
    attempted_requests = 0
    def mark_error(msg):
        nonlocal success
        success = False
        errors.append(msg)
    if push_settings.get('wecom_enabled'):
        enabled_channels += 1
        url = sanitize_push_url(push_settings.get('wecom_webhook', ''))
        if not url:
            mark_error('企业微信未配置 Webhook')
        else:
            safe, safe_msg = is_safe_outbound_url(url)
            if not safe:
                mark_error(f'企业微信 Webhook 不合法: {safe_msg}')
            else:
                try:
                    content = sanitize_wecom_content(message)
                    mobiles, users = [], []
                    for m in (push_settings.get('wecom_mentions') or '').split(','):
                        raw = m.strip()
                        if not raw:
                            continue
                        matched = re.match(r'^<at\s+userid="([^"]+)"\s*></at>$', raw, flags=re.IGNORECASE)
                        if matched:
                            raw = matched.group(1).strip()
                        raw = raw[1:] if raw.startswith('@') else raw
                        mobile = raw.replace('-', '').replace(' ', '')
                        if mobile.isdigit() and len(mobile) >= 6:
                            if mobile not in mobiles: mobiles.append(mobile)
                        elif raw and raw not in users:
                            users.append(raw)
                    attempted_requests += 1
                    resp = requests.post(url, json={'msgtype':'text','text':{'content':content,'mentioned_list':users,'mentioned_mobile_list':mobiles}}, timeout=10)
                    if resp.status_code != 200:
                        mark_error(f'企业微信响应错误: {resp.status_code}')
                except Exception as e:
                    mark_error(f'企业微信请求失败: {e}')
    if push_settings.get('telegram_enabled'):
        enabled_channels += 1
        api = sanitize_push_url(push_settings.get('telegram_api_url', 'https://api.telegram.org')) or 'https://api.telegram.org'
        token = push_settings.get('telegram_bot_token') or ''
        chat_id = push_settings.get('telegram_chat_id') or ''
        if not token or not chat_id:
            mark_error('Telegram 未配置 Bot Token 或 Chat ID')
        else:
            safe, safe_msg = is_safe_outbound_url(api)
            if not safe:
                mark_error(f'Telegram API 地址不合法: {safe_msg}')
            else:
                try:
                    attempted_requests += 1
                    resp = requests.post(f'{api}/bot{token}/sendMessage', json={'chat_id': chat_id, 'text': message}, timeout=10)
                    if resp.status_code != 200:
                        mark_error(f'Telegram响应错误: {resp.status_code}')
                except Exception as e:
                    mark_error(f'Telegram请求失败: {e}')
    if push_settings.get('xizhi_enabled'):
        enabled_channels += 1
        url = sanitize_push_url(push_settings.get('xizhi_url', ''))
        if not url:
            mark_error('息知未配置推送URL')
        else:
            safe, safe_msg = is_safe_outbound_url(url)
            if not safe:
                mark_error(f'息知 URL 不合法: {safe_msg}')
            else:
                try:
                    attempted_requests += 1
                    resp = requests.post(url, json={'title':'通知推送系统','content':message}, timeout=10)
                    if resp.status_code != 200:
                        mark_error(f'息知响应错误: {resp.status_code}')
                except Exception as e:
                    mark_error(f'息知请求失败: {e}')
    if push_settings.get('pushplus_enabled'):
        enabled_channels += 1
        url = sanitize_push_url(push_settings.get('pushplus_url', 'https://www.pushplus.plus/send')) or 'https://www.pushplus.plus/send'
        token = push_settings.get('pushplus_token') or ''
        template = push_settings.get('pushplus_template') or 'markdown'
        if not token:
            mark_error('PushPlus 未配置 Token')
        else:
            safe, safe_msg = is_safe_outbound_url(url)
            if not safe:
                mark_error(f'PushPlus URL 不合法: {safe_msg}')
            else:
                try:
                    attempted_requests += 1
                    resp = requests.post(url, json={'token':token,'title':'通知推送系统','content':message,'template':template}, timeout=10)
                    if resp.status_code != 200:
                        mark_error(f'PushPlus响应错误: {resp.status_code}')
                except Exception as e:
                    mark_error(f'PushPlus请求失败: {e}')
    for i in [1, 2]:
        if not push_settings.get(f'custom_webhook{i}_enabled'):
            continue
        enabled_channels += 1
        url = sanitize_push_url(push_settings.get(f'custom_webhook{i}_url', ''))
        method = (push_settings.get(f'custom_webhook{i}_method') or 'POST').upper()
        headers_str = push_settings.get(f'custom_webhook{i}_headers') or ''
        body = push_settings.get(f'custom_webhook{i}_body') or ''
        if not url:
            mark_error(f'Webhook{i} 未配置地址')
            continue
        safe, safe_msg = is_safe_outbound_url(url)
        if not safe:
            mark_error(f'Webhook{i} 地址不合法: {safe_msg}')
            continue
        try:
            headers = {}
            if headers_str.strip().startswith('{'):
                try:
                    headers = {str(k): str(v) for k, v in json.loads(headers_str).items()}
                except Exception:
                    headers = {}
            else:
                for line in headers_str.split('\n'):
                    if ':' in line:
                        k, v = line.split(':', 1)
                        headers[k.strip()] = v.strip()
            attempted_requests += 1
            if method == 'GET':
                resp = requests.get(url, headers=headers, timeout=10)
            else:
                kwargs = {'headers': headers, 'timeout': 10}
                if body.strip():
                    if 'application/json' in (headers.get('Content-Type', '') + headers.get('content-type', '')).lower():
                        try: kwargs['json'] = json.loads(body)
                        except Exception: kwargs['data'] = body
                    else:
                        kwargs['data'] = body
                resp = requests.request(method, url, **kwargs)
            if resp.status_code not in (200, 201, 202, 204):
                mark_error(f'Webhook{i}响应错误: {resp.status_code}')
        except Exception as e:
            mark_error(f'Webhook{i}请求失败: {e}')
    if enabled_channels == 0:
        return False, '所有推送渠道均未启用'
    if attempted_requests == 0:
        return False, '已启用渠道未发送请求，请检查配置'
    if not success:
        return False, '；'.join(errors)
    return True, ''


def check_ping_target_online(target):
    value = normalize_ping_target(target)
    if not value:
        return False, '目标不能为空'
    if value.startswith(('http://','https://')):
        safe, msg = is_safe_outbound_url(value)
        if not safe: return False, msg
        try:
            resp = requests.get(value, timeout=5)
            return resp.status_code < 500, ''
        except Exception as e:
            return False, str(e)
    if '/' in value:
        return False, 'IP或域名格式不合法'
    host = value
    ports = [80, 443]
    if ':' in value:
        host_part, port_part = value.rsplit(':', 1)
        if port_part.isdigit():
            host, ports = host_part, [int(port_part)]
    host = host.strip('[]')
    if not is_public_host_or_ip(host):
        return False, '仅支持公网 IP 或域名'
    last_error = '连接失败'
    for port in ports:
        try:
            with socket.create_connection((host, port), timeout=3):
                return True, ''
        except Exception as e:
            last_error = str(e)
    return False, last_error


def check_stock_keyword_absent(target_url, keyword):
    url = sanitize_push_url(target_url)
    if not url: return None, '地址不能为空'
    if not keyword: return None, '关键字不能为空'
    safe, msg = is_safe_outbound_url(url)
    if not safe: return None, msg
    try:
        resp = requests.get(url, timeout=8)
        return (keyword not in (resp.text or '')), ''
    except Exception as e:
        return None, str(e)


def check_and_send_notifications():
    now = get_local_now().replace(second=0, microsecond=0)
    current_minute_key = now.strftime('%Y-%m-%d %H:%M')
    current_time = now.strftime('%H:%M')
    current_date = now.date()
    changed = {'sent': 0}
    def mutate(data):
        for notification in data.get('notifications', []):
            if not notification.get('is_active') or notification.get('notify_type') in ('ping','stock'):
                continue
            config = notification.get('config') or {}
            ntype = notification.get('notify_type')
            event_key = None
            if ntype in ('normal','birthday'):
                start_time = config.get('start_time', '')
                repeat_mode = config.get('repeat_mode', 'once')
                notify_time = start_time[11:16] if len(start_time) >= 16 else start_time[:5]
                if notify_time == current_time:
                    if repeat_mode == 'once' and start_time[:10] == current_date.strftime('%Y-%m-%d'):
                        event_key = f'{current_minute_key}:once'
                    elif repeat_mode == 'daily':
                        event_key = f'{current_minute_key}:daily'
                    elif repeat_mode == 'weekly':
                        days = set(normalize_week_days_values(config.get('week_days')))
                        if current_date.weekday() in days:
                            event_key = f'{current_minute_key}:weekly'
                    elif repeat_mode == 'monthly':
                        start_dt = parse_start_datetime(start_time)
                        if start_dt:
                            interval_months = get_month_interval(config)
                            advance_days = int(config.get('advance_days', 0) or 0)
                            candidate = start_dt
                            for _ in range(240):
                                reminder_dt = candidate - timedelta(days=advance_days)
                                if reminder_dt.strftime('%Y-%m-%d %H:%M') == current_minute_key:
                                    event_key = f'{current_minute_key}:monthly:{interval_months}'
                                    break
                                if reminder_dt > now:
                                    break
                                candidate = add_months(candidate, interval_months)
                    elif repeat_mode == 'yearly':
                        md = int(config.get('month_day') or 0)
                        if current_date.month == md // 100 and current_date.day == md % 100:
                            event_key = f'{current_minute_key}:yearly'
            elif ntype == 'shift':
                try:
                    start_date = datetime.strptime(config.get('start_date', ''), '%Y-%m-%d').date()
                    cycle_days = max(1, int(config.get('cycle_days', 1) or 1))
                    if current_date >= start_date:
                        day_of_cycle = ((current_date - start_date).days % cycle_days) + 1
                        hits = []
                        for schedule in config.get('schedules', []):
                            if int(schedule.get('day_of_cycle', 1)) != day_of_cycle:
                                continue
                            if schedule.get('notify_on_start', 1) and schedule.get('start_time', '')[:5] == current_time:
                                hits.append('start')
                            if schedule.get('notify_on_end', 1) and schedule.get('end_time', '')[:5] == current_time:
                                hits.append('end')
                        if hits:
                            event_key = f"{current_minute_key}:shift:{'-'.join(hits)}"
                except Exception:
                    event_key = None
            if not event_key:
                continue
            if notification.get('last_sent_event_key') == event_key:
                continue
            notification['last_sent_event_key'] = event_key
            content = notification.get('content') or ''
            if ntype == 'birthday':
                age_text = build_birthday_age_text(config, current_date)
                if age_text: content = f'{content}{age_text}' if content else age_text
            message = format_push_message(notification.get('name'), content, now)
            send_notification_with_retry(data, notification, message, source='scheduled')
            notification['updated_at'] = now_str()
            changed['sent'] += 1
    update_data(mutate)
    if changed['sent']:
        broadcast_event('state_update', {'reason': 'scheduled_push', 'count': changed['sent']})
    return changed['sent']


def check_realtime_notifications():
    now = get_local_now()
    changed = {'sent': 0, 'checked': 0}
    def mutate(data):
        for notification in data.get('notifications', []):
            if not notification.get('is_active') or notification.get('notify_type') not in ('ping','stock'):
                continue
            config = notification.get('config') or {}
            changed['checked'] += 1
            if notification.get('notify_type') == 'ping':
                target = config.get('target', '')
                is_online, err = check_ping_target_online(target)
                previous = config.get('last_is_online')
                should_send = (previous is not None and int(previous) == 0 and is_online) or (not is_online and (previous is None or int(previous) == 1))
                config['last_is_online'] = 1 if is_online else 0
                config['last_checked_at'] = now_str()
                config['last_error'] = err or ''
                if should_send:
                    status = '已上线' if is_online else '已下线'
                    text = f"Ping 状态提醒\n目标：{target}\n状态：{status}"
                    if notification.get('content'):
                        text += f"\n备注：{notification.get('content')}"
                    message = format_push_message(notification.get('name'), text, now)
                    send_notification_with_retry(data, notification, message, source='realtime')
                    notification['updated_at'] = now_str()
                    changed['sent'] += 1
            elif notification.get('notify_type') == 'stock':
                target_url, keyword = config.get('target_url',''), (config.get('keyword') or '').strip()
                keyword_absent, err = check_stock_keyword_absent(target_url, keyword)
                config['last_checked_at'] = now_str()
                config['last_error'] = err or ''
                if keyword_absent is None:
                    continue
                current_state = 1 if keyword_absent else 0
                previous = config.get('last_in_stock')
                changed_state = previous is None or int(previous) != current_state
                config['last_in_stock'] = current_state
                if changed_state:
                    status = '有货' if keyword_absent else '缺货'
                    text = f"库存提醒\n地址：{target_url}\n状态：{status}"
                    if notification.get('content'):
                        text += f"\n备注：{notification.get('content')}"
                    message = format_push_message(notification.get('name'), text, now)
                    send_notification_with_retry(data, notification, message, source='realtime')
                    notification['updated_at'] = now_str()
                    changed['sent'] += 1
    update_data(mutate)
    if changed['sent'] or changed['checked']:
        broadcast_event('state_update', {'reason': 'realtime_check', 'sent': changed['sent'], 'checked': changed['checked']})
    return changed

_scheduler_lock = threading.Lock()
_scheduler_started = False
_scheduler = None


def start_background_scheduler():
    global _scheduler_started, _scheduler
    with _scheduler_lock:
        if _scheduler_started:
            return
        _scheduler_started = True
        _scheduler = BackgroundScheduler(timezone='Asia/Shanghai')
        _scheduler.add_job(check_and_send_notifications, CronTrigger(second=0), id='minute_notifications', max_instances=1, coalesce=True, misfire_grace_time=30, replace_existing=True)
        _scheduler.add_job(check_realtime_notifications, IntervalTrigger(seconds=10), id='realtime_notifications', max_instances=1, coalesce=True, misfire_grace_time=20, replace_existing=True)
        _scheduler.add_job(process_retry_queue, IntervalTrigger(seconds=20), id='push_retry_queue', max_instances=1, coalesce=True, misfire_grace_time=60, replace_existing=True)
        _scheduler.start()
        print('后台调度器已启动：分钟级任务按整分钟执行，实时检测10秒一次，重试队列20秒一次。')

init_db()
if __name__ != '__main__' and os.environ.get('START_SCHEDULER', '0') == '1':
    start_background_scheduler()

if __name__ == '__main__':
    start_background_scheduler()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', '5000')), debug=False)
