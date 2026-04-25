import copy
import hashlib
import json
import os
import re
import tempfile
import threading
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config

PUSHPLUS_DEFAULT_URL = 'https://www.pushplus.plus/send'
_LEGACY_SHA256_RE = re.compile(r'^[a-f0-9]{64}$')
_store_lock = threading.RLock()


def now_str():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def ensure_data_dir():
    os.makedirs(Config.DATA_DIR, exist_ok=True)
    os.makedirs(Config.LOG_DIR, exist_ok=True)
    if not os.access(Config.DATA_DIR, os.W_OK):
        raise PermissionError(f'数据目录不可写: {Config.DATA_DIR}')
    try:
        os.chmod(Config.DATA_DIR, 0o750)
    except OSError:
        pass


def default_push_settings():
    return {
        'wecom_enabled': 0,
        'wecom_webhook': '',
        'wecom_mentions': '',
        'telegram_enabled': 0,
        'telegram_api_url': 'https://api.telegram.org',
        'telegram_bot_token': '',
        'telegram_chat_id': '',
        'xizhi_enabled': 0,
        'xizhi_url': '',
        'pushplus_enabled': 0,
        'pushplus_url': PUSHPLUS_DEFAULT_URL,
        'pushplus_token': '',
        'pushplus_template': 'markdown',
        'custom_webhook1_enabled': 0,
        'custom_webhook1_url': '',
        'custom_webhook1_method': 'POST',
        'custom_webhook1_headers': '',
        'custom_webhook1_body': '',
        'custom_webhook2_enabled': 0,
        'custom_webhook2_url': '',
        'custom_webhook2_method': 'POST',
        'custom_webhook2_headers': '',
        'custom_webhook2_body': '',
    }


def default_data():
    ts = now_str()
    return {
        'version': 3,
        'next_notification_id': 1,
        'next_log_id': 1,
        'user': {
            'id': 1,
            'username': Config.ADMIN_DEFAULT_USERNAME,
            'password_hash': hash_password(Config.ADMIN_DEFAULT_PASSWORD),
            'is_admin': 1,
            'created_at': ts,
        },
        'push_settings': default_push_settings(),
        'notifications': [],
        'notification_logs': [],
        'retry_queue': [],
        'runtime': {},
        'system_settings': {'registration_mode': 'closed'},
    }



def _safe_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default



def normalize_week_days_values(value):
    """Normalize weekly repeat values to UI/backend convention: Monday=0 ... Sunday=6.

    Accepts old JSON strings, comma separated strings, Chinese weekday names, lists,
    tuples, sets and dicts.  Invalid values are ignored instead of breaking the
    edit modal or scheduler.
    """
    if value in (None, ''):
        return []
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return []
        try:
            parsed = json.loads(raw)
            return normalize_week_days_values(parsed)
        except Exception:
            parts = re.split(r'[,，\s]+', raw)
            value = [p for p in parts if p]
    if isinstance(value, dict):
        value = [k for k, v in value.items() if v]
    if not isinstance(value, (list, tuple, set)):
        value = [value]
    zh_map = {
        '周一': 0, '星期一': 0, '一': 0, 'mon': 0, 'monday': 0,
        '周二': 1, '星期二': 1, '二': 1, 'tue': 1, 'tuesday': 1,
        '周三': 2, '星期三': 2, '三': 2, 'wed': 2, 'wednesday': 2,
        '周四': 3, '星期四': 3, '四': 3, 'thu': 3, 'thursday': 3,
        '周五': 4, '星期五': 4, '五': 4, 'fri': 4, 'friday': 4,
        '周六': 5, '星期六': 5, '六': 5, 'sat': 5, 'saturday': 5,
        '周日': 6, '星期日': 6, '星期天': 6, '日': 6, '天': 6, 'sun': 6, 'sunday': 6,
    }
    result = []
    for item in value:
        if item is None:
            continue
        if isinstance(item, bool):
            continue
        if isinstance(item, str):
            key = item.strip().lower()
            if key in zh_map:
                day = zh_map[key]
            else:
                try:
                    day = int(float(key))
                except Exception:
                    continue
        else:
            try:
                day = int(item)
            except Exception:
                continue
        # Current project convention is 0-6 = Monday-Sunday.  Also accept 7 as Sunday.
        if day == 7:
            day = 6
        if 0 <= day <= 6 and day not in result:
            result.append(day)
    return sorted(result)


def normalize_notification_record(raw, fallback_id=None):
    """Normalize old/new notification records so every API response is editable.

    Older config.json files may contain mixed schemas from previous versions.  The
    frontend edit modal expects a stable shape, so storage is migrated here at
    load time instead of letting missing fields break individual dialogs.
    """
    if not isinstance(raw, dict):
        raw = {}
    ts = now_str()
    item = dict(raw)
    item['id'] = _safe_int(item.get('id'), fallback_id or 0)
    item['user_id'] = 1
    item['name'] = str(item.get('name') or item.get('title') or '未命名通知')
    notify_type = item.get('notify_type') or item.get('type') or 'normal'
    if notify_type not in ('normal', 'birthday', 'shift', 'ping', 'stock'):
        notify_type = 'normal'
    item['notify_type'] = notify_type
    item['content'] = str(item.get('content') or item.get('message') or '')
    item['is_active'] = 1 if str(item.get('is_active', 1)).lower() not in ('0', 'false', 'none') else 0
    item['created_at'] = item.get('created_at') or ts
    item['updated_at'] = item.get('updated_at') or item['created_at']
    config = item.get('config') if isinstance(item.get('config'), dict) else {}

    if notify_type in ('normal', 'birthday'):
        repeat_mode = config.get('repeat_mode') or item.get('repeat_mode') or ('yearly' if notify_type == 'birthday' else 'once')
        if notify_type == 'birthday':
            repeat_mode = 'yearly'
        if repeat_mode not in ('once', 'daily', 'weekly', 'monthly', 'yearly'):
            repeat_mode = 'once'
        start_time = config.get('start_time') or item.get('start_time') or item.get('time') or ''
        week_days = normalize_week_days_values(config.get('week_days', item.get('week_days', [])))
        month_day = config.get('month_day')
        if month_day in ('', None) and isinstance(start_time, str) and len(start_time) >= 10:
            try:
                if repeat_mode == 'yearly':
                    month_day = int(start_time[5:7]) * 100 + int(start_time[8:10])
                else:
                    month_day = int(start_time[8:10])
            except Exception:
                month_day = None
        month_interval = _safe_int(config.get('month_interval'), 1)
        if month_interval not in (1, 2, 3, 6):
            month_interval = 1
        config = {
            'repeat_mode': repeat_mode,
            'week_days': week_days,
            'month_day': month_day,
            'month_interval': month_interval,
            'start_time': str(start_time or ''),
            'is_lunar': 1 if str(config.get('is_lunar', 0)).lower() in ('1', 'true') else 0,
            'advance_days': _safe_int(config.get('advance_days'), 0),
        }
    elif notify_type == 'shift':
        schedules = config.get('schedules', [])
        if not isinstance(schedules, list):
            schedules = []
        normalized_schedules = []
        for idx, s in enumerate(schedules):
            if not isinstance(s, dict):
                s = {}
            normalized_schedules.append({
                'day_of_cycle': _safe_int(s.get('day_of_cycle'), idx + 1),
                'shift_type': s.get('shift_type') or 'day',
                'start_time': s.get('start_time') or ('07:55' if (s.get('shift_type') == 'night') else '08:00'),
                'end_time': s.get('end_time') or '17:00',
                'notify_on_start': 1 if str(s.get('notify_on_start', 1)).lower() not in ('0', 'false') else 0,
                'notify_on_end': 1 if str(s.get('notify_on_end', 1)).lower() not in ('0', 'false') else 0,
            })
        config = {
            'cycle_days': max(1, _safe_int(config.get('cycle_days'), 1)),
            'start_date': str(config.get('start_date') or ''),
            'schedules': normalized_schedules,
        }
    elif notify_type == 'ping':
        config = {
            'target': str(config.get('target') or ''),
            'last_is_online': config.get('last_is_online'),
            'last_checked_at': config.get('last_checked_at'),
        }
    elif notify_type == 'stock':
        config = {
            'target_url': str(config.get('target_url') or ''),
            'keyword': str(config.get('keyword') or ''),
            'last_in_stock': config.get('last_in_stock'),
            'last_checked_at': config.get('last_checked_at'),
        }
    item['config'] = config
    return item


def normalize_data(data):
    changed = False
    if not isinstance(data, dict):
        data = default_data()
        changed = True
    data.setdefault('version', 2)
    data.setdefault('next_notification_id', 1)
    data.setdefault('next_log_id', 1)
    data.setdefault('notifications', [])
    data.setdefault('notification_logs', [])
    data.setdefault('retry_queue', [])
    data.setdefault('runtime', {})
    data.setdefault('system_settings', {'registration_mode': 'closed'})
    data['system_settings']['registration_mode'] = 'closed'
    if 'user' not in data or not isinstance(data['user'], dict):
        data['user'] = default_data()['user']
        changed = True
    data['user']['id'] = 1
    data['user']['is_admin'] = 1
    data['user'].setdefault('username', Config.ADMIN_DEFAULT_USERNAME)
    if not data['user'].get('password_hash'):
        data['user']['password_hash'] = hash_password(Config.ADMIN_DEFAULT_PASSWORD)
        changed = True
    push = default_push_settings()
    push.update(data.get('push_settings') or {})
    data['push_settings'] = push
    max_id = 0
    normalized_notifications = []
    used_ids = set()
    next_candidate_id = 1
    for n in data['notifications']:
        normalized = normalize_notification_record(n, next_candidate_id)
        if normalized['id'] <= 0 or normalized['id'] in used_ids:
            while next_candidate_id in used_ids:
                next_candidate_id += 1
            normalized['id'] = next_candidate_id
        used_ids.add(normalized['id'])
        max_id = max(max_id, normalized['id'])
        next_candidate_id = max(next_candidate_id, normalized['id'] + 1)
        normalized_notifications.append(normalized)
    if normalized_notifications != data.get('notifications', []):
        changed = True
    data['notifications'] = normalized_notifications
    data['next_notification_id'] = max(_safe_int(data.get('next_notification_id'), 1), max_id + 1)
    data['notification_logs'] = sorted(data.get('notification_logs', []), key=lambda x: int(x.get('id', 0) or 0), reverse=True)[:50]
    if not isinstance(data.get('retry_queue'), list):
        data['retry_queue'] = []
        changed = True
    data['retry_queue'] = data['retry_queue'][:100]
    if not isinstance(data.get('runtime'), dict):
        data['runtime'] = {}
        changed = True
    max_log_id = 0
    for log in data['notification_logs']:
        max_log_id = max(max_log_id, int(log.get('id', 0) or 0))
    data['next_log_id'] = max(int(data.get('next_log_id', 1) or 1), max_log_id + 1)
    return data, changed


def read_data_unlocked():
    ensure_data_dir()
    if not os.path.exists(Config.DATA_FILE):
        data = default_data()
        write_data_unlocked(data)
        return data
    try:
        with open(Config.DATA_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception:
        backup = Config.DATA_FILE + '.' + datetime.now().strftime('%Y%m%d%H%M%S') + '.broken'
        try:
            os.replace(Config.DATA_FILE, backup)
        except Exception:
            pass
        data = default_data()
        write_data_unlocked(data)
        return data
    data, changed = normalize_data(data)
    if changed:
        write_data_unlocked(data)
    return data


def write_data_unlocked(data):
    ensure_data_dir()
    fd, tmp = tempfile.mkstemp(prefix='.config-', suffix='.json', dir=Config.DATA_DIR)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.write('\n')
        os.replace(tmp, Config.DATA_FILE)
        try:
            os.chmod(Config.DATA_FILE, 0o600)
        except OSError:
            pass
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)



def get_push_logger():
    ensure_data_dir()
    logger = logging.getLogger('worker.push')
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if not logger.handlers:
        handler = RotatingFileHandler(Config.PUSH_LOG_FILE, maxBytes=Config.PUSH_LOG_MAX_BYTES, backupCount=Config.PUSH_LOG_BACKUP_COUNT, encoding='utf-8')
        handler.setFormatter(logging.Formatter('%(message)s'))
        logger.addHandler(handler)
    return logger


def append_push_log(log_item):
    item = dict(log_item or {})
    item.setdefault('pushed_at', now_str())
    try:
        get_push_logger().info(json.dumps(item, ensure_ascii=False, separators=(',', ':')))
    except Exception:
        pass


def read_push_logs(limit=50):
    ensure_data_dir()
    paths = [Config.PUSH_LOG_FILE] + [f'{Config.PUSH_LOG_FILE}.{i}' for i in range(1, Config.PUSH_LOG_BACKUP_COUNT + 1)]
    rows = []
    for path in paths:
        if not os.path.exists(path):
            continue
        try:
            with open(path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rows.append(json.loads(line))
                    except Exception:
                        continue
        except Exception:
            continue
    rows.sort(key=lambda x: (str(x.get('pushed_at', '')), int(x.get('id', 0) or 0)), reverse=True)
    return rows[:int(limit or 50)]
def load_data():
    with _store_lock:
        return copy.deepcopy(read_data_unlocked())


def save_data(data):
    with _store_lock:
        normalized, _ = normalize_data(data)
        write_data_unlocked(normalized)
        return copy.deepcopy(normalized)


def update_data(mutator):
    with _store_lock:
        data = read_data_unlocked()
        result = mutator(data)
        normalized, _ = normalize_data(data)
        write_data_unlocked(normalized)
        return result


def init_db():
    # 保留函数名以兼容原入口；实际为 JSON 初始化，不再创建 SQLite。
    with _store_lock:
        data = read_data_unlocked()
        write_data_unlocked(data)



def hash_password(password):
    return generate_password_hash(password, method='pbkdf2:sha256:260000')


def is_legacy_password_hash(password_hash):
    if not isinstance(password_hash, str):
        return False
    return bool(_LEGACY_SHA256_RE.fullmatch(password_hash))


def verify_password(password, password_hash):
    if not password_hash:
        return False
    if is_legacy_password_hash(password_hash):
        legacy_hash = hashlib.sha256((password + Config.PASSWORD_SALT).encode()).hexdigest()
        return legacy_hash == password_hash
    try:
        return check_password_hash(password_hash, password)
    except Exception:
        return False


def needs_password_rehash(password_hash):
    return is_legacy_password_hash(password_hash)
