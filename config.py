import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
DATA_FILE = os.path.join(DATA_DIR, 'config.json')
SECRET_KEY_FILE = os.path.join(DATA_DIR, 'secret.key')
LOG_DIR = os.path.join(DATA_DIR, 'logs')
PUSH_LOG_FILE = os.path.join(LOG_DIR, 'push.log')


def ensure_data_dir():
    os.makedirs(DATA_DIR, exist_ok=True)


def load_or_create_secret():
    ensure_data_dir()
    if os.path.exists(SECRET_KEY_FILE):
        with open(SECRET_KEY_FILE, 'r', encoding='utf-8') as f:
            value = f.read().strip()
            if value:
                return value
    value = os.urandom(32).hex()
    with open(SECRET_KEY_FILE, 'w', encoding='utf-8') as f:
        f.write(value)
    try:
        os.chmod(SECRET_KEY_FILE, 0o600)
    except OSError:
        pass
    return value


class Config:
    DATA_DIR = DATA_DIR
    DATA_FILE = DATA_FILE
    SECRET_KEY_FILE = SECRET_KEY_FILE
    LOG_DIR = LOG_DIR
    PUSH_LOG_FILE = PUSH_LOG_FILE
    PUSH_LOG_MAX_BYTES = 1024 * 1024
    PUSH_LOG_BACKUP_COUNT = 3
    SECRET_KEY = load_or_create_secret()
    PASSWORD_SALT = 'notify-salt'
    ADMIN_DEFAULT_USERNAME = 'admin'
    ADMIN_DEFAULT_PASSWORD = '12345678'
    MIN_PASSWORD_LENGTH = 8
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_SECURE = False
    MAX_CONTENT_LENGTH = 1024 * 1024
