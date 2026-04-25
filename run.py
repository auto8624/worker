#!/usr/bin/env python3
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, init_db, start_background_scheduler
from config import Config

if __name__ == '__main__':
    init_db()
    start_background_scheduler()
    print('=' * 50)
    print('通知推送系统 JSON 单用户版已启动')
    print('=' * 50)
    print('登录地址: http://localhost:5000/login')
    print(f'首次默认账号: {Config.ADMIN_DEFAULT_USERNAME} / {Config.ADMIN_DEFAULT_PASSWORD}')
    print('登录后请到“推送设置 / 账号设置”修改账号密码。')
    print('=' * 50)
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', '5000')), debug=False)
