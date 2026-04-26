# Worker

一个轻量级通知推送系统，支持普通提醒、生日提醒、排班提醒、Ping 监控和库存关键字监控。使用 JSON 文件保存配置，无需数据库，适合个人长期部署使用。

## 功能特点

- JSON 存储，无需 SQLite/MySQL
- 配置热更新，修改后无需重启
- WebSocket 实时状态更新，前端无刷新刷新列表和日志
- 推送失败重试机制
- 推送日志滚动保存，避免日志无限增长
- 通知列表在手机端采用卡片式展示，保留通知名称、下次推送和操作项
- 添加/编辑通知弹窗已适配手机全屏视口，底部保存按钮始终可见
- Docker / Docker Compose 一键部署
- 编辑通知数据兼容旧版本，避免旧通知弹窗打不开

## 默认账号

```text
admin / 12345678
```

首次登录后建议立即修改账号密码。

## 数据目录

```text
./data/config.json
```

该文件保存：

- 用户账号密码
- 通知任务
- 推送渠道配置
- 推送日志索引
- 重试队列

请自行备份 `data/` 目录内的数据。

## 安装方式一：Docker Compose（推荐）

在服务器创建 `docker-compose.yml`：

```yaml
services:
  worker:
    image: auto8624/worker:latest
    container_name: worker
    restart: always

    ports:
      - "5000:5000"

    volumes:
      - ./data:/app/data

    environment:
      - TZ=Asia/Shanghai

    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:5000/health"]
      interval: 30s
      timeout: 5s
      retries: 3

    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
```

启动：

```bash
docker compose up -d
```

旧版 Docker Compose 也可以使用：

```bash
docker-compose up -d
```

## 安装方式二：Docker 单命令运行

```bash
mkdir -p data
docker run -d \
  --name worker \
  -p 5000:5000 \
  -v $(pwd)/data:/app/data \
  --restart always \
  auto8624/worker:latest
```

## 安装方式三：源码运行

```bash
git clone https://github.com/auto8624/worker1.git
cd worker1
pip install -r requirements.txt
python run.py
```

访问：

```text
http://服务器IP:5000
```

## 更新方式

Docker Compose：

```bash
docker compose pull
docker compose up -d
```

Docker 单命令：

```bash
docker pull auto8624/worker:latest
docker rm -f worker
docker run -d \
  --name worker \
  -p 5000:5000 \
  -v $(pwd)/data:/app/data \
  --restart always \
  auto8624/worker:latest
```

## 项目结构

```text
.
├── app.py                  # Web 路由、通知逻辑、实时状态、定时任务
├── models.py               # JSON 数据读写、数据迁移、日志滚动
├── config.py               # 基础配置
├── run.py                  # 启动入口
├── requirements.txt        # Python 依赖
├── Dockerfile              # Docker 镜像构建文件
├── docker-compose.yml      # 本地 compose 部署配置
├── docker-entrypoint.sh    # 容器启动脚本
├── templates/
│   ├── admin.html          # 主业务页面
│   ├── config.html         # 推送设置页面
│   └── login.html          # 登录页面
├── static/
│   └── css/app.css         # 前端样式
└── data/                   # 运行数据目录
    └── config.json
```


## 常见问题

