bind = "127.0.0.1:8000"
workers = 1
threads = 2
worker_class = "gthread"
timeout = 30
graceful_timeout = 15
keepalive = 5
accesslog = "-"
errorlog = "-"
loglevel = "info"
preload_app = False

