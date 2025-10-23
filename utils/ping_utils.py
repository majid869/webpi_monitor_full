# utils/ping_utils.py

import subprocess
import socket
import requests
import shlex

def parse_host_port(host_str, default_port=80):
    """
    جدا کردن هاست و پورت از ورودی.
    مثال: "192.168.1.55:1935" -> ("192.168.1.55", 1935)
    """
    if ":" in host_str:
        host, port = host_str.split(":", 1)
        try:
            port = int(port)
        except:
            port = default_port
    else:
        host = host_str
        port = default_port
    return host, port

def ping_host(host, timeout_s=2):
    """پینگ ساده"""
    if not host:
        return False
    try:
        proc = subprocess.run(
            ["/bin/ping", "-c", "1", "-W", str(timeout_s), host],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout_s+1
        )
        return proc.returncode == 0
    except:
        return False

def check_tcp(host_str, timeout=2):
    host, port = parse_host_port(host_str, 80)
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except:
        return False

def check_udp(host_str, timeout=2):
    host, port = parse_host_port(host_str, 53)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(b"ping", (host, port))
        s.recvfrom(1024)
        s.close()
        return True
    except:
        return False

def check_http(host_str, https=False, timeout=5):
    host, port = parse_host_port(host_str, 443 if https else 80)
    try:
        url = f"{'https' if https else 'http'}://{host}:{port}"
        r = requests.get(url, timeout=timeout)
        return r.status_code < 400
    except:
        return False

import subprocess, shlex

def check_rtmp_stream(url: str, timeout=5) -> bool:
    """
    بررسی واقعی استریم RTMP با ffprobe.
    url مثال: rtmp://192.168.1.55/live/dv1
    """
    try:
        cmd = f"ffprobe -v error -show_streams -select_streams v:0 {url}"
        result = subprocess.run(shlex.split(cmd), capture_output=True, text=True, timeout=timeout)
        output = result.stdout.strip()
        return bool(output)  # اگر جریان ویدئو پیدا شد True
    except subprocess.TimeoutExpired:
        return False
    except Exception:
        return False
