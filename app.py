#!/usr/bin/env python3
import os, json, time, threading, uuid, hashlib, binascii
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, abort
from functools import wraps
from utils.ping_utils import ping_host, check_tcp, check_udp,check_rtmp_stream , check_http
from utils.sms_gsm import send_sms_gsm
from utils.auth_utils import login_required, admin_required
from datetime import datetime, timezone

APP_DIR = os.path.dirname(__file__)
DATA_FILE = os.path.join(APP_DIR, "data", "data.json")
USERS_FILE = os.path.join(APP_DIR, "data", "users.json")
CONFIG_FILE = os.path.join(APP_DIR, "config.py")

# load config
GSM_PORT = "/dev/ttyUSB0"
SECRET_KEY = "change_me"
if os.path.exists(CONFIG_FILE):
    spec = {}
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        exec(f.read(), spec)
    GSM_PORT = spec.get("GSM_PORT", GSM_PORT)
    SECRET_KEY = spec.get("SECRET_KEY", SECRET_KEY)

app = Flask(__name__)
app.secret_key = SECRET_KEY

# --- password hash check ---
def check_password_hash(stored_hash, password):
    try:
        parts = stored_hash.split('$')
        meta = parts[0]
        iterations = int(meta.split(':')[-1])
        salt = parts[1]
        hexd = parts[2]
        dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), iterations)
        return binascii.hexlify(dk).decode() == hexd
    except:
        return False

# --- users ---
def load_users():
    if os.path.exists(USERS_FILE):
        return json.load(open(USERS_FILE, "r", encoding="utf-8"))
    return {"users": []}

def find_user(username):
    for u in load_users().get("users", []):
        if u.get("username") == username:
            return u
    return None

# --- auth decorators ---
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if session.get("role") != "admin":
            return abort(403)
        return f(*args, **kwargs)
    return wrapper

# --- data storage ---
data_lock = threading.Lock()
def load_data():
    if os.path.exists(DATA_FILE):
        return json.load(open(DATA_FILE, "r", encoding="utf-8"))
    return {"targets": {}}

def save_data(d):
    tmp = DATA_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(d, f, indent=2, ensure_ascii=False)
    os.replace(tmp, DATA_FILE)

data = load_data()

# --- pinger thread ---
stop_event = threading.Event()
def make_id():
    return uuid.uuid4().hex[:12]

def pinger_loop():
    global data
    while not stop_event.is_set():
        with data_lock:
            targets = dict(data.get("targets", {}))
        for tid, t in targets.items():
            interval = max(1, int(t.get("interval", 10)))
            next_run = t.get("next_run", 0)
            if time.time() >= next_run:
                host = t.get("host")
                protocol = t.get("protocol","ping")
              
		# پروتکل‌ها
                if protocol == "ping":
                        ok = ping_host(host)
                elif protocol == "http":
                        ok = check_http(host, https=False)
                elif protocol == "https":
                        ok = check_http(host, https=True)
                elif protocol == "tcp":
                        ok = check_tcp(host)
                elif protocol == "udp":
                        ok = check_udp(host)
                elif protocol == "rtmp":
                        ok = check_rtmp_stream(host)
                else:
                        ok = False

                                
                ts = datetime.now(timezone.utc).isoformat(timespec='seconds').replace("+00:00","Z")
                t["last_status"] = bool(ok)
                t["last_checked"] = ts
                t["next_run"] = time.time() + interval

                # SMS logic
                sms = t.get("sms") or {}
                sms_enabled = sms.get("enabled", False)
                sms_to = sms.get("to")
                notify_on_recovery = sms.get("notify_on_recovery", False)
                reminder = sms.get("reminder_minutes", 0)
                prev_notified = t.get("notified", False)
                last_sms_ts = t.get("last_sms_ts", 0)

                if not ok:
                    if sms_enabled and (not prev_notified) and sms_to:
                        body = f"[WebPi] هشدار: {host} قطع شد\nزمان: {ts}"
                        sent = send_sms_gsm(GSM_PORT, sms_to, body)
                        if sent: t["notified"]=True; t["last_sms_ts"]=time.time()
                    elif sms_enabled and prev_notified and reminder and (time.time()-last_sms_ts)>=(reminder*60):
                        body = f"[WebPi] یادآوری: {host} هنوز قطع است\nزمان: {ts}"
                        sent = send_sms_gsm(GSM_PORT, sms_to, body)
                        if sent: t["last_sms_ts"]=time.time()
                else:
                    if prev_notified:
                        if sms_enabled and notify_on_recovery and sms_to:
                            body = f"[WebPi] اطلاع: {host} دوباره آنلاین شد\nزمان: {ts}"
                            send_sms_gsm(GSM_PORT, sms_to, body)
                        t["notified"]=False
                        t["last_sms_ts"]=0

        save_data(data)
        stop_event.wait(1)

t = threading.Thread(target=pinger_loop, daemon=True)
t.start()

# --- routes ---
@app.route("/")
def root(): return redirect(url_for("login"))

@app.route('/favicon.ico')
def favicon():
    # پاسخ خالی، یعنی "هیچی برای نمایش نیست" ولی بدون خطا
    return ('', 204)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        u = find_user(username)
        if u and check_password_hash(u.get("password_hash", ""), password):
            session["logged_in"] = True
            session["username"] = username
            session["role"] = u.get("role", "viewer")
            return redirect(url_for("monitor"))
        flash("نام کاربری یا رمز عبور اشتباه است.", "danger")
        return render_template("login.html"), 401
    return render_template("login.html")

@app.route("/api/users/change_password", methods=["POST"])
@admin_required
def api_user_change_password():
    data_req = request.get_json() or {}
    username = data_req.get("username")
    new_password = data_req.get("new_password")

    if not username or not new_password:
        return jsonify({"error": "username و new_password لازم است"}), 400

    users_data = load_users()
    found = False
    for u in users_data["users"]:
        if u["username"] == username:
            import hashlib, binascii, os
            iterations = 260000
            salt = binascii.hexlify(os.urandom(16)).decode()
            dk = hashlib.pbkdf2_hmac('sha256', new_password.encode(), salt.encode(), iterations)
            u["password_hash"] = f"pbkdf2:sha256:{iterations}${salt}${binascii.hexlify(dk).decode()}"
            found = True
            break
    if not found:
        return jsonify({"error":"کاربر یافت نشد"}), 404

    with open(USERS_FILE,"w",encoding="utf-8") as f:
        json.dump(users_data,f,indent=2,ensure_ascii=False)
    return jsonify({"ok": True})

@app.route("/logout")
def logout():
    session.clear()
    flash("خروج انجام شد.","info")
    return redirect(url_for("login"))

@app.route("/monitor")
def monitor(): return render_template("monitor.html")

@app.route("/monitortv")
def monitortv(): return render_template("monitor_tv.html")

@app.route("/manage")
@login_required
@admin_required
def manage(): return render_template("manage.html")

@app.route("/check_now")
@login_required
def check_now():
    tid = request.args.get("id")
    if not tid:
        return jsonify({"ok": False, "error": "no target id"}), 400

    with data_lock:
        t = data.get("targets", {}).get(tid)
        if not t:
            return jsonify({"ok": False, "error": "target not found"}), 404
        host_str = t.get("host")
        protocol = t.get("protocol", "ping")

    try:
        if protocol == "ping": ok = ping_host(host_str)
        elif protocol == "http": ok = check_http(host_str, https=False)
        elif protocol == "https": ok = check_http(host_str, https=True)
        elif protocol == "tcp": ok = check_tcp(host_str)
        elif protocol == "udp": ok = check_udp(host_str)
        elif protocol == "rtmp": ok = check_rtmp_stream(host_str)
        else: ok = False
    except:
        ok = False

    # update last_checked
    with data_lock:
        ts = datetime.now(timezone.utc).isoformat(timespec='seconds').replace("+00:00","Z")
        t["last_status"] = bool(ok)
        t["last_checked"] = ts
        save_data(data)

    return jsonify({"ok": ok})


@app.route("/profile")
@login_required
def profile(): return render_template("profile.html")

# API endpoints
@app.route("/api/status")
def api_status():
    with data_lock:
        lst = [{**t, "id":tid} for tid,t in data.get("targets",{}).items()]
    return jsonify({"targets": lst})

@app.route("/api/targets", methods=["POST"])
@login_required
@admin_required
def api_add_target():
    payload = request.get_json() or {}
    host = payload.get("host","").strip()
    protocol = payload.get("protocol","ping")
    try: interval=int(payload.get("interval",10))
    except: interval=10
    sms = payload.get("sms")
    if not host: return jsonify({"error":"host required"}),400
    tid = make_id()
    now = time.time()
    with data_lock:
        data.setdefault("targets", {})[tid] = {
            "host": host, "protocol": protocol, "interval": max(1, interval),
            "last_status": False, "last_checked": None, "next_run": now+0.5,
            "sms": sms or {"enabled": False}, "notified": False, "last_sms_ts":0
        }
        save_data(data)
    return jsonify({"id":tid}),201

@app.route("/api/targets/<tid>", methods=["DELETE","PUT"])
@login_required
@admin_required
def api_modify_target(tid):
    with data_lock:
        if tid not in data.get("targets",{}): return jsonify({"error":"not found"}),404
        if request.method=="DELETE":
            del data["targets"][tid]
            save_data(data)
            return jsonify({"ok":True})
        payload = request.get_json() or {}
        if "host" in payload: data["targets"][tid]["host"]=payload["host"]
        if "protocol" in payload: data["targets"][tid]["protocol"]=payload["protocol"]
        if "interval" in payload:
            try: data["targets"][tid]["interval"]=max(1,int(payload["interval"]))
            except: pass
        if "sms" in payload: data["targets"][tid]["sms"]=payload["sms"]
        save_data(data)
    return jsonify({"ok":True})
    
@app.route("/api/change_password", methods=["POST"])
@login_required
def api_change_password():
    data_req = request.get_json() or {}
    old = data_req.get("old","")
    new = data_req.get("new","")

    # پیدا کردن کاربر
    u = find_user(session["username"])
    if not u or not check_password_hash(u["password_hash"], old):
        return jsonify({"error":"رمز فعلی اشتباه است"}),400

    # ایجاد هش جدید
    import hashlib, binascii, os
    iterations = 260000
    salt = binascii.hexlify(os.urandom(16)).decode()
    dk = hashlib.pbkdf2_hmac('sha256', new.encode(), salt.encode(), iterations)
    u["password_hash"] = f"pbkdf2:sha256:{iterations}${salt}${binascii.hexlify(dk).decode()}"

    # ذخیره در فایل users.json
    all_users = load_users()
    for idx,user in enumerate(all_users["users"]):
        if user["username"]==u["username"]:
            all_users["users"][idx]=u
            break
    with open(USERS_FILE,"w",encoding="utf-8") as f:
        json.dump(all_users,f,indent=2,ensure_ascii=False)

    return jsonify({"ok":True})

@app.route("/users")
@admin_required
def users_page():
    return render_template("users.html")

@app.route("/api/users")
@admin_required
def api_users():
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    return jsonify(data["users"])

@app.route("/api/users/add", methods=["POST"])
@admin_required
def api_user_add():
    info = request.json
    username = info.get("username")
    password = info.get("password")
    role = info.get("role", "user")

    from werkzeug.security import generate_password_hash
    with open(USERS_FILE, "r+", encoding="utf-8") as f:
        data = json.load(f)
        if any(u["username"] == username for u in data["users"]):
            return jsonify({"error": "exists"}), 400
        data["users"].append({
            "username": username,
            "password_hash": generate_password_hash(password),
            "role": role
        })
        f.seek(0)
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.truncate()
    return jsonify({"ok": True})

@app.route("/api/users/delete", methods=["POST"])
@admin_required
def api_user_delete():
    username = request.json.get("username")
    with open(USERS_FILE, "r+", encoding="utf-8") as f:
        data = json.load(f)
        data["users"] = [u for u in data["users"] if u["username"] != username]
        f.seek(0)
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.truncate()
    return jsonify({"ok": True})

@app.route("/api/meta")
@login_required
def api_meta():
    with data_lock:
        return jsonify({"modem": data.get("meta", {}).get("modem", {})})

# graceful shutdown
def shutdown():
    stop_event.set()
    t.join(timeout=2)

if __name__=="__main__":
    try:
        app.run(host="0.0.0.0", port=80)
    finally:
        shutdown()
