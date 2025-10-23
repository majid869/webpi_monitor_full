from functools import wraps
from flask import session, redirect, url_for, abort

# دکوراتور برای ورود کاربران
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


# دکوراتور مخصوص ادمین
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        if session.get("role") != "admin":
            abort(403)  # دسترسی غیرمجاز
        return f(*args, **kwargs)
    return decorated_function
