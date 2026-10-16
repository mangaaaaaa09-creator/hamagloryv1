import os, sys, json, uuid, threading, subprocess, functools
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template, session, redirect
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
import requests as req_lib

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

USERS_FILE = os.path.join(DATA_DIR, "users.json")
JOBS_FILE  = os.path.join(DATA_DIR, "jobs.json")
ACCOUNTS_FILE = os.path.join(BASE_DIR, "accounts.json")

INVITE_API = "https://apijoinclan.up.railway.app/clan"
BOT_COUNT  = 4          
BOT_PREFIX = "hello__"  

app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(32)
if not os.environ.get("SECRET_KEY"):
    print("WARNING: SECRET_KEY is not set; sessions will reset when the server restarts.")

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
)

CORS(app, supports_credentials=True, origins=[])

def _load(path, default):
    if not os.path.exists(path): return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default

def _save(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)

def load_users(): return _load(USERS_FILE, {})
def save_users(u): _save(USERS_FILE, u)
def load_jobs():  return _load(JOBS_FILE, {})
def save_jobs(j): _save(JOBS_FILE, j)
def current_user():
    uid = session.get("user_id")
    if not uid: return None
    for u in load_users().values():
        if u.get("id") == uid:
            return u
    return None

def require_login(fn):
    @functools.wraps(fn)
    def wrapper(*a, **kw):
        if not current_user():
            if request.path.startswith("/api/"):
                return jsonify({"error": "unauthorized"}), 401
            return redirect("/login")
        return fn(*a, **kw)
    return wrapper

@app.route("/")
def page_index():
    return redirect("/dashboard" if current_user() else "/login")

@app.route("/login")
def page_login():
    if current_user():
        return redirect("/dashboard")
    return render_template("login.html")

@app.route("/dashboard")
@require_login
def page_dashboard():
    return render_template("dashboard.html")

@app.route("/api/register", methods=["POST"])
def api_register():
    d = request.get_json(force=True) or {}
    username = (d.get("username") or "").strip().lower()
    password = (d.get("password") or "").strip()
    if not username or not password:
        return jsonify({"error": "username and password required"}), 400
    if len(username) < 3 or len(password) < 6:
        return jsonify({"error": "username>=3, password>=6"}), 400
    users = load_users()
    if username in users:
        return jsonify({"error": "username already exists"}), 409
    user_id = str(uuid.uuid4())
    users[username] = {
        "id": user_id,
        "username": username,
        "password": generate_password_hash(password),
        "created_at": datetime.utcnow().isoformat(),
    }
    save_users(users)
    session.permanent = True
    session["user_id"] = user_id
    session["username"] = username
    return jsonify({"ok": True, "user_id": user_id, "username": username})

@app.route("/api/login", methods=["POST"])
def api_login():
    d = request.get_json(force=True) or {}
    username = (d.get("username") or "").strip().lower()
    password = (d.get("password") or "").strip()
    u = load_users().get(username)
    if not u:
        return jsonify({"error": "invalid credentials"}), 401
    stored = u.get("password", "")
    valid = False
    try:
        valid = check_password_hash(stored, password)
    except (ValueError, TypeError):
        valid = False
    # Backward compatibility: upgrade older plaintext password records on login.
    if not valid and stored == password:
        valid = True
        users = load_users()
        users[username]["password"] = generate_password_hash(password)
        save_users(users)
    if not valid:
        return jsonify({"error": "invalid credentials"}), 401
    session.permanent = True
    session["user_id"] = u["id"]
    session["username"] = username
    return jsonify({"ok": True, "username": username})

@app.route("/api/change-password", methods=["POST"])
@require_login
def api_change_password():
    d = request.get_json(force=True) or {}
    current = str(d.get("current_password") or "")
    new_password = str(d.get("new_password") or "")
    confirm = str(d.get("confirm_password") or "")
    if len(new_password) < 6:
        return jsonify({"error": "كلمة المرور الجديدة يجب أن تكون 6 أحرف على الأقل"}), 400
    if new_password != confirm:
        return jsonify({"error": "تأكيد كلمة المرور غير مطابق"}), 400
    username = session.get("username", "")
    users = load_users()
    user = users.get(username)
    if not user:
        session.clear()
        return jsonify({"error": "الحساب غير موجود، سجل الدخول من جديد"}), 401
    stored = user.get("password", "")
    try:
        valid = check_password_hash(stored, current)
    except (ValueError, TypeError):
        valid = False
    if not valid and stored == current:
        valid = True
    if not valid:
        return jsonify({"error": "كلمة المرور الحالية غير صحيحة"}), 403
    user["password"] = generate_password_hash(new_password)
    users[username] = user
    save_users(users)
    return jsonify({"ok": True, "message": "تم تغيير كلمة المرور بنجاح"})

@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"ok": True})

@app.route("/api/me")
def api_me():
    u = current_user()
    if not u:
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"username": u["username"], "id": u["id"]})

JOBS_LOCK = threading.Lock()
PROCESSES = {}   # job_id -> {"gen": Popen|None}
ACTIVE_USERS = set()
ACTIVE_USERS_LOCK = threading.Lock()

def _append_log(job_id, line):
    with JOBS_LOCK:
        jobs = load_jobs()
        if job_id in jobs:
            logs = jobs[job_id].setdefault("logs", [])
            logs.append({"t": datetime.utcnow().isoformat(), "m": line})
            if len(logs) > 500: logs[:] = logs[-500:]
            save_jobs(jobs)

def _job_update(job_id, **kw):
    with JOBS_LOCK:
        jobs = load_jobs()
        if job_id in jobs:
            jobs[job_id].update(kw)
            jobs[job_id]["updated_at"] = datetime.utcnow().isoformat()
            save_jobs(jobs)

def _set_bot_status(job_id, uid, status):
    with JOBS_LOCK:
        jobs = load_jobs()
        j = jobs.get(job_id)
        if not j: return
        for b in j.get("bots", []):
            if str(b.get("uid")) == str(uid):
                b["status"] = status
        save_jobs(jobs)

def _read_new_accounts(prev_set):
    if not os.path.exists(ACCOUNTS_FILE):
        return []
    try:
        with open(ACCOUNTS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return []
    out = []
    for acc in data:
        if not isinstance(acc, dict): continue
        if not acc.get("name", "").startswith(BOT_PREFIX): continue
        key = (acc.get("uid"), acc.get("password"))
        if key not in prev_set:
            out.append(acc)
    return out

def _invite_bot_to_clan(uid, pw, clan_id, timeout=20):
    try:
        r = req_lib.get(
            INVITE_API,
            params={"uid": uid, "password": pw, "clan_id": clan_id},
            timeout=timeout,
        )
        body = r.text[:300]
        return (r.status_code == 200), body
    except Exception as e:
        return False, str(e)

def _run_gen_subprocess(job, region, count):
    """يشغّل gen.py في subprocess منفصل مع ENV لمنع input()"""
    script = f'''
import sys, os
sys.path.insert(0, r"{BASE_DIR}")
os.chdir(r"{BASE_DIR}")
import gen
gen.run_generation(region="{region}", prefix="{BOT_PREFIX}", count={count})
'''
    path = os.path.join(DATA_DIR, f"gen_runner_{job['id']}.py")
    with open(path, "w", encoding="utf-8") as f:
        f.write(script)
    return subprocess.Popen(
        [sys.executable, "-u", path],
        cwd=BASE_DIR,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1,
    )

def _run_one_shot_job(job_id, username):
    try:
        with JOBS_LOCK:
            job = load_jobs().get(job_id)
            if not job: return
            if job.get("done"):
                _append_log(job_id, "⚠️ Job منتهي مسبقاً، تجاهل")
                return

        region  = job.get("region", "ME")
        clan_id = job.get("clan_id")
        prev = set()
        if os.path.exists(ACCOUNTS_FILE):
            try:
                with open(ACCOUNTS_FILE, "r", encoding="utf-8") as f:
                    for a in json.load(f):
                        prev.add((a.get("uid"), a.get("password")))
            except Exception:
                pass
        _append_log(job_id, f"📸 snapshot: {len(prev)} حساب موجود مسبقاً")

        _job_update(job_id, status="running", stage="generating")
        _append_log(job_id, f"⚡ إنشاء {BOT_COUNT} توكنات | Region={region}")
        proc = _run_gen_subprocess(job, region, BOT_COUNT)
        PROCESSES.setdefault(job_id, {})["gen"] = proc

        if proc.stdout:
            for line in proc.stdout:
                line = line.rstrip()
                if not line: continue
                _append_log(job_id, f"[GEN] {line}")
        proc.wait()

        if proc.returncode != 0:
            _job_update(job_id, status="stopped", stage="gen_failed", done=True)
            _append_log(job_id, f"❌ gen.py فشل (code={proc.returncode})")
            return

        new_accs = _read_new_accounts(prev)
        if not new_accs:
            _job_update(job_id, status="stopped", stage="no_accounts", done=True)
            _append_log(job_id, "❌ لم يتم إنشاء أي حساب جديد")
            return

        new_accs = new_accs[:BOT_COUNT]
        _append_log(job_id, f"✅ تم إنشاء {len(new_accs)} توكنات (الحد الأقصى {BOT_COUNT})")

        # سجّل البوتات في الـ Job
        with JOBS_LOCK:
            jobs = load_jobs()
            j = jobs[job_id]
            j["bots"] = []
            for a in new_accs:
                j["bots"].append({
                    "uid": a.get("uid"),
                    "password": a.get("password"),
                    "account_id": a.get("account_id"),
                    "name": a.get("name"),
                    "status": "idle",
                })
            save_jobs(jobs)

        _job_update(job_id, stage="inviting")
        _append_log(job_id, f"📨 إرسال {len(new_accs)} دعوات إلى الكلان {clan_id} ...")
        ok_count = 0
        for a in new_accs:
            uid = a.get("uid"); pw = a.get("password")
            ok, msg = _invite_bot_to_clan(uid, pw, clan_id)
            status = "in_clan" if ok else "invite_failed"
            _set_bot_status(job_id, uid, status)
            if ok: ok_count += 1
            _append_log(job_id,
                f"📨 uid={uid} → {'✅ OK' if ok else '❌ FAIL: ' + msg[:120]}")

        _append_log(job_id, f"✅ اكتملت العملية: {ok_count}/{len(new_accs)} دعوات ناجحة")
        _job_update(job_id,
                    status="stopped",
                    stage="done",
                    done=True)
        _append_log(job_id, "🏁 انتهى — لن يتم إنشاء أي حساب جديد لهذا الـ Job")

    except Exception as e:
        _append_log(job_id, f"❌ استثناء: {e}")
        _job_update(job_id, status="stopped", stage="error", done=True)
    finally:
        PROCESSES.pop(job_id, None)
        # ⭐ حرّر المستخدم من قائمة النشطين
        with ACTIVE_USERS_LOCK:
            ACTIVE_USERS.discard(username)

@app.route("/api/jobs", methods=["GET"])
@require_login
def api_jobs_list():
    u = current_user()
    jobs = [j for j in load_jobs().values() if j.get("user") == u["username"]]
    jobs.sort(key=lambda j: j.get("created_at", ""), reverse=True)
    return jsonify(jobs)

@app.route("/api/jobs", methods=["POST"])
@require_login
def api_jobs_create():
    u = current_user()
    username = u["username"]
    d = request.get_json(force=True) or {}
    clan_id = str(d.get("clan_id") or "").strip()
    region  = str(d.get("region") or "ME").strip().upper()

    if not clan_id.isdigit():
        return jsonify({"error": "clan_id must be numeric"}), 400

    with ACTIVE_USERS_LOCK:
        if username in ACTIVE_USERS:
            return jsonify({
                "error": "لديك Job قيد التنفيذ حالياً. انتظر انتهاءه أو احذفه."
            }), 409

    with JOBS_LOCK:
        jobs = load_jobs()
        for existing in jobs.values():
            if existing.get("user") != username: continue
            if str(existing.get("clan_id")) != clan_id: continue
            # إذا كان هناك Job لنفس الكلان → ارفض
            return jsonify({
                "error": f"يوجد بالفعل Job للكلان {clan_id}. احذفه أولاً إذا أردت إنشاء جديد."
            }), 409

        job_id = str(uuid.uuid4())[:8]
        job = {
            "id": job_id,
            "user": username,
            "clan_id": clan_id,
            "region": region,
            "status": "starting",
            "stage": "queued",
            "bots": [],
            "logs": [],
            "done": False,
            "created_at": datetime.utcnow().isoformat(),
        }
        jobs[job_id] = job
        save_jobs(jobs)

    # سجّل المستخدم كنشط
    with ACTIVE_USERS_LOCK:
        ACTIVE_USERS.add(username)

    # شغّل Job في thread منفصل (تنفيذ مرة واحدة فقط)
    threading.Thread(
        target=_run_one_shot_job,
        args=(job_id, username),
        daemon=True,
    ).start()

    return jsonify({"ok": True, "job": job})

@app.route("/api/jobs/<job_id>", methods=["GET"])
@require_login
def api_jobs_get(job_id):
    u = current_user()
    j = load_jobs().get(job_id)
    if not j or j.get("user") != u["username"]:
        return jsonify({"error": "not found"}), 404
    return jsonify(j)

@app.route("/api/jobs/<job_id>/start", methods=["POST"])
@require_login
def api_jobs_start(job_id):
    u = current_user()
    with JOBS_LOCK:
        jobs = load_jobs()
        j = jobs.get(job_id)
        if not j or j.get("user") != u["username"]:
            return jsonify({"error": "not found"}), 404
        if j.get("status") in ("running", "starting", "stopping"):
            return jsonify({"error": "هذا المشروع يعمل بالفعل"}), 409
        j.update(status="starting", stage="queued", done=False, bots=[], logs=[])
        j["created_at"] = datetime.utcnow().isoformat()
        save_jobs(jobs)
    with ACTIVE_USERS_LOCK:
        if u["username"] in ACTIVE_USERS:
            return jsonify({"error": "لديك عملية أخرى قيد التنفيذ"}), 409
        ACTIVE_USERS.add(u["username"])
    threading.Thread(target=_run_one_shot_job, args=(job_id, u["username"]), daemon=True).start()
    return jsonify({"ok": True, "job": j})

@app.route("/api/jobs/<job_id>/stop", methods=["POST"])
@require_login
def api_jobs_stop(job_id):
    u = current_user()
    j = load_jobs().get(job_id)
    if not j or j.get("user") != u["username"]:
        return jsonify({"error": "not found"}), 404

    procs = PROCESSES.get(job_id, {})
    for key, p in procs.items():
        if p and p.poll() is None:
            try: p.terminate()
            except Exception: pass
    _job_update(job_id, status="stopping", stage="stopping", done=True)
    _append_log(job_id, "🛑 طلب إيقاف يدوي")

    with ACTIVE_USERS_LOCK:
        ACTIVE_USERS.discard(u["username"])

    return jsonify({"ok": True})

@app.route("/api/jobs/<job_id>", methods=["DELETE"])
@require_login
def api_jobs_delete(job_id):
    u = current_user()
    with JOBS_LOCK:
        jobs = load_jobs()
        j = jobs.get(job_id)
        if not j or j.get("user") != u["username"]:
            return jsonify({"error": "not found"}), 404
        procs = PROCESSES.get(job_id, {})
        for key, p in procs.items():
            if p and p.poll() is None:
                try: p.terminate()
                except Exception: pass
        del jobs[job_id]
        save_jobs(jobs)
    PROCESSES.pop(job_id, None)

    with ACTIVE_USERS_LOCK:
        ACTIVE_USERS.discard(u["username"])

    return jsonify({"ok": True})

@app.route("/api/jobs/<job_id>/edit", methods=["POST"])
@require_login
def api_jobs_edit(job_id):
    """يعرض معلومات البوتات + السجل"""
    u = current_user()
    j = load_jobs().get(job_id)
    if not j or j.get("user") != u["username"]:
        return jsonify({"error": "not found"}), 404
    return jsonify({
        "ok": True,
        "job_id": job_id,
        "clan_id": j.get("clan_id"),
        "region": j.get("region"),
        "status": j.get("status"),
        "stage": j.get("stage"),
        "done":   j.get("done", False),
        "bots":   j.get("bots", []),
        "logs":   j.get("logs", [])[-80:],
    })

@app.route("/api/health")
def api_health():
    return jsonify({"ok": True, "time": datetime.utcnow().isoformat()})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f" FFGlory running on http://0.0.0.0:{port}")
    print(f"BOT_COUNT={BOT_COUNT}  PREFIX={BOT_PREFIX}")
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
