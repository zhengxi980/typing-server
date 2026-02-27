"""
타자 연습 서버 API (v26 — 보안 강화)
- 회원가입/로그인/계정 관리
- 랭킹 등록/조회/삭제
- Railway + PostgreSQL 용

보안 기능:
- CORS 도메인 제한 (xixityping.com만)
- API Rate Limiting (IP 기반)
- 로그인 실패 잠금 (5회/15분)
- 세션 토큰 만료 (30일)
- 랭킹 입력값 교차 검증
"""

import os
import re
import time
import hashlib
import secrets
import datetime
import threading
from collections import defaultdict
from functools import wraps

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import psycopg2
import psycopg2.extras

# ============================================================
# Flask 앱 설정
# ============================================================
app = Flask(__name__, static_folder="static", static_url_path="/static")

# ── 보안 #1: CORS 도메인 제한 ──
# PC 앱(urllib)은 Origin 헤더 없음 → CORS 무관
# 브라우저만 Origin 체크 대상 → xixityping.com만 허용
ALLOWED_ORIGINS = [
    "https://xixityping.com",
    "https://www.xixityping.com",
    "http://localhost:5000",       # 로컬 개발용
    "http://127.0.0.1:5000",
]
CORS(app, origins=ALLOWED_ORIGINS)

# Railway가 자동으로 제공하는 DATABASE_URL 환경변수 사용
DATABASE_URL = os.environ.get("DATABASE_URL", "")

ADMIN_ID = "zhengxi980"

# ── 보안 #2: 세션 토큰 유효 기간 (30일) ──
SESSION_MAX_AGE_DAYS = 30

# ── 보안 #3: 랭킹 입력값 상한선 ──
MAX_CPM = 2000         # 분당 글자수 상한 (세계 기록급 ~800)
MAX_KPM = 3000         # 분당 타수 상한
MAX_ACC = 100.0        # 정확도 상한
MAX_ELAPSED = 86400.0  # 최대 경과 시간 (24시간)
MAX_CHARS = 100000     # 최대 글자수

# ── 보안 #4: 로그인 실패 잠금 ──
LOGIN_MAX_ATTEMPTS = 5       # 최대 시도 횟수
LOGIN_LOCKOUT_SECONDS = 900  # 잠금 시간 (15분)

# ── 보안 #5: Rate Limiting ──
# {IP: [(timestamp, ...), ...]}
_rate_store = defaultdict(list)
_rate_lock = threading.Lock()


def _rate_limit(ip, max_calls, window_seconds):
    """IP 기반 호출 횟수 제한. 초과 시 True 반환."""
    now = time.time()
    cutoff = now - window_seconds
    with _rate_lock:
        calls = _rate_store[ip]
        # 오래된 기록 정리
        _rate_store[ip] = [t for t in calls if t > cutoff]
        if len(_rate_store[ip]) >= max_calls:
            return True
        _rate_store[ip].append(now)
    return False


def rate_limit(max_calls=30, window=60):
    """데코레이터: 엔드포인트별 Rate Limiting."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown")
            ip = ip.split(",")[0].strip()
            key = f"{ip}:{f.__name__}"
            if _rate_limit(key, max_calls, window):
                return jsonify({
                    "ok": False,
                    "msg": "요청이 너무 많습니다. 잠시 후 다시 시도해 주세요.",
                    "msg_code": "svr_rate_limited"
                }), 429
            return f(*args, **kwargs)
        return wrapper
    return decorator


# ── 로그인 실패 추적 ──
_login_failures = defaultdict(list)  # {IP: [timestamp, ...]}
_login_lock = threading.Lock()


def _check_login_lockout(ip):
    """로그인 잠금 상태 확인. 잠금이면 True."""
    now = time.time()
    cutoff = now - LOGIN_LOCKOUT_SECONDS
    with _login_lock:
        attempts = _login_failures[ip]
        _login_failures[ip] = [t for t in attempts if t > cutoff]
        return len(_login_failures[ip]) >= LOGIN_MAX_ATTEMPTS


def _record_login_failure(ip):
    """로그인 실패 기록."""
    with _login_lock:
        _login_failures[ip].append(time.time())


def _clear_login_failures(ip):
    """로그인 성공 시 실패 기록 초기화."""
    with _login_lock:
        _login_failures.pop(ip, None)


# ============================================================
# 보안 미들웨어: 응답 헤더
# ============================================================
@app.after_request
def add_security_headers(response):
    """보안 관련 HTTP 헤더를 자동 추가."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# ============================================================
# 데이터베이스 연결
# ============================================================
def get_db():
    """PostgreSQL 연결을 반환한다."""
    conn = psycopg2.connect(DATABASE_URL)
    conn.autocommit = True
    return conn


def init_db():
    """테이블이 없으면 생성한다. (서버 시작 시 1회 실행)"""
    conn = get_db()
    cur = conn.cursor()

    # 사용자 테이블
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id     TEXT PRIMARY KEY,
            salt        TEXT NOT NULL,
            hash        TEXT NOT NULL,
            iter        INTEGER NOT NULL DEFAULT 120000,
            nickname    TEXT NOT NULL,
            email       TEXT NOT NULL DEFAULT '',
            created_at  TEXT NOT NULL
        )
    """)

    # 세션 토큰 테이블 (로그인 유지용)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token       TEXT PRIMARY KEY,
            user_id     TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
            created_at  TIMESTAMP NOT NULL DEFAULT NOW()
        )
    """)

    # 랭킹 테이블
    cur.execute("""
        CREATE TABLE IF NOT EXISTS rankings (
            id          SERIAL PRIMARY KEY,
            board_key   TEXT NOT NULL,
            board_name  TEXT NOT NULL DEFAULT '',
            user_id     TEXT NOT NULL,
            nickname    TEXT NOT NULL,
            typewriter  TEXT NOT NULL DEFAULT '',
            cpm         INTEGER NOT NULL DEFAULT 0,
            kpm         INTEGER NOT NULL DEFAULT 0,
            acc         REAL NOT NULL DEFAULT 0.0,
            completion  REAL NOT NULL DEFAULT 0.0,
            chars       INTEGER NOT NULL DEFAULT 0,
            input_chars INTEGER NOT NULL DEFAULT 0,
            elapsed     REAL NOT NULL DEFAULT 0.0,
            created_at  TEXT NOT NULL,
            created_ts  BIGINT NOT NULL DEFAULT 0
        )
    """)

    # 연습 텍스트 테이블
    cur.execute("""
        CREATE TABLE IF NOT EXISTS texts (
            id          SERIAL PRIMARY KEY,
            title       TEXT NOT NULL,
            content     TEXT NOT NULL,
            language    TEXT NOT NULL DEFAULT '한국어',
            created_at  TIMESTAMP NOT NULL DEFAULT NOW()
        )
    """)
    # language 컬럼이 없으면 추가 (기존 DB 호환)
    cur.execute("""
        DO $$ BEGIN
            ALTER TABLE texts ADD COLUMN language TEXT NOT NULL DEFAULT '한국어';
        EXCEPTION WHEN duplicate_column THEN NULL;
        END $$;
    """)

    # 텍스트 요청 테이블 (일반 사용자 → 관리자 승인)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS text_requests (
            id          SERIAL PRIMARY KEY,
            user_id     TEXT NOT NULL,
            nickname    TEXT NOT NULL DEFAULT '',
            title       TEXT NOT NULL,
            content     TEXT NOT NULL,
            language    TEXT NOT NULL DEFAULT '한국어',
            status      TEXT NOT NULL DEFAULT 'pending',
            created_at  TIMESTAMP NOT NULL DEFAULT NOW(),
            reviewed_at TIMESTAMP
        )
    """)

    # review_comment, user_notified 컬럼 추가 (기존 DB 호환)
    cur.execute("""
        DO $$ BEGIN
            ALTER TABLE text_requests ADD COLUMN review_comment TEXT NOT NULL DEFAULT '';
        EXCEPTION WHEN duplicate_column THEN NULL;
        END $$;
    """)
    cur.execute("""
        DO $$ BEGIN
            ALTER TABLE text_requests ADD COLUMN user_notified BOOLEAN NOT NULL DEFAULT TRUE;
        EXCEPTION WHEN duplicate_column THEN NULL;
        END $$;
    """)

    # v143: 기존 중복 랭킹 정리 — (nickname, created_at)이 동일한 기록 중 id가 가장 작은 것만 유지
    cur.execute("""
        DELETE FROM rankings
        WHERE id NOT IN (
            SELECT MIN(id) FROM rankings GROUP BY nickname, created_at
        )
    """)

    # ── 보안: 만료된 세션 토큰 정리 ──
    cur.execute("""
        DELETE FROM sessions
        WHERE created_at < NOW() - INTERVAL '%s days'
    """, (SESSION_MAX_AGE_DAYS,))

    # v144: 앱 메타 정보 테이블 (버전 관리 등)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS app_meta (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL DEFAULT ''
        )
    """)
    # 초기 버전 정보 (없을 때만)
    cur.execute("SELECT 1 FROM app_meta WHERE key = 'latest_version'")
    if not cur.fetchone():
        cur.execute("INSERT INTO app_meta (key, value) VALUES ('latest_version', 'v146')")
    cur.execute("SELECT 1 FROM app_meta WHERE key = 'download_url'")
    if not cur.fetchone():
        cur.execute("INSERT INTO app_meta (key, value) VALUES ('download_url', '')")
    cur.execute("SELECT 1 FROM app_meta WHERE key = 'update_message'")
    if not cur.fetchone():
        cur.execute("INSERT INTO app_meta (key, value) VALUES ('update_message', '')")

    # 기본 샘플 텍스트 삽입 (비어있을 때만)
    cur.execute("SELECT COUNT(*) FROM texts")
    if cur.fetchone()[0] == 0:
        samples = [
            ("한글 연습 - 기초", "다람쥐 헌 쳇바퀴에 타고파 한글은 세종대왕이 만든 우리 고유의 문자입니다 가나다라마바사아자차카타파하 빠른 갈색 여우가 게으른 개를 뛰어넘었습니다", "한국어"),
            ("한글 연습 - 문장", "오늘도 좋은 하루가 되길 바랍니다 타자 연습은 꾸준히 하는 것이 중요합니다 매일 조금씩이라도 연습하면 실력이 빠르게 늘어납니다 포기하지 말고 끝까지 도전해 보세요", "한국어"),
            ("English - Basic", "The quick brown fox jumps over the lazy dog Pack my box with five dozen liquor jugs How vexingly quick daft zebras jump", "한국어"),
            ("English - Sentences", "Practice makes perfect Every day is a new opportunity to learn and grow The best time to start is now Keep typing and you will improve", "한국어"),
        ]
        for title, content, lang in samples:
            cur.execute("INSERT INTO texts (title, content, language) VALUES (%s, %s, %s)", (title, content, lang))

    cur.close()
    conn.close()


# ============================================================
# 비밀번호 해싱 (v120과 동일한 PBKDF2-HMAC-SHA256)
# ============================================================
def hash_password(password: str, iterations: int = 120000) -> dict:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return {"salt": salt.hex(), "hash": dk.hex(), "iter": iterations}


def verify_password(password: str, salt_hex: str, hash_hex: str, iterations: int = 120000) -> bool:
    try:
        salt = bytes.fromhex(salt_hex)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return dk.hex() == hash_hex
    except Exception:
        return False


# ============================================================
# 인증 헬퍼
# ============================================================
def get_current_user():
    """요청 헤더의 토큰으로 현재 로그인된 사용자를 반환한다."""
    token = request.headers.get("Authorization", "").replace("Bearer ", "").strip()
    if not token:
        return None

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    # ── 보안: 토큰 만료 체크 (30일) ──
    cur.execute("""
        SELECT s.user_id, u.nickname, u.email, s.created_at as session_created
        FROM sessions s JOIN users u ON s.user_id = u.user_id
        WHERE s.token = %s
    """, (token,))
    row = cur.fetchone()

    if row:
        # 세션 만료 확인
        session_age = datetime.datetime.now(datetime.timezone.utc) - row["session_created"].replace(
            tzinfo=datetime.timezone.utc) if row["session_created"].tzinfo is None else (
            datetime.datetime.now(datetime.timezone.utc) - row["session_created"])
        if session_age.days > SESSION_MAX_AGE_DAYS:
            # 만료된 세션 삭제
            cur.execute("DELETE FROM sessions WHERE token = %s", (token,))
            cur.close(); conn.close()
            return None
        result = {"user_id": row["user_id"], "nickname": row["nickname"], "email": row["email"]}
        cur.close(); conn.close()
        return result

    cur.close()
    conn.close()
    return None


def require_login():
    """로그인 필수. 실패 시 (None, 에러응답) 반환."""
    user = get_current_user()
    if not user:
        return None, (jsonify({"ok": False, "msg": "로그인이 필요합니다.", "msg_code": "svr_login_required"}), 401)
    return user, None


# ============================================================
# API: 회원가입
# ============================================================
@app.route("/api/signup", methods=["POST"])
@rate_limit(max_calls=5, window=300)  # 5분에 5회
def signup():
    data = request.get_json(force=True, silent=True) or {}
    uid = str(data.get("user_id", "") or "").strip()
    pw = str(data.get("password", "") or "")
    nick = str(data.get("nickname", "") or "").strip()
    email = str(data.get("email", "") or "").strip()

    # 유효성 검사 (v120과 동일한 규칙)
    if not uid or not pw or not nick:
        return jsonify({"ok": False, "msg": "ID/비밀번호/닉네임을 모두 입력해 주세요.", "msg_code": "svr_fill_all_signup"}), 400
    if len(uid) < 3:
        return jsonify({"ok": False, "msg": "ID는 3자 이상을 권장합니다.", "msg_code": "svr_id_min3"}), 400
    if len(pw) < 4:
        return jsonify({"ok": False, "msg": "비밀번호는 4자 이상을 권장합니다.", "msg_code": "svr_pw_min4"}), 400
    if len(nick) > 10:
        return jsonify({"ok": False, "msg": "닉네임은 10자 이하로 해 주세요.", "msg_code": "svr_nick_max10"}), 400
    if email and not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return jsonify({"ok": False, "msg": "이메일 형식이 올바르지 않습니다.", "msg_code": "svr_email_invalid"}), 400

    conn = get_db()
    cur = conn.cursor()

    # ID 중복 검사
    cur.execute("SELECT 1 FROM users WHERE user_id = %s", (uid,))
    if cur.fetchone():
        cur.close(); conn.close()
        return jsonify({"ok": False, "msg": "이미 사용 중인 ID입니다.", "msg_code": "svr_dup_id"}), 409

    # 닉네임 중복 검사
    cur.execute("SELECT 1 FROM users WHERE LOWER(nickname) = LOWER(%s)", (nick,))
    if cur.fetchone():
        cur.close(); conn.close()
        return jsonify({"ok": False, "msg": "이미 사용 중인 닉네임입니다.", "msg_code": "svr_dup_nick"}), 409

    # 이메일 중복 검사
    if email:
        cur.execute("SELECT 1 FROM users WHERE LOWER(email) = LOWER(%s) AND email != ''", (email,))
        if cur.fetchone():
            cur.close(); conn.close()
            return jsonify({"ok": False, "msg": "이미 사용 중인 이메일입니다.", "msg_code": "svr_dup_email"}), 409

    # 저장
    h = hash_password(pw)
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cur.execute("""
        INSERT INTO users (user_id, salt, hash, iter, nickname, email, created_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """, (uid, h["salt"], h["hash"], h["iter"], nick, email, now))

    # 자동 로그인 토큰 발급
    token = secrets.token_hex(32)
    cur.execute("INSERT INTO sessions (token, user_id) VALUES (%s, %s)", (token, uid))

    cur.close()
    conn.close()
    return jsonify({"ok": True, "token": token, "user_id": uid, "nickname": nick})


# ============================================================
# API: 로그인
# ============================================================
@app.route("/api/login", methods=["POST"])
@rate_limit(max_calls=10, window=60)  # 1분에 10회
def login():
    data = request.get_json(force=True, silent=True) or {}
    uid = str(data.get("user_id", "") or "").strip()
    pw = str(data.get("password", "") or "")

    if not uid or not pw:
        return jsonify({"ok": False, "msg": "ID와 비밀번호를 입력해 주세요.", "msg_code": "svr_enter_id_pw"}), 400

    # ── 보안: 로그인 실패 잠금 확인 ──
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
    if _check_login_lockout(ip):
        return jsonify({
            "ok": False,
            "msg": "로그인 시도가 너무 많습니다. 15분 후 다시 시도해 주세요.",
            "msg_code": "svr_login_locked"
        }), 429

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM users WHERE user_id = %s", (uid,))
    row = cur.fetchone()

    if not row:
        _record_login_failure(ip)
        cur.close(); conn.close()
        return jsonify({"ok": False, "msg": "ID 또는 비밀번호가 올바르지 않습니다.", "msg_code": "svr_wrong_id_pw"}), 401

    if not verify_password(pw, row["salt"], row["hash"], row["iter"]):
        _record_login_failure(ip)
        cur.close(); conn.close()
        return jsonify({"ok": False, "msg": "ID 또는 비밀번호가 올바르지 않습니다.", "msg_code": "svr_wrong_id_pw"}), 401

    # 성공 → 실패 기록 초기화
    _clear_login_failures(ip)

    # 토큰 발급
    token = secrets.token_hex(32)
    cur2 = conn.cursor()
    cur2.execute("INSERT INTO sessions (token, user_id) VALUES (%s, %s)", (token, uid))
    cur2.close()

    cur.close()
    conn.close()
    return jsonify({
        "ok": True,
        "token": token,
        "user_id": uid,
        "nickname": row["nickname"],
    })


# ============================================================
# API: 로그아웃
# ============================================================
@app.route("/api/logout", methods=["POST"])
def logout():
    token = request.headers.get("Authorization", "").replace("Bearer ", "").strip()
    if token:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("DELETE FROM sessions WHERE token = %s", (token,))
        cur.close()
        conn.close()
    return jsonify({"ok": True})


# ============================================================
# API: 아이디 찾기 (이메일로)
# ============================================================
@app.route("/api/find-id", methods=["POST"])
@rate_limit(max_calls=5, window=300)  # 5분에 5회
def find_id():
    data = request.get_json(force=True, silent=True) or {}
    email = str(data.get("email", "") or "").strip()

    if not email:
        return jsonify({"ok": False, "msg": "이메일을 입력해 주세요.", "msg_code": "svr_enter_email"}), 400

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT user_id FROM users WHERE LOWER(email) = LOWER(%s)", (email,))
    row = cur.fetchone()
    cur.close()
    conn.close()

    if not row:
        return jsonify({"ok": False, "msg": "해당 이메일로 가입된 계정을 찾을 수 없습니다.", "msg_code": "svr_email_not_found"}), 404

    return jsonify({"ok": True, "user_id": row["user_id"]})


# ============================================================
# API: 비밀번호 재설정
# ============================================================
@app.route("/api/reset-password", methods=["POST"])
@rate_limit(max_calls=3, window=300)  # 5분에 3회
def reset_password():
    data = request.get_json(force=True, silent=True) or {}
    uid = str(data.get("user_id", "") or "").strip()
    email = str(data.get("email", "") or "").strip()
    new_pw = str(data.get("new_password", "") or "")

    if not uid or not email or not new_pw:
        return jsonify({"ok": False, "msg": "ID, 이메일, 새 비밀번호를 모두 입력해 주세요.", "msg_code": "svr_fill_all_reset"}), 400
    if len(new_pw) < 4:
        return jsonify({"ok": False, "msg": "비밀번호는 4자 이상을 권장합니다.", "msg_code": "svr_pw_min4"}), 400

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT user_id FROM users WHERE user_id = %s AND LOWER(email) = LOWER(%s)", (uid, email))
    row = cur.fetchone()

    if not row:
        cur.close(); conn.close()
        return jsonify({"ok": False, "msg": "ID와 이메일이 일치하는 계정을 찾을 수 없습니다.", "msg_code": "svr_id_email_mismatch"}), 404

    h = hash_password(new_pw)
    cur2 = conn.cursor()
    cur2.execute("UPDATE users SET salt=%s, hash=%s, iter=%s WHERE user_id=%s",
                 (h["salt"], h["hash"], h["iter"], uid))
    cur2.close()
    cur.close()
    conn.close()
    return jsonify({"ok": True, "msg": "비밀번호가 재설정되었습니다.", "msg_code": "svr_pw_reset_done"})


# ============================================================
# API: 이메일 등록/변경
# ============================================================
@app.route("/api/update-email", methods=["POST"])
def update_email():
    user, err = require_login()
    if err:
        return err

    data = request.get_json(force=True, silent=True) or {}
    new_email = str(data.get("email", "") or "").strip()

    if not new_email:
        return jsonify({"ok": False, "msg": "이메일을 입력해 주세요.", "msg_code": "svr_enter_email"}), 400
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", new_email):
        return jsonify({"ok": False, "msg": "이메일 형식이 올바르지 않습니다.", "msg_code": "svr_email_invalid"}), 400

    conn = get_db()
    cur = conn.cursor()

    # 중복 검사
    cur.execute("SELECT 1 FROM users WHERE LOWER(email) = LOWER(%s) AND user_id != %s AND email != ''",
                (new_email, user["user_id"]))
    if cur.fetchone():
        cur.close(); conn.close()
        return jsonify({"ok": False, "msg": "이미 사용 중인 이메일입니다.", "msg_code": "svr_dup_email"}), 409

    cur.execute("UPDATE users SET email = %s WHERE user_id = %s", (new_email, user["user_id"]))
    cur.close()
    conn.close()
    return jsonify({"ok": True, "msg": "이메일이 변경되었습니다.", "msg_code": "svr_email_changed"})


# ============================================================
# API: 회원탈퇴
# ============================================================
@app.route("/api/delete-account", methods=["POST"])
@rate_limit(max_calls=3, window=300)  # 5분에 3회
def delete_account():
    user, err = require_login()
    if err:
        return err

    data = request.get_json(force=True, silent=True) or {}
    pw = str(data.get("password", "") or "")

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM users WHERE user_id = %s", (user["user_id"],))
    row = cur.fetchone()

    if not row or not verify_password(pw, row["salt"], row["hash"], row["iter"]):
        cur.close(); conn.close()
        return jsonify({"ok": False, "msg": "비밀번호가 올바르지 않습니다.", "msg_code": "svr_pw_wrong"}), 401

    cur2 = conn.cursor()
    cur2.execute("DELETE FROM sessions WHERE user_id = %s", (user["user_id"],))
    cur2.execute("DELETE FROM rankings WHERE user_id = %s", (user["user_id"],))
    cur2.execute("DELETE FROM users WHERE user_id = %s", (user["user_id"],))
    cur2.close()
    cur.close()
    conn.close()
    return jsonify({"ok": True, "msg": "계정이 삭제되었습니다.", "msg_code": "svr_account_deleted"})


# ============================================================
# API: 랭킹 조회
# ============================================================
@app.route("/api/rankings", methods=["GET"])
def get_rankings():
    """전체 또는 특정 보드의 랭킹을 조회한다.
    
    ?board_key=xxx  → 특정 보드만
    ?user_id=xxx    → 특정 사용자만
    (둘 다 없으면 전체)
    """
    board_key = request.args.get("board_key", "").strip()
    user_id = request.args.get("user_id", "").strip()

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    query = "SELECT * FROM rankings WHERE 1=1"
    params = []

    if board_key:
        query += " AND board_key = %s"
        params.append(board_key)
    if user_id:
        query += " AND user_id = %s"
        params.append(user_id)

    query += " ORDER BY cpm DESC, created_ts DESC"
    cur.execute(query, params)
    rows = cur.fetchall()

    # board_key별로 그룹핑 (v120 호환 형식)
    boards = {}
    meta = {}
    for r in rows:
        bk = r["board_key"]
        if bk not in boards:
            boards[bk] = []
            meta[bk] = {"name": r["board_name"], "digest": bk}
        boards[bk].append({
            "id": r["id"],
            "user_id": r["user_id"],
            "nickname": r["nickname"],
            "typewriter": r["typewriter"],
            "board_name": r["board_name"],
            "cpm": r["cpm"],
            "kpm": r["kpm"],
            "acc": r["acc"],
            "completion": r["completion"],
            "chars": r["chars"],
            "input_chars": r["input_chars"],
            "elapsed": r["elapsed"],
            "created_at": r["created_at"],
            "created_ts": r["created_ts"],
        })

    cur.close()
    conn.close()
    return jsonify({"ok": True, "schema": 3, "meta": meta, "boards": boards})


# ============================================================
# API: 랭킹 등록
# ============================================================
@app.route("/api/rankings", methods=["POST"])
@rate_limit(max_calls=10, window=60)  # 1분에 10회
def submit_ranking():
    user, err = require_login()
    if err:
        return err

    data = request.get_json(force=True, silent=True) or {}

    board_key = str(data.get("board_key", "") or "").strip()
    board_name = str(data.get("board_name", "") or "").strip()
    typewriter = str(data.get("typewriter", "") or "").strip()

    if not board_key:
        return jsonify({"ok": False, "msg": "보드 정보가 없습니다.", "msg_code": "svr_no_board"}), 400
    if not typewriter:
        return jsonify({"ok": False, "msg": "'타자기 구분'을 입력해 주세요.", "msg_code": "svr_enter_typewriter"}), 400

    # ── 보안: 입력값 범위 검증 ──
    cpm = int(data.get("cpm", 0) or 0)
    kpm = int(data.get("kpm", 0) or 0)
    acc = float(data.get("acc", 0.0) or 0.0)
    completion = float(data.get("completion", 0.0) or 0.0)
    chars = int(data.get("chars", 0) or 0)
    input_chars = int(data.get("input_chars", 0) or 0)
    elapsed = float(data.get("elapsed", 0.0) or 0.0)

    # 범위 검사
    if cpm < 0 or cpm > MAX_CPM:
        return jsonify({"ok": False, "msg": "비정상적인 CPM 값입니다.", "msg_code": "svr_invalid_cpm"}), 400
    if kpm < 0 or kpm > MAX_KPM:
        return jsonify({"ok": False, "msg": "비정상적인 KPM 값입니다.", "msg_code": "svr_invalid_kpm"}), 400
    if acc < 0 or acc > MAX_ACC:
        return jsonify({"ok": False, "msg": "비정상적인 정확도 값입니다.", "msg_code": "svr_invalid_acc"}), 400
    if completion < 0 or completion > 100.0:
        return jsonify({"ok": False, "msg": "비정상적인 완료율 값입니다.", "msg_code": "svr_invalid_completion"}), 400
    if elapsed <= 0 or elapsed > MAX_ELAPSED:
        return jsonify({"ok": False, "msg": "비정상적인 경과 시간입니다.", "msg_code": "svr_invalid_elapsed"}), 400
    if chars < 0 or chars > MAX_CHARS:
        return jsonify({"ok": False, "msg": "비정상적인 글자수입니다.", "msg_code": "svr_invalid_chars"}), 400

    # ── 보안: 교차 검증 (CPM vs 경과시간 vs 글자수) ──
    if elapsed > 0 and chars > 0:
        expected_cpm = chars / (elapsed / 60.0)
        # 실제 CPM이 기대값의 2배를 초과하면 조작 의심
        if cpm > expected_cpm * 2 + 50:
            return jsonify({"ok": False, "msg": "입력 데이터가 일치하지 않습니다.", "msg_code": "svr_data_mismatch"}), 400

    now = data.get("created_at") or datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ts = int(data.get("created_ts") or 0) or int(time.time())

    conn = get_db()
    cur = conn.cursor()

    # v143: 중복 방지 — (nickname, created_at)이 동일한 기록이 이미 있으면 등록 안 함
    cur.execute("""
        SELECT id FROM rankings
        WHERE nickname = %s AND created_at = %s
        LIMIT 1
    """, (user["nickname"], now))
    if cur.fetchone():
        cur.close()
        conn.close()
        return jsonify({"ok": True, "msg": "이미 등록된 기록입니다.", "msg_code": "svr_rank_duplicate", "duplicate": True})

    cur.execute("""
        INSERT INTO rankings
            (board_key, board_name, user_id, nickname, typewriter,
             cpm, kpm, acc, completion, chars, input_chars, elapsed,
             created_at, created_ts)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING id
    """, (
        board_key,
        board_name,
        user["user_id"],
        user["nickname"],
        typewriter,
        cpm,
        kpm,
        acc,
        completion,
        chars,
        input_chars,
        elapsed,
        now,
        ts,
    ))

    new_id = cur.fetchone()[0]
    cur.close()
    conn.close()
    return jsonify({"ok": True, "msg": "랭킹에 등록되었습니다.", "msg_code": "svr_rank_registered", "id": new_id})


# ============================================================
# API: 랭킹 삭제 (단일)
# ============================================================
@app.route("/api/rankings/<int:ranking_id>", methods=["DELETE"])
def delete_ranking(ranking_id):
    user, err = require_login()
    if err:
        return err

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM rankings WHERE id = %s", (ranking_id,))
    row = cur.fetchone()

    if not row:
        cur.close(); conn.close()
        return jsonify({"ok": False, "msg": "해당 기록을 찾을 수 없습니다.", "msg_code": "svr_record_not_found"}), 404

    # 본인 또는 관리자만 삭제 가능
    if row["user_id"] != user["user_id"] and user["user_id"] != ADMIN_ID:
        cur.close(); conn.close()
        return jsonify({"ok": False, "msg": "삭제 권한이 없습니다.", "msg_code": "svr_no_delete_perm"}), 403

    cur2 = conn.cursor()
    cur2.execute("DELETE FROM rankings WHERE id = %s", (ranking_id,))
    cur2.close()
    cur.close()
    conn.close()
    return jsonify({"ok": True, "msg": "삭제되었습니다.", "msg_code": "svr_deleted"})


# ============================================================
# API: 랭킹 전체 삭제 (보드 단위, 관리자 전용)
# ============================================================
@app.route("/api/rankings/board/<path:board_key>", methods=["DELETE"])
def delete_board_rankings(board_key):
    user, err = require_login()
    if err:
        return err

    if user["user_id"] != ADMIN_ID:
        return jsonify({"ok": False, "msg": "관리자만 전체 삭제할 수 있습니다.", "msg_code": "svr_admin_only_bulk_del"}), 403

    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM rankings WHERE board_key = %s", (board_key,))
    cur.close()
    conn.close()
    return jsonify({"ok": True, "msg": "해당 보드의 모든 기록이 삭제되었습니다.", "msg_code": "svr_board_cleared"})


# ============================================================
# API: 보드 목록 (랭킹 탭 드롭다운용)
# ============================================================
@app.route("/api/boards", methods=["GET"])
def get_boards():
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        SELECT DISTINCT board_key, board_name
        FROM rankings
        ORDER BY board_name
    """)
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify({"ok": True, "boards": [dict(r) for r in rows]})


# ============================================================
# API: 서버 상태 확인
# ============================================================
# ── SEO: robots.txt / sitemap.xml ──
@app.route("/robots.txt", methods=["GET"])
def robots_txt():
    txt = "User-agent: *\nAllow: /\nSitemap: https://www.xixityping.com/sitemap.xml\n"
    return txt, 200, {"Content-Type": "text/plain; charset=utf-8"}

@app.route("/sitemap.xml", methods=["GET"])
def sitemap_xml():
    xml = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://www.xixityping.com/</loc>
    <changefreq>weekly</changefreq>
    <priority>1.0</priority>
  </url>
</urlset>"""
    return xml, 200, {"Content-Type": "application/xml; charset=utf-8"}


@app.route("/", methods=["GET"])
def index():
    return send_from_directory("static", "index.html")


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"ok": True, "msg": "타자 연습 서버 가동 중", "msg_code": "svr_server_running", "version": "1.0"})


@app.route("/api/ping", methods=["GET"])
def ping():
    return jsonify({"ok": True})


# ============================================================
# API: 텍스트 목록
# ============================================================
@app.route("/api/texts", methods=["GET"])
def get_texts():
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT id, title, content, language FROM texts ORDER BY language, id")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    # 언어별로 그룹핑
    languages = []
    lang_set = set()
    for r in rows:
        lang = r.get("language", "한국어")
        if lang not in lang_set:
            lang_set.add(lang)
            languages.append(lang)
    return jsonify({"ok": True, "texts": [dict(r) for r in rows], "languages": languages})


# ============================================================
# API: 텍스트 추가 (관리자 전용)
# ============================================================
@app.route("/api/texts", methods=["POST"])
def add_text():
    user, err = require_login()
    if err:
        return err
    if user["user_id"] != ADMIN_ID:
        return jsonify({"ok": False, "msg": "관리자만 추가할 수 있습니다.", "msg_code": "svr_admin_only_add"}), 403

    data = request.get_json(force=True, silent=True) or {}
    title = str(data.get("title", "") or "").strip()
    content = str(data.get("content", "") or "").strip()
    language = str(data.get("language", "한국어") or "한국어").strip()
    if not title or not content:
        return jsonify({"ok": False, "msg": "제목과 내용을 입력해 주세요.", "msg_code": "svr_enter_title_content"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute("INSERT INTO texts (title, content, language) VALUES (%s, %s, %s) RETURNING id", (title, content, language))
    new_id = cur.fetchone()[0]
    cur.close()
    conn.close()
    return jsonify({"ok": True, "id": new_id})


# ============================================================
# API: 텍스트 수정 (관리자 전용)
# ============================================================
@app.route("/api/texts/<int:text_id>", methods=["PUT"])
def update_text(text_id):
    user, err = require_login()
    if err:
        return err
    if user["user_id"] != ADMIN_ID:
        return jsonify({"ok": False, "msg": "관리자만 수정할 수 있습니다.", "msg_code": "svr_admin_only_edit"}), 403

    data = request.get_json(force=True, silent=True) or {}
    title = str(data.get("title", "") or "").strip()
    content = str(data.get("content", "") or "").strip()
    language = str(data.get("language", "") or "").strip()

    conn = get_db()
    cur = conn.cursor()
    if title and content and language:
        cur.execute("UPDATE texts SET title=%s, content=%s, language=%s WHERE id=%s", (title, content, language, text_id))
    elif title:
        cur.execute("UPDATE texts SET title=%s WHERE id=%s", (title, text_id))
    cur.close()
    conn.close()
    return jsonify({"ok": True})


# ============================================================
# API: 텍스트 삭제 (관리자 전용)
# ============================================================
@app.route("/api/texts/<int:text_id>", methods=["DELETE"])
def delete_text(text_id):
    user, err = require_login()
    if err:
        return err
    if user["user_id"] != ADMIN_ID:
        return jsonify({"ok": False, "msg": "관리자만 삭제할 수 있습니다.", "msg_code": "svr_admin_only_delete"}), 403

    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM texts WHERE id = %s", (text_id,))
    cur.close()
    conn.close()
    return jsonify({"ok": True})


# ============================================================
# API: 텍스트 요청 (일반 사용자가 텍스트 등록 요청)
# ============================================================
@app.route("/api/text-requests", methods=["POST"])
@rate_limit(max_calls=5, window=300)  # 5분에 5회
def submit_text_request():
    user, err = require_login()
    if err:
        return err

    data = request.get_json(force=True, silent=True) or {}
    title = str(data.get("title", "") or "").strip()
    content = str(data.get("content", "") or "").strip()
    language = str(data.get("language", "한국어") or "한국어").strip()
    if not title or not content:
        return jsonify({"ok": False, "msg": "제목과 내용을 입력해 주세요.", "msg_code": "svr_enter_title_content"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO text_requests (user_id, nickname, title, content, language)
        VALUES (%s, %s, %s, %s, %s) RETURNING id
    """, (user["user_id"], user["nickname"], title, content, language))
    new_id = cur.fetchone()[0]
    cur.close()
    conn.close()
    return jsonify({"ok": True, "id": new_id, "msg": "텍스트 요청이 등록되었습니다. 관리자 승인을 기다려 주세요.", "msg_code": "svr_text_req_submitted"})


# ============================================================
# API: 텍스트 요청 목록 조회
# ============================================================
@app.route("/api/text-requests", methods=["GET"])
def get_text_requests():
    user, err = require_login()
    if err:
        return err

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    if user["user_id"] == ADMIN_ID:
        # 관리자: 모든 요청 조회
        cur.execute("SELECT * FROM text_requests ORDER BY created_at DESC")
    else:
        # 일반 사용자: 자기 요청만
        cur.execute("SELECT * FROM text_requests WHERE user_id = %s ORDER BY created_at DESC",
                     (user["user_id"],))

    rows = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify({"ok": True, "requests": [dict(r) for r in rows]})


# ============================================================
# API: 텍스트 요청 승인 (관리자 전용)
# ============================================================
@app.route("/api/text-requests/<int:req_id>/approve", methods=["POST"])
def approve_text_request(req_id):
    user, err = require_login()
    if err:
        return err
    if user["user_id"] != ADMIN_ID:
        return jsonify({"ok": False, "msg": "관리자만 승인할 수 있습니다.", "msg_code": "svr_admin_only_approve"}), 403

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    cur.execute("SELECT * FROM text_requests WHERE id = %s", (req_id,))
    req = cur.fetchone()
    if not req:
        cur.close()
        conn.close()
        return jsonify({"ok": False, "msg": "요청을 찾을 수 없습니다.", "msg_code": "svr_request_not_found"}), 404

    # texts 테이블에 추가
    cur.execute("INSERT INTO texts (title, content, language) VALUES (%s, %s, %s) RETURNING id",
                (req["title"], req["content"], req["language"]))
    new_text_id = cur.fetchone()["id"]

    # 요청 상태 변경 + 코멘트 저장
    data = request.get_json(force=True, silent=True) or {}
    comment = str(data.get("comment", "") or "").strip()
    cur.execute("""UPDATE text_requests
                   SET status = 'approved', reviewed_at = NOW(),
                       review_comment = %s, user_notified = FALSE
                   WHERE id = %s""", (comment, req_id))

    cur.close()
    conn.close()
    return jsonify({"ok": True, "text_id": new_text_id, "msg": "승인 완료. 텍스트가 등록되었습니다.", "msg_code": "svr_approved_done"})


# ============================================================
# API: 텍스트 요청 거절 (관리자 전용)
# ============================================================
@app.route("/api/text-requests/<int:req_id>/reject", methods=["POST"])
def reject_text_request(req_id):
    user, err = require_login()
    if err:
        return err
    if user["user_id"] != ADMIN_ID:
        return jsonify({"ok": False, "msg": "관리자만 거절할 수 있습니다.", "msg_code": "svr_admin_only_reject"}), 403

    conn = get_db()
    cur = conn.cursor()
    data = request.get_json(force=True, silent=True) or {}
    comment = str(data.get("comment", "") or "").strip()
    cur.execute("""UPDATE text_requests
                   SET status = 'rejected', reviewed_at = NOW(),
                       review_comment = %s, user_notified = FALSE
                   WHERE id = %s""", (comment, req_id))
    cur.close()
    conn.close()
    return jsonify({"ok": True, "msg": "요청이 거절되었습니다.", "msg_code": "svr_rejected_done"})


# ============================================================
# API: 텍스트 요청 알림 조회 (사용자용)
# ============================================================
@app.route("/api/text-requests/notifications", methods=["GET"])
def get_text_request_notifications():
    user, err = require_login()
    if err:
        return err

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        SELECT id, title, status, review_comment, reviewed_at
        FROM text_requests
        WHERE user_id = %s AND status != 'pending' AND user_notified = FALSE
        ORDER BY reviewed_at DESC
    """, (user["user_id"],))
    rows = cur.fetchall()
    cur.close()
    conn.close()

    result = []
    for r in rows:
        d = dict(r)
        if d.get("reviewed_at"):
            d["reviewed_at"] = str(d["reviewed_at"])
        result.append(d)

    return jsonify({"ok": True, "notifications": result})


# ============================================================
# API: 텍스트 요청 알림 확인 처리
# ============================================================
@app.route("/api/text-requests/notifications/ack", methods=["POST"])
def ack_text_request_notifications():
    user, err = require_login()
    if err:
        return err

    data = request.get_json(force=True, silent=True) or {}
    ids = data.get("ids", [])
    if not ids:
        return jsonify({"ok": True})

    conn = get_db()
    cur = conn.cursor()
    for req_id in ids:
        cur.execute("""UPDATE text_requests SET user_notified = TRUE
                       WHERE id = %s AND user_id = %s""", (req_id, user["user_id"]))
    cur.close()
    conn.close()
    return jsonify({"ok": True})


# ============================================================
# API: 앱 버전 확인 (공개)
# ============================================================
@app.route("/api/version", methods=["GET"])
def get_version():
    try:
        conn = get_db()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT key, value FROM app_meta WHERE key IN ('latest_version', 'download_url', 'update_message')")
        rows = cur.fetchall()
        cur.close()
        conn.close()
        result = {}
        for r in rows:
            result[r["key"]] = r["value"]
        return jsonify({
            "ok": True,
            "latest_version": result.get("latest_version", ""),
            "download_url": result.get("download_url", ""),
            "update_message": result.get("update_message", ""),
        })
    except Exception as e:
        return jsonify({"ok": False, "msg": str(e)}), 500


# ============================================================
# API: 앱 버전 업데이트 (관리자 전용)
# ============================================================
@app.route("/api/version", methods=["POST"])
def update_version():
    user, err = require_login()
    if err:
        return err
    if user["user_id"] != ADMIN_ID:
        return jsonify({"ok": False, "msg": "관리자만 가능합니다.", "msg_code": "svr_admin_only"}), 403

    data = request.get_json(force=True, silent=True) or {}
    conn = get_db()
    cur = conn.cursor()

    for key in ("latest_version", "download_url", "update_message"):
        if key in data:
            val = str(data[key] or "").strip()
            cur.execute("""
                INSERT INTO app_meta (key, value) VALUES (%s, %s)
                ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
            """, (key, val))

    cur.close()
    conn.close()
    return jsonify({"ok": True, "msg": "버전 정보가 업데이트되었습니다.", "msg_code": "svr_version_updated"})


# ============================================================
# 서버 시작
# ============================================================

# 서버가 시작될 때 테이블 자동 생성
try:
    if DATABASE_URL:
        init_db()
except Exception as e:
    print(f"[init_db] 초기화 대기 중... ({e})")

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
