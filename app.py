"""
타자 연습 서버 API
- 회원가입/로그인/계정 관리
- 랭킹 등록/조회/삭제
- Railway + PostgreSQL 용
"""

import os
import re
import time
import hashlib
import secrets
import datetime

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import psycopg2
import psycopg2.extras

# ============================================================
# Flask 앱 설정
# ============================================================
app = Flask(__name__, static_folder="static", static_url_path="/static")
CORS(app)  # 웹 버전에서 접속할 수 있도록 허용

# Railway가 자동으로 제공하는 DATABASE_URL 환경변수 사용
DATABASE_URL = os.environ.get("DATABASE_URL", "")

ADMIN_ID = "zhengxi980"


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
            created_at  TIMESTAMP NOT NULL DEFAULT NOW()
        )
    """)

    # 기본 샘플 텍스트 삽입 (비어있을 때만)
    cur.execute("SELECT COUNT(*) FROM texts")
    if cur.fetchone()[0] == 0:
        samples = [
            ("한글 연습 - 기초", "다람쥐 헌 쳇바퀴에 타고파 한글은 세종대왕이 만든 우리 고유의 문자입니다 가나다라마바사아자차카타파하 빠른 갈색 여우가 게으른 개를 뛰어넘었습니다"),
            ("한글 연습 - 문장", "오늘도 좋은 하루가 되길 바랍니다 타자 연습은 꾸준히 하는 것이 중요합니다 매일 조금씩이라도 연습하면 실력이 빠르게 늘어납니다 포기하지 말고 끝까지 도전해 보세요"),
            ("English - Basic", "The quick brown fox jumps over the lazy dog Pack my box with five dozen liquor jugs How vexingly quick daft zebras jump"),
            ("English - Sentences", "Practice makes perfect Every day is a new opportunity to learn and grow The best time to start is now Keep typing and you will improve"),
        ]
        for title, content in samples:
            cur.execute("INSERT INTO texts (title, content) VALUES (%s, %s)", (title, content))

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
    cur.execute("""
        SELECT s.user_id, u.nickname, u.email
        FROM sessions s JOIN users u ON s.user_id = u.user_id
        WHERE s.token = %s
    """, (token,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    return dict(row) if row else None


def require_login():
    """로그인 필수. 실패 시 (None, 에러응답) 반환."""
    user = get_current_user()
    if not user:
        return None, (jsonify({"ok": False, "msg": "로그인이 필요합니다."}), 401)
    return user, None


# ============================================================
# API: 회원가입
# ============================================================
@app.route("/api/signup", methods=["POST"])
def signup():
    data = request.get_json(force=True, silent=True) or {}
    uid = str(data.get("user_id", "") or "").strip()
    pw = str(data.get("password", "") or "")
    nick = str(data.get("nickname", "") or "").strip()
    email = str(data.get("email", "") or "").strip()

    # 유효성 검사 (v120과 동일한 규칙)
    if not uid or not pw or not nick:
        return jsonify({"ok": False, "msg": "ID/비밀번호/닉네임을 모두 입력해 주세요."}), 400
    if len(uid) < 3:
        return jsonify({"ok": False, "msg": "ID는 3자 이상을 권장합니다."}), 400
    if len(pw) < 4:
        return jsonify({"ok": False, "msg": "비밀번호는 4자 이상을 권장합니다."}), 400
    if len(nick) > 10:
        return jsonify({"ok": False, "msg": "닉네임은 10자 이하로 해 주세요."}), 400
    if email and not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return jsonify({"ok": False, "msg": "이메일 형식이 올바르지 않습니다."}), 400

    conn = get_db()
    cur = conn.cursor()

    # ID 중복 검사
    cur.execute("SELECT 1 FROM users WHERE user_id = %s", (uid,))
    if cur.fetchone():
        cur.close(); conn.close()
        return jsonify({"ok": False, "msg": "이미 사용 중인 ID입니다."}), 409

    # 닉네임 중복 검사
    cur.execute("SELECT 1 FROM users WHERE LOWER(nickname) = LOWER(%s)", (nick,))
    if cur.fetchone():
        cur.close(); conn.close()
        return jsonify({"ok": False, "msg": "이미 사용 중인 닉네임입니다."}), 409

    # 이메일 중복 검사
    if email:
        cur.execute("SELECT 1 FROM users WHERE LOWER(email) = LOWER(%s) AND email != ''", (email,))
        if cur.fetchone():
            cur.close(); conn.close()
            return jsonify({"ok": False, "msg": "이미 사용 중인 이메일입니다."}), 409

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
def login():
    data = request.get_json(force=True, silent=True) or {}
    uid = str(data.get("user_id", "") or "").strip()
    pw = str(data.get("password", "") or "")

    if not uid or not pw:
        return jsonify({"ok": False, "msg": "ID와 비밀번호를 입력해 주세요."}), 400

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM users WHERE user_id = %s", (uid,))
    row = cur.fetchone()

    if not row:
        cur.close(); conn.close()
        return jsonify({"ok": False, "msg": "ID 또는 비밀번호가 올바르지 않습니다."}), 401

    if not verify_password(pw, row["salt"], row["hash"], row["iter"]):
        cur.close(); conn.close()
        return jsonify({"ok": False, "msg": "ID 또는 비밀번호가 올바르지 않습니다."}), 401

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
def find_id():
    data = request.get_json(force=True, silent=True) or {}
    email = str(data.get("email", "") or "").strip()

    if not email:
        return jsonify({"ok": False, "msg": "이메일을 입력해 주세요."}), 400

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT user_id FROM users WHERE LOWER(email) = LOWER(%s)", (email,))
    row = cur.fetchone()
    cur.close()
    conn.close()

    if not row:
        return jsonify({"ok": False, "msg": "해당 이메일로 가입된 계정을 찾을 수 없습니다."}), 404

    return jsonify({"ok": True, "user_id": row["user_id"]})


# ============================================================
# API: 비밀번호 재설정
# ============================================================
@app.route("/api/reset-password", methods=["POST"])
def reset_password():
    data = request.get_json(force=True, silent=True) or {}
    uid = str(data.get("user_id", "") or "").strip()
    email = str(data.get("email", "") or "").strip()
    new_pw = str(data.get("new_password", "") or "")

    if not uid or not email or not new_pw:
        return jsonify({"ok": False, "msg": "ID, 이메일, 새 비밀번호를 모두 입력해 주세요."}), 400
    if len(new_pw) < 4:
        return jsonify({"ok": False, "msg": "비밀번호는 4자 이상을 권장합니다."}), 400

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT user_id FROM users WHERE user_id = %s AND LOWER(email) = LOWER(%s)", (uid, email))
    row = cur.fetchone()

    if not row:
        cur.close(); conn.close()
        return jsonify({"ok": False, "msg": "ID와 이메일이 일치하는 계정을 찾을 수 없습니다."}), 404

    h = hash_password(new_pw)
    cur2 = conn.cursor()
    cur2.execute("UPDATE users SET salt=%s, hash=%s, iter=%s WHERE user_id=%s",
                 (h["salt"], h["hash"], h["iter"], uid))
    cur2.close()
    cur.close()
    conn.close()
    return jsonify({"ok": True, "msg": "비밀번호가 재설정되었습니다."})


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
        return jsonify({"ok": False, "msg": "이메일을 입력해 주세요."}), 400
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", new_email):
        return jsonify({"ok": False, "msg": "이메일 형식이 올바르지 않습니다."}), 400

    conn = get_db()
    cur = conn.cursor()

    # 중복 검사
    cur.execute("SELECT 1 FROM users WHERE LOWER(email) = LOWER(%s) AND user_id != %s AND email != ''",
                (new_email, user["user_id"]))
    if cur.fetchone():
        cur.close(); conn.close()
        return jsonify({"ok": False, "msg": "이미 사용 중인 이메일입니다."}), 409

    cur.execute("UPDATE users SET email = %s WHERE user_id = %s", (new_email, user["user_id"]))
    cur.close()
    conn.close()
    return jsonify({"ok": True, "msg": "이메일이 변경되었습니다."})


# ============================================================
# API: 회원탈퇴
# ============================================================
@app.route("/api/delete-account", methods=["POST"])
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
        return jsonify({"ok": False, "msg": "비밀번호가 올바르지 않습니다."}), 401

    cur2 = conn.cursor()
    cur2.execute("DELETE FROM sessions WHERE user_id = %s", (user["user_id"],))
    cur2.execute("DELETE FROM rankings WHERE user_id = %s", (user["user_id"],))
    cur2.execute("DELETE FROM users WHERE user_id = %s", (user["user_id"],))
    cur2.close()
    cur.close()
    conn.close()
    return jsonify({"ok": True, "msg": "계정이 삭제되었습니다."})


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
def submit_ranking():
    user, err = require_login()
    if err:
        return err

    data = request.get_json(force=True, silent=True) or {}

    board_key = str(data.get("board_key", "") or "").strip()
    board_name = str(data.get("board_name", "") or "").strip()
    typewriter = str(data.get("typewriter", "") or "").strip()

    if not board_key:
        return jsonify({"ok": False, "msg": "보드 정보가 없습니다."}), 400
    if not typewriter:
        return jsonify({"ok": False, "msg": "'타자기 구분'을 입력해 주세요."}), 400

    now = data.get("created_at") or datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ts = int(data.get("created_ts") or 0) or int(time.time())

    conn = get_db()
    cur = conn.cursor()
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
        int(data.get("cpm", 0) or 0),
        int(data.get("kpm", 0) or 0),
        float(data.get("acc", 0.0) or 0.0),
        float(data.get("completion", 0.0) or 0.0),
        int(data.get("chars", 0) or 0),
        int(data.get("input_chars", 0) or 0),
        float(data.get("elapsed", 0.0) or 0.0),
        now,
        ts,
    ))

    new_id = cur.fetchone()[0]
    cur.close()
    conn.close()
    return jsonify({"ok": True, "msg": "랭킹에 등록되었습니다.", "id": new_id})


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
        return jsonify({"ok": False, "msg": "해당 기록을 찾을 수 없습니다."}), 404

    # 본인 또는 관리자만 삭제 가능
    if row["user_id"] != user["user_id"] and user["user_id"] != ADMIN_ID:
        cur.close(); conn.close()
        return jsonify({"ok": False, "msg": "삭제 권한이 없습니다."}), 403

    cur2 = conn.cursor()
    cur2.execute("DELETE FROM rankings WHERE id = %s", (ranking_id,))
    cur2.close()
    cur.close()
    conn.close()
    return jsonify({"ok": True, "msg": "삭제되었습니다."})


# ============================================================
# API: 랭킹 전체 삭제 (보드 단위, 관리자 전용)
# ============================================================
@app.route("/api/rankings/board/<path:board_key>", methods=["DELETE"])
def delete_board_rankings(board_key):
    user, err = require_login()
    if err:
        return err

    if user["user_id"] != ADMIN_ID:
        return jsonify({"ok": False, "msg": "관리자만 전체 삭제할 수 있습니다."}), 403

    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM rankings WHERE board_key = %s", (board_key,))
    cur.close()
    conn.close()
    return jsonify({"ok": True, "msg": "해당 보드의 모든 기록이 삭제되었습니다."})


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
@app.route("/", methods=["GET"])
def index():
    return send_from_directory("static", "index.html")


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"ok": True, "msg": "타자 연습 서버 가동 중", "version": "1.0"})


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
    cur.execute("SELECT id, title, content FROM texts ORDER BY id")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify({"ok": True, "texts": [dict(r) for r in rows]})


# ============================================================
# API: 텍스트 추가 (관리자 전용)
# ============================================================
@app.route("/api/texts", methods=["POST"])
def add_text():
    user, err = require_login()
    if err:
        return err
    if user["user_id"] != ADMIN_ID:
        return jsonify({"ok": False, "msg": "관리자만 추가할 수 있습니다."}), 403

    data = request.get_json(force=True, silent=True) or {}
    title = str(data.get("title", "") or "").strip()
    content = str(data.get("content", "") or "").strip()
    if not title or not content:
        return jsonify({"ok": False, "msg": "제목과 내용을 입력해 주세요."}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute("INSERT INTO texts (title, content) VALUES (%s, %s) RETURNING id", (title, content))
    new_id = cur.fetchone()[0]
    cur.close()
    conn.close()
    return jsonify({"ok": True, "id": new_id})


# ============================================================
# API: 텍스트 삭제 (관리자 전용)
# ============================================================
@app.route("/api/texts/<int:text_id>", methods=["DELETE"])
def delete_text(text_id):
    user, err = require_login()
    if err:
        return err
    if user["user_id"] != ADMIN_ID:
        return jsonify({"ok": False, "msg": "관리자만 삭제할 수 있습니다."}), 403

    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM texts WHERE id = %s", (text_id,))
    cur.close()
    conn.close()
    return jsonify({"ok": True})


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
