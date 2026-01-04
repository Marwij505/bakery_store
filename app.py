from flask import (
    Flask, render_template, request, 
    redirect, url_for, session, flash
)
import mysql.connector
import secrets
import json
import os
from functools import wraps
from mysql.connector import Error
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from decimal import Decimal

# ================================================
# FUNGTION UTILITIES
# ================================================
def safe_float(val, default=0.0):
    try:
        if val is None:
            return float(default)
        if isinstance(val, Decimal):
            return float(val)
        return float(val)
    except Exception:
        return float(default)

def safe_int(val, default=0):
    try:
        if val is None:
            return int(default)
        if isinstance(val, Decimal):
            return int(val)
        return int(val)
    except Exception:
        return int(default)

def get_client_ip():
    # kalau nanti pakai reverse proxy, tetap aman
    fwd = request.headers.get("X-Forwarded-For", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.remote_addr or ""

def generate_temp_password(length=10):
    # mudah diketik, tapi cukup kuat untuk reset sementara
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$"
    return "".join(secrets.choice(alphabet) for _ in range(length))

def owner_only_or_superadmin():
    return session.get("role") in ("owner", "superadmin")

def require_owner_or_superadmin(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        if not owner_only_or_superadmin():
            flash("Akses Access Control hanya untuk Owner (atau Superadmin).", "danger")
            return redirect(url_for("owner_dashboard"))
        return fn(*args, **kwargs)
    return wrapper

def create_session_record(user_id: int):
    """
    Catat login ke tabel user_sessions dan simpan token di session Flask
    """
    token = secrets.token_hex(24)
    ip = get_client_ip()
    ua = (request.headers.get("User-Agent") or "")[:255]

    connection = get_db_connection()
    if not connection:
        return None

    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            INSERT INTO user_sessions (user_id, session_token, ip_address, user_agent, is_active)
            VALUES (%s, %s, %s, %s, 1)
            """,
            (user_id, token, ip, ua)
        )
        connection.commit()
        return token
    except Error as e:
        connection.rollback()
        print("Error create_session_record:", e)
        return None
    finally:
        cursor.close()
        connection.close()

def close_session_record():
    """
    Saat logout, update logout_at
    """
    token = session.get("session_token")
    if not token:
        return

    connection = get_db_connection()
    if not connection:
        return

    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            UPDATE user_sessions
            SET logout_at = NOW(), is_active = 0
            WHERE session_token = %s
            LIMIT 1
            """,
            (token,)
        )
        connection.commit()
    except Error as e:
        connection.rollback()
        print("Error close_session_record:", e)
    finally:
        cursor.close()
        connection.close()

def log_user_activity(action: str, meta: dict | None = None):
    """
    Simpan aktivitas terakhir user (last action, IP, dsb.)
    """
    if "user_id" not in session:
        return

    user_id = session.get("user_id")
    ip = get_client_ip()
    endpoint = request.endpoint or ""
    method = request.method
    meta_json = None
    if meta is not None:
        try:
            meta_json = json.dumps(meta, ensure_ascii=False)
        except Exception:
            meta_json = None

    connection = get_db_connection()
    if not connection:
        return

    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            INSERT INTO user_activity_logs (user_id, action, endpoint, method, ip_address, meta_json)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (user_id, action[:120], endpoint[:120], method[:10], ip[:64], meta_json)
        )
        connection.commit()
    except Error as e:
        connection.rollback()
        print("Error log_user_activity:", e)
    finally:
        cursor.close()
        connection.close()

def get_client_ip():
    # aman untuk dev/local; kalau nanti deploy behind proxy bisa pakai X-Forwarded-For
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr

def log_audit(action, status="success", target_type=None, target_id=None, details=None):
    """
    Simpan log audit penting (login/logout, ubah role, reset password, perubahan data sensitif, approval, dsb).
    Aman dipanggil walau belum login (actor_* bisa NULL).
    """
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        actor_user_id = session.get("user_id")
        actor_employee_id = session.get("employee_id")
        actor_full_name = session.get("full_name")
        actor_role = session.get("role")

        ip = get_client_ip()
        ua = (request.headers.get("User-Agent") or "")[:255]

        cur.execute("""
            INSERT INTO audit_logs
            (actor_user_id, actor_employee_id, actor_full_name, actor_role,
             action, status, target_type, target_id, details, ip_address, user_agent)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            actor_user_id, actor_employee_id, actor_full_name, actor_role,
            action, status, target_type, str(target_id) if target_id is not None else None,
            details, ip, ua
        ))

        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        # jangan bikin app crash kalau audit gagal
        print("AUDIT LOG ERROR:", e)

# =================================================
# KONFIGURASI FLASK
# =================================================
app = Flask(
    __name__,
    template_folder="Template",   # folder HTML
    static_folder="CSS"           # folder CSS
)
app.secret_key = os.getenv("SECRET_KEY", "dev-only-change-me")

# ============================================
# FUNGSI KONEKSI KE DATABASE (XAMPP / MySQL)
# ============================================
def get_db_connection():
    try:
        connection = mysql.connector.connect(
            host=os.getenv("DB_HOST"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            database=os.getenv("DB_NAME"),
            port=int(os.getenv("DB_PORT", "3306")),
        )
        return connection
    except Error as e:
        print("Error connecting to MySQL:", e)
        return None

# ============================
# AUTO USER ACTIVITY TRACKER
# ============================
@app.before_request
def _auto_activity_tracker():
    # jangan log file static
    if request.endpoint == "static":
        return

    # jangan log request yang terlalu sensitif/berisik (opsional)
    skip = {"login", "logout"}
    if request.endpoint in skip:
        return

    if "user_id" in session:
        # action = endpoint biar simple tapi kebaca
        log_user_activity(action=f"visit:{request.endpoint}")

# =================================================
# ROUTE UTAMA -> redirect ke /login
# =================================================
@app.route("/")
def index():
    return redirect(url_for("login"))

# =================================================
# LOGIN (Owner / Manager / Admin)
# =================================================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")   # di DB = employee_id
        password = request.form.get("password")

        connection = get_db_connection()
        if not connection:
            flash("Gagal konek ke database. Cek XAMPP / konfigurasi DB.", "danger")
            return render_template("login.html")

        cursor = connection.cursor(dictionary=True)
        query = """
            SELECT *
            FROM portal_users
            WHERE employee_id = %s
              AND is_active = 1
            LIMIT 1
        """
        cursor.execute(query, (username,))
        user = cursor.fetchone()
        cursor.close()
        connection.close()

        if user and check_password_hash(user["password_hash"], password):
            role = user["role"]

            # simpan session
            session["user_id"] = user["id"]
            session["username"] = user["employee_id"]
            session["full_name"] = user["full_name"]
            session["role"] = role
            # catat login session (untuk last login & IP)
            token = create_session_record(user["id"])
            if token:
                session["session_token"] = token

            flash(f"Welcome back, {user['full_name']}!", "success")
            log_audit(action="login", status="success", target_type="portal_user", target_id=user["id"])

            # redirect sesuai role
            if role == "owner":
                return redirect(url_for("owner_dashboard"))
            elif role == "manager":
                return redirect(url_for("manager_dashboard"))
            elif role == "admin":
                return redirect(url_for("admin_dashboard"))
            else:
                flash("Role akun ini belum diatur untuk portal.", "danger")    

        else:
            flash("Username atau password salah.", "danger")
            employee_id = request.form.get("username", "").strip() # atau "employee_id"
            password = request.form.get("password", "")
            log_audit(action="login_failed", status="failed", target_type="portal_user", target_id=employee_id, details="wrong_credentials")

    return render_template("login.html")

# ===============================================================================
# REGISTER (khusus Manager / Admin, Owner di-seed dari backend)
#   NOTE: disesuaikan dengan struktur tabel portal_users:
#   id, employee_id, full_name, email, password_hash, role, is_active, created_at
#   -> di sini 'phone' kita simpan dulu ke kolom email biar nggak error.
# ================================================================================
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        full_name   = request.form.get("full_name")
        phone       = request.form.get("phone")         # disimpan di kolom email
        father_name = request.form.get("father_name")   # BELUM disimpan ke DB
        mother_name = request.form.get("mother_name")   # BELUM disimpan ke DB
        username    = request.form.get("username")      # employee_id
        password    = request.form.get("password")
        role        = request.form.get("role")          # manager / admin

        # validasi sederhana
        if role not in ("manager", "admin"):
            flash("Role tidak valid. Hanya manager atau admin.", "danger")
            return render_template("register.html")

        if not all([full_name, phone, father_name, mother_name, username, password]):
            flash("Semua field wajib diisi.", "danger")
            return render_template("register.html")

        connection = get_db_connection()
        if not connection:
            flash("Gagal konek ke database.", "danger")
            return render_template("register.html")

        cursor = connection.cursor()

        # cek username sudah ada?
        cursor.execute(
            "SELECT id FROM portal_users WHERE employee_id = %s LIMIT 1",
            (username,)
        )
        existing = cursor.fetchone()
        if existing:
            cursor.close()
            connection.close()
            flash("Username sudah digunakan. Pilih username lain.", "danger")
            return render_template("register.html")

        password_hash = generate_password_hash(password)

        try:
            cursor.execute(
                """
                INSERT INTO portal_users
                    (employee_id, full_name, email, password_hash, role, is_active)
                VALUES (%s, %s, %s, %s, %s, 1)
                """,
                (username, full_name, phone, password_hash, role)
            )
            connection.commit()
            flash("Registrasi berhasil. Silakan login dengan akun baru.", "success")
            cursor.close()
            connection.close()
            return redirect(url_for("login"))
        except Error as e:
            connection.rollback()
            cursor.close()
            connection.close()
            print("Error insert user:", e)
            flash("Terjadi kesalahan saat menyimpan data.", "danger")
            return render_template("register.html")

    return render_template("register.html")

# ==================================================
# LOGOUT
# ==================================================
@app.route("/logout")
def logout():
    close_session_record()
    session.clear()
    flash("Kamu sudah logout dari portal.", "info")
    log_audit("logout", status="success", target_type="session", target_id=session.get("user_id"))
    return redirect(url_for("login"))

# ===========================================
# SEED 4 OWNER (AKSES SEKALI: /create_owners)
# ===========================================
@app.route("/create_owners")
def create_owners():
    connection = get_db_connection()
    if not connection:
        return "Gagal konek ke database."

    cursor = connection.cursor()

    owners = [
        ("MarWij", "Marcell", "mar123"),
        ("ReiPret", "Reifan", "rei123"),
        ("ShaHan", "Shafa",  "han123"),
        ("ZarUl",  "Zara",   "aul123"),
    ]

    created = 0
    for username, full_name, raw_password in owners:
        password_hash = generate_password_hash(raw_password)
        try:
            cursor.execute(
                """
                INSERT INTO portal_users
                    (employee_id, full_name, password_hash, role, is_active)
                VALUES (%s, %s, %s, %s, 1)
                """,
                (username, full_name, password_hash, "owner")
            )
            created += 1
        except Error as e:
            print(f"Error insert {username}: {e}")

    connection.commit()
    cursor.close()
    connection.close()

    return f"{created} owner account(s) created. Coba login via /login."

# ====================================
# DASHBOARD OWNER (EXECUTIVE OVERVIEW)
# ====================================
@app.route("/owner-dashboard")
def owner_dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if session.get("role") not in ("owner", "manager", "admin"):
        flash("Akses hanya untuk Owner / Management.", "danger")
        return redirect(url_for("login"))

    connection = get_db_connection()
    if not connection:
        flash("Gagal konek ke database. Cek XAMPP / konfigurasi DB.", "danger")
        return render_template(
            "owner_dashboard.html",
            summary=None,
            cabang_rows=[],
            kota_list=[],
            branches_master=[],
            filter_kota="",
            tanggal_filter="",
            full_name=session.get("full_name"),
            role=session.get("role"),
            alerts=[],
            active_menu="overview"   # <<< PENTING
        )

    cursor = connection.cursor(dictionary=True)

    kota_filter = (request.args.get("kota") or "").strip()
    tanggal_filter = (request.args.get("tanggal") or "").strip()
    # -----------------------------
    # FILTER hanya untuk master cabang
    # (supaya cabang tetap muncul walau belum punya data penjualan)
    # -----------------------------
    where_tc = []
    params_tc = []
    if kota_filter:
        where_tc.append("tc.kota = %s")
        params_tc.append(kota_filter)

    where_sql = ("WHERE " + " AND ".join(where_tc)) if where_tc else ""

    # join penjualan harian:
    # - jika user pilih tanggal -> ambil data tanggal itu
    # - jika tidak pilih tanggal -> ambil tanggal terbaru per cabang
    params_sales = []
    if tanggal_filter:
        join_sales = "LEFT JOIN penjualan_harian ph ON ph.id_cabang = tc.id AND ph.tanggal = %s"
        params_sales.append(tanggal_filter)
    else:
        join_sales = """LEFT JOIN penjualan_harian ph
            ON ph.id_cabang = tc.id
           AND ph.tanggal = (
               SELECT MAX(tanggal)
               FROM penjualan_harian
               WHERE id_cabang = tc.id
           )"""
    # -----------------------------
    # SUMMARY
    # -----------------------------
    summary_query = f"""
        SELECT
            COUNT(DISTINCT tc.id)                 AS total_cabang,
            COALESCE(SUM(ph.total_pendapatan), 0) AS total_pendapatan,
            COALESCE(SUM(ph.total_pesanan), 0)    AS total_pesanan
        FROM toko_cabang tc
        {join_sales}
        {where_sql}
    """
    cursor.execute(summary_query, params_sales + params_tc)
    summary = cursor.fetchone()
    # -----------------------------
    # DETAIL ROWS (1 row per cabang)
    # -----------------------------
    detail_query = f"""
        SELECT
            tc.id,
            tc.nama_cabang,
            tc.kota,
            tc.negara,
            tc.status_cabang,
            tc.alamat_lengkap,
            tc.tanggal_buka,
            ph.tanggal,
            COALESCE(ph.total_pendapatan, 0) AS total_pendapatan,
            COALESCE(ph.total_pesanan, 0)    AS total_pesanan,
            COALESCE(ph.laba_bersih, 0)      AS laba_bersih
        FROM toko_cabang tc
        {join_sales}
        {where_sql}
        ORDER BY tc.kota, tc.nama_cabang
        LIMIT 200
    """
    cursor.execute(detail_query, params_sales + params_tc)
    cabang_rows = cursor.fetchall() or []

    # dropdown filter kota
    cursor.execute("SELECT DISTINCT kota FROM toko_cabang ORDER BY kota")
    kota_list = [row["kota"] for row in (cursor.fetchall() or []) if row.get("kota")]

    # dropdown cabang untuk form penjualan harian (hindari duplikat dari join)
    cursor.execute("SELECT id, nama_cabang, kota FROM toko_cabang ORDER BY kota, nama_cabang")
    branches_master = cursor.fetchall() or []

    # contoh alert sederhana
    alerts = []
    if summary and summary["total_pendapatan"] == 0:
        alerts.append({
            "level": "warning",
            "title": "Belum ada data penjualan.",
            "message": "Input penjualan harian pertama untuk mulai melihat tren.",
            "meta": "Tips: gunakan form 'Input Penjualan Harian' di atas."
        })

    cursor.close()
    connection.close()

    return render_template(
        "owner_dashboard.html",
        summary=summary,
        cabang_rows=cabang_rows,
        kota_list=kota_list,
        branches_master=branches_master,
        filter_kota=kota_filter,
        tanggal_filter=tanggal_filter,
        full_name=session.get("full_name"),
        role=session.get("role"),
        alerts=alerts,
        active_menu="overview"    # <<< pastikan di sini
    )
# -------------------------------------------------
# FORM: TAMBAH CABANG
# -------------------------------------------------
@app.route("/owner-dashboard/add-branch", methods=["POST"])
def add_branch():
    if "user_id" not in session:
        return redirect(url_for("login"))
    if session.get("role") != "owner":
        flash("Hanya Owner yang boleh menambah cabang.", "danger")
        return redirect(url_for("owner_dashboard"))

    nama_cabang = request.form.get("nama_cabang")
    kota = request.form.get("kota")
    negara = request.form.get("negara") or "Indonesia"
    alamat_lengkap = request.form.get("alamat_lengkap")
    tanggal_buka = request.form.get("tanggal_buka") or None

    if not nama_cabang or not kota:
        flash("Nama cabang dan kota wajib diisi.", "danger")
        return redirect(url_for("owner_dashboard"))

    connection = get_db_connection()
    if not connection:
        flash("Gagal konek ke database.", "danger")
        return redirect(url_for("owner_dashboard"))

    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            INSERT INTO toko_cabang
                (nama_cabang, kota, negara, alamat_lengkap, status_cabang, tanggal_buka)
            VALUES (%s, %s, %s, %s, 'aktif', %s)
            """,
            (nama_cabang, kota, negara, alamat_lengkap, tanggal_buka)
        )
        connection.commit()
        flash("Cabang baru berhasil ditambahkan.", "success")
    except Error as e:
        print("Error insert cabang:", e)
        flash("Gagal menambahkan cabang.", "danger")
    finally:
        cursor.close()
        connection.close()

    return redirect(url_for("owner_dashboard"))
# -------------------------------------------------
# EDIT CABANG (fix typo / update master data cabang)
# -------------------------------------------------
@app.route("/owner-dashboard/edit-branch", methods=["POST"])
def edit_branch():
    if "user_id" not in session:
        return redirect(url_for("login"))

    # master data cabang: batasi hanya Owner (biar tidak sembarang role ubah profil cabang)
    if session.get("role") != "owner":
        flash("Hanya Owner yang boleh mengedit data cabang.", "danger")
        return redirect(url_for("owner_dashboard"))

    next_url = (
        request.form.get("next")
        or request.headers.get("Referer")
        or url_for("owner_dashboard")
    )

    branch_id = (request.form.get("branch_id") or "").strip()
    nama_cabang = (request.form.get("nama_cabang") or "").strip()
    kota = (request.form.get("kota") or "").strip()
    negara = (request.form.get("negara") or "Indonesia").strip()
    alamat_lengkap = (request.form.get("alamat_lengkap") or "").strip()
    status_cabang = (request.form.get("status_cabang") or "aktif").strip().lower()
    tanggal_buka = request.form.get("tanggal_buka") or None

    if not branch_id.isdigit():
        flash("ID cabang tidak valid.", "danger")
        return redirect(next_url)

    if not nama_cabang or not kota:
        flash("Nama cabang dan kota wajib diisi.", "danger")
        return redirect(next_url)

    allowed_status = {"aktif", "tutup", "renovasi"}
    if status_cabang not in allowed_status:
        flash("Status cabang tidak valid.", "danger")
        return redirect(next_url)

    connection = get_db_connection()
    if not connection:
        flash("Gagal konek ke database.", "danger")
        return redirect(next_url)

    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            UPDATE toko_cabang
            SET
                nama_cabang = %s,
                kota = %s,
                negara = %s,
                alamat_lengkap = %s,
                status_cabang = %s,
                tanggal_buka = %s
            WHERE id = %s
            LIMIT 1
            """,
            (nama_cabang, kota, negara, alamat_lengkap, status_cabang, tanggal_buka, int(branch_id)),
        )
        connection.commit()
        flash("Data cabang berhasil diperbarui.", "success")
    except Error as e:
        connection.rollback()
        print("Error update cabang:", e)
        flash("Gagal memperbarui data cabang.", "danger")
    finally:
        cursor.close()
        connection.close()

    return redirect(next_url)
# -------------------------------------------------
# FORM: TAMBAH PENJUALAN HARIAN
# -------------------------------------------------
@app.route("/owner-dashboard/add-sales", methods=["POST"])
def add_sales():
    if "user_id" not in session:
        return redirect(url_for("login"))
    if session.get("role") not in ("owner", "manager"):
        flash("Hanya Owner / Manager yang boleh input penjualan.", "danger")
        return redirect(url_for("owner_dashboard"))

    id_cabang        = request.form.get("id_cabang")
    tanggal          = request.form.get("tanggal")
    total_pendapatan = request.form.get("total_pendapatan") or 0
    total_pesanan    = request.form.get("total_pesanan") or 0
    laba_bersih      = request.form.get("laba_bersih") or 0

    if not id_cabang or not tanggal:
        flash("Cabang dan tanggal wajib diisi untuk input penjualan.", "danger")
        return redirect(url_for("owner_dashboard"))

    connection = get_db_connection()
    if not connection:
        flash("Gagal konek ke database.", "danger")
        return redirect(url_for("owner_dashboard"))

    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            INSERT INTO penjualan_harian
                (id_cabang, tanggal, total_pendapatan, total_pesanan, laba_bersih)
            VALUES (%s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                total_pendapatan = VALUES(total_pendapatan),
                total_pesanan    = VALUES(total_pesanan),
                laba_bersih      = VALUES(laba_bersih)
            """,
            (id_cabang, tanggal, total_pendapatan, total_pesanan, laba_bersih)
        )
        connection.commit()
        flash("Data penjualan harian tersimpan.", "success")
    except Error as e:
        print("Error insert penjualan:", e)
        flash("Gagal menyimpan penjualan harian.", "danger")
    finally:
        cursor.close()
        connection.close()

    return redirect(url_for("owner_dashboard"))
# ----------------------------------------------------------
# EDIT SALES (fix typo / update master data penjualan)
# ----------------------------------------------------------
@app.route("/owner-dashboard/edit-sales", methods=["POST"])
def edit_sales():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if session.get("role") not in ("owner", "manager"):
        flash("Hanya Owner / Manager yang boleh mengedit penjualan.", "danger")
        return redirect(url_for("owner_dashboard"))

    next_url = (
        request.form.get("next")
        or request.headers.get("Referer")
        or url_for("owner_dashboard")
    )

    id_cabang = (request.form.get("id_cabang") or "").strip()
    tanggal = (request.form.get("tanggal") or "").strip()

    total_pendapatan = request.form.get("total_pendapatan") or 0
    total_pesanan = request.form.get("total_pesanan") or 0
    laba_bersih = request.form.get("laba_bersih") or 0

    if not id_cabang or not tanggal:
        flash("Cabang dan tanggal wajib diisi.", "danger")
        return redirect(next_url)

    connection = get_db_connection()
    if not connection:
        flash("Gagal konek ke database.", "danger")
        return redirect(next_url)

    cursor = connection.cursor()
    try:
        cursor.execute(
            '''
            INSERT INTO penjualan_harian
                (id_cabang, tanggal, total_pendapatan, total_pesanan, laba_bersih)
            VALUES (%s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                total_pendapatan = VALUES(total_pendapatan),
                total_pesanan    = VALUES(total_pesanan),
                laba_bersih      = VALUES(laba_bersih)
            ''',
            (id_cabang, tanggal, total_pendapatan, total_pesanan, laba_bersih)
        )
        connection.commit()

        # Audit log
        try:
            log_audit(
                "edit_sales",
                status="success",
                target_type="penjualan_harian",
                target_id=f"{id_cabang}:{tanggal}",
                details=json.dumps({
                    "id_cabang": id_cabang,
                    "tanggal": tanggal,
                    "total_pendapatan": float(total_pendapatan) if str(total_pendapatan).strip() else 0,
                    "total_pesanan": int(total_pesanan) if str(total_pesanan).strip() else 0,
                    "laba_bersih": float(laba_bersih) if str(laba_bersih).strip() else 0,
                }, ensure_ascii=False),
            )
        except Exception as e:
            print("WARN audit edit_sales:", e)

        flash("Data penjualan harian berhasil diperbarui.", "success")
    except Error as e:
        connection.rollback()
        print("Error edit penjualan:", e)
        try:
            log_audit(
                "edit_sales",
                status="failed",
                target_type="penjualan_harian",
                target_id=f"{id_cabang}:{tanggal}",
                details=str(e),
            )
        except Exception:
            pass
        flash("Gagal memperbarui data penjualan.", "danger")
    finally:
        cursor.close()
        connection.close()

    return redirect(next_url)

# =============================================
# DASHBOARD SEDERHANA UNTUK MANAGER & ADMIN
# =============================================
@app.route("/manager-dashboard")
def manager_dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    if session.get("role") != "manager":
        flash("Akses ditolak. Hanya untuk Manager.", "danger")
        return redirect(url_for("login"))

    full_name = session.get("full_name")
    username = session.get("username")

    return f"""
    <h1>Manager Dashboard</h1>
    <p>Halo, {full_name} (Username: {username}, Role: manager)</p>
    <p>Di sini nanti ada overview performa cabang dan operasional harian.</p>
    <a href="{url_for('logout')}">Logout</a>
    """

@app.route("/admin-dashboard")
def admin_dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    if session.get("role") != "admin":
        flash("Akses ditolak. Hanya untuk Admin.", "danger")
        return redirect(url_for("login"))

    full_name = session.get("full_name")
    username = session.get("username")

    return f"""
    <h1>Admin Dashboard</h1>
    <p>Halo, {full_name} (Username: {username}, Role: admin)</p>
    <p>Di sini nanti admin bisa mengelola user dan konfigurasi sistem.</p>
    <a href="{url_for('logout')}">Logout</a>
    """

# ===================================
# PRODUCT INSIGHTS / PRODUCT CATALOG
# ===================================
@app.route("/products", methods=["GET", "POST"])
def product_dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if session.get("role") not in ("owner", "manager", "admin"):
        flash("Akses hanya untuk Owner / Management.", "danger")
        return redirect(url_for("login"))

    connection = get_db_connection()
    if not connection:
        flash("Gagal konek ke database. Cek XAMPP / konfigurasi DB.", "danger")
        return render_template(
            "product_dashboard.html",
            produk_list=[],
            kategori_summary=[],
            sales_rows=[],
            branch_list=[],
            sales_history=[],
            sales_history_total_qty=0,
            sales_history_total_rev=0,
            rec_branch_id="",
            rec_product_id="",
            rec_date_from="",
            rec_date_to="",
            full_name=session.get("full_name"),
            role=session.get("role"),
            active_menu="products",
        )

    cursor = connection.cursor(dictionary=True)

    try:
        # 1) HANDLE POST: ADD PRODUCT
        if request.method == "POST" and request.form.get("form_type") == "add_product":
            nama_produk = (request.form.get("nama_produk") or "").strip()
            kategori    = (request.form.get("kategori") or "").strip()
            harga       = request.form.get("harga") or "0"
            status      = request.form.get("status_produk") or "aktif"

            if not nama_produk or not kategori:
                flash("Product name and category are required.", "danger")
            else:
                try:
                    cursor.execute(
                        """
                        INSERT INTO produk (nama_produk, kategori, harga, status_produk)
                        VALUES (%s, %s, %s, %s)
                        """,
                        (nama_produk, kategori, harga, status)
                    )
                    connection.commit()
                    flash("Product has been added.", "success")
                    return redirect(url_for("product_dashboard"))
                except Exception as e:
                    print("Error insert product:", e)
                    connection.rollback()
                    flash("Failed to save product. Please check again.", "danger")

        # 2) FILTER SALES HISTORY (GET)
        rec_branch_id  = (request.args.get("rec_branch_id") or "").strip()
        rec_product_id = (request.args.get("rec_product_id") or "").strip()
        rec_date_from  = (request.args.get("rec_date_from") or "").strip()
        rec_date_to    = (request.args.get("rec_date_to") or "").strip()

        where = []
        params = []

        if rec_branch_id:
            where.append("pph.id_cabang = %s")
            params.append(rec_branch_id)

        if rec_product_id:
            where.append("pph.id_produk = %s")
            params.append(rec_product_id)

        # tanggal bisa DATE / DATETIME, jadi pakai DATE()
        if rec_date_from:
            where.append("DATE(pph.tanggal) >= %s")
            params.append(rec_date_from)

        if rec_date_to:
            where.append("DATE(pph.tanggal) <= %s")
            params.append(rec_date_to)

        where_sql = ("WHERE " + " AND ".join(where)) if where else ""

        # 3) LIST PRODUK
        cursor.execute(
            """
            SELECT
                id,
                nama_produk,
                kategori,
                harga,
                status_produk,
                created_at
            FROM produk
            ORDER BY status_produk DESC, nama_produk ASC
            """
        )
        produk_list = cursor.fetchall()

        # 4) RINGKASAN KATEGORI
        cursor.execute(
            """
            SELECT
                kategori,
                COUNT(*) AS jumlah,
                SUM(CASE WHEN status_produk = 'aktif' THEN 1 ELSE 0 END) AS aktif_count
            FROM produk
            GROUP BY kategori
            ORDER BY kategori
            """
        )
        kategori_summary = cursor.fetchall()

        # 5) LIST CABANG (dropdown)
        cursor.execute(
            """
            SELECT
                id,
                nama_cabang,
                kota
            FROM toko_cabang
            ORDER BY kota, nama_cabang
            """
        )
        branch_list = cursor.fetchall()

        # 6) SALES HISTORY (maks 50)
        cursor.execute(
            f"""
            SELECT
                pph.id,
                pph.tanggal,
                pph.jumlah_terjual,
                pph.pendapatan,
                pph.created_at,
                tc.id AS cabang_id,
                tc.nama_cabang,
                tc.kota,
                pr.id AS produk_id,
                pr.nama_produk,
                pr.kategori
            FROM penjualan_produk_harian pph
            JOIN toko_cabang tc ON tc.id = pph.id_cabang
            JOIN produk pr ON pr.id = pph.id_produk
            {where_sql}
            ORDER BY DATE(pph.tanggal) DESC, pph.id DESC
            LIMIT 50
            """,
            tuple(params)
        )
        sales_history = cursor.fetchall() or []
        
        # 7) TOTAL QTY & TOTAL REV (ikut filter)
        cursor.execute(
            f"""
            SELECT
                COALESCE(SUM(pph.jumlah_terjual), 0) AS total_qty,
                COALESCE(SUM(pph.pendapatan), 0)     AS total_rev
            FROM penjualan_produk_harian pph
            {where_sql}
            """,
            tuple(params)
        )
        totals = cursor.fetchone() or {"total_qty": 0, "total_rev": 0}
        sales_history_total_qty = int(totals.get("total_qty") or 0)
        sales_history_total_rev = float(totals.get("total_rev") or 0)

        # 8) TOP PRODUCTS BY SALES (ikut filter juga!)
        cursor.execute(
            f"""
            SELECT
                pr.nama_produk,
                COALESCE(SUM(pph.jumlah_terjual), 0) AS total_terjual,
                COALESCE(SUM(pph.pendapatan), 0)     AS total_pendapatan
            FROM penjualan_produk_harian pph
            JOIN produk pr ON pr.id = pph.id_produk
            {where_sql}
            GROUP BY pr.id, pr.nama_produk
            ORDER BY total_pendapatan DESC
            LIMIT 5
            """,
            tuple(params)
        )
        sales_rows = cursor.fetchall() or []

        # 9) RENDER
        return render_template(
            "product_dashboard.html",
            produk_list=produk_list,
            kategori_summary=kategori_summary,
            sales_rows=sales_rows,
            branch_list=branch_list,
            full_name=session.get("full_name"),
            role=session.get("role"),
            active_menu="products",

            sales_history=sales_history,
            sales_history_total_qty=sales_history_total_qty,
            sales_history_total_rev=sales_history_total_rev,
            rec_branch_id=rec_branch_id,
            rec_product_id=rec_product_id,
            rec_date_from=rec_date_from,
            rec_date_to=rec_date_to,
        )

    finally:
        try:
            cursor.close()
        except:
            pass
        try:
            connection.close()
        except:
            pass
#-------------------------------------------------
# TOGGLE STATUS PRODUK (AKTIF / NONAKTIF)
#-------------------------------------------------
@app.route("/products/<int:id_produk>/toggle", methods=["POST"])
def toggle_product_status(id_produk):
    if "user_id" not in session:
        return redirect(url_for("login"))

    if session.get("role") not in ("owner", "manager"):
        flash("Only Owner / Manager can change product status.", "danger")
        return redirect(url_for("product_dashboard"))

    connection = get_db_connection()
    if not connection:
        flash("Gagal konek ke database.", "danger")
        return redirect(url_for("product_dashboard"))

    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            UPDATE produk
            SET status_produk = CASE
                WHEN status_produk = 'aktif' THEN 'nonaktif'
                ELSE 'aktif'
            END
            WHERE id = %s
            """,
            (id_produk,)
        )
        connection.commit()
        flash("Product status has been updated.", "success")
    except Error as e:
        print("Error toggle status:", e)
        connection.rollback()
        flash("Failed to change product status.", "danger")
    finally:
        cursor.close()
        connection.close()

    return redirect(url_for("product_dashboard"))
#-------------------------------------------------
# FORM: TAMBAH PENJUALAN PRODUK HARIAN
#-------------------------------------------------
@app.route("/products/add-sales", methods=["POST"])
def add_product_sales():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if session.get("role") not in ("owner", "manager"):
        flash("Only Owner / Manager can record product sales.", "danger")
        return redirect(url_for("product_dashboard"))

    id_produk        = request.form.get("id_produk")
    id_cabang        = request.form.get("id_cabang")   # wajib, supaya per-cabang
    tanggal          = request.form.get("tanggal")
    jumlah_terjual   = request.form.get("jumlah_terjual") or "0"
    pendapatan_total = request.form.get("pendapatan_total") or "0"

    if not id_produk or not id_cabang or not tanggal:
        flash("Branch, product, and date are required.", "danger")
        return redirect(url_for("product_dashboard"))

    # Konversi angka
    try:
        jumlah_terjual_val   = int(jumlah_terjual)
        pendapatan_total_val = float(pendapatan_total)
    except ValueError:
        flash("Quantity and revenue must be numeric.", "danger")
        return redirect(url_for("product_dashboard"))

    connection = get_db_connection()
    if not connection:
        flash("Cannot connect to database.", "danger")
        return redirect(url_for("product_dashboard"))

    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            INSERT INTO penjualan_produk_harian
                (id_cabang, id_produk, tanggal, jumlah_terjual, pendapatan)
            VALUES (%s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                jumlah_terjual = VALUES(jumlah_terjual),
                pendapatan     = VALUES(pendapatan)
            """,
            (id_cabang, id_produk, tanggal, jumlah_terjual_val, pendapatan_total_val)
        )
        connection.commit()
        flash("Daily product sales saved.", "success")
    except Error as e:
        print("Error inserting penjualan_produk_harian:", e)
        connection.rollback()
        flash("Failed to save daily product sales.", "danger")
    finally:
        cursor.close()
        connection.close()

    return redirect(url_for("product_dashboard"))

# =========================================================
# BRANCH PERFORMANCE (catalog performance cabang HARMSTORE)
# =========================================================
@app.route("/branch-performance", methods=["GET"])
def branch_performance():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if session.get("role") not in ("owner", "manager", "admin"):
        flash("Access restricted to management only.", "danger")
        return redirect(url_for("login"))

    connection = get_db_connection()
    if not connection:
        flash("Cannot connect to database.", "danger")
        return render_template(
            "branch_dashboard.html",
            branches=[],
            summary={"total_cabang": 0, "total_pendapatan": 0, "total_pesanan": 0},
            negara_list=[],
            kota_list=[],
            filter_negara="",
            filter_kota="",
            tanggal_filter="",
            sort_by="revenue",
            detail_branch_id=None,
            detail_branch=None,
            monthly_chart=[],
            chart_max=0,
            top_products=[],
            peak_hour=None,
            full_name=session.get("full_name"),
            role=session.get("role"),
            active_menu="branches",
        )

    cursor = connection.cursor(dictionary=True)

    # --- ambil filter dari query string ---
    negara_filter = request.args.get("negara", "").strip()
    kota_filter = request.args.get("kota", "").strip()
    tanggal_filter = request.args.get("tanggal", "").strip()
    sort_by = request.args.get("sort_by", "revenue").strip()
    detail_branch_id = request.args.get("detail_branch_id") or None

    params = []
    where = []

    # filter negara/kota pakai table cabang
    if negara_filter:
        where.append("tc.negara = %s")
        params.append(negara_filter)
    if kota_filter:
        where.append("tc.kota = %s")
        params.append(kota_filter)

    # filter tanggal kalau dipakai: taruh di JOIN agar LEFT JOIN tidak berubah jadi INNER JOIN
    join_sales_extra = ""
    params_sales = []
    if tanggal_filter:
        join_sales_extra = " AND ph.tanggal = %s "
        params_sales.append(tanggal_filter)

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    # --- tentukan ORDER BY sesuai sort_by ---
    if sort_by == "orders":
        order_clause = "ORDER BY total_pesanan DESC"
    elif sort_by == "profit":
        order_clause = "ORDER BY total_laba DESC"
    elif sort_by == "days":
        order_clause = "ORDER BY hari_aktif DESC"
    elif sort_by == "name":
        order_clause = "ORDER BY tc.nama_cabang ASC"
    else:  # default revenue
        order_clause = "ORDER BY total_pendapatan DESC"

    # Aggregasi performa cabang
    cursor.execute(
        f"""
        SELECT
            tc.id,
            tc.nama_cabang,
            tc.kota,
            tc.negara,
            tc.status_cabang,
            COUNT(ph.id)                           AS hari_aktif,
            COALESCE(SUM(ph.total_pendapatan), 0)  AS total_pendapatan,
            COALESCE(SUM(ph.total_pesanan), 0)     AS total_pesanan,
            COALESCE(SUM(ph.laba_bersih), 0)       AS total_laba
        FROM toko_cabang tc
        LEFT JOIN penjualan_harian ph
            ON ph.id_cabang = tc.id
            {join_sales_extra}
        {where_sql}
        GROUP BY
            tc.id, tc.nama_cabang, tc.kota, tc.negara, tc.status_cabang
        {order_clause}
        """,
        params_sales + params,
    )
    branches_raw = cursor.fetchall() or []

    # normalisasi angka (hindari Decimal vs float)
    branches = []
    for b in branches_raw:
        total_rev = safe_float(b.get("total_pendapatan"), 0)
        total_profit = safe_float(b.get("total_laba"), 0)
        total_orders = safe_int(b.get("total_pesanan"), 0)
        days_active = safe_int(b.get("hari_aktif"), 0)

        profit_margin = (total_profit / total_rev * 100.0) if total_rev > 0 else 0.0

        branches.append({
            **b,
            "total_pendapatan": total_rev,
            "total_laba": total_profit,
            "total_pesanan": total_orders,
            "hari_aktif": days_active,
            "profit_margin": profit_margin,
            # default values (akan diisi jika ada data growth/health)
            "growth_pct": 0.0,
            "health_status": "normal",
        })
    # -------------------------------------------------
    # Growth & Health indicator (opsional)
    # - growth dihitung 30 hari terakhir vs 30 hari sebelumnya
    # - jika user memilih tanggal spesifik, growth tidak dihitung (0)
    # -------------------------------------------------
    if branches and (not tanggal_filter):
        try:
            cursor.execute(
                """
                SELECT
                    id_cabang,
                    COALESCE(SUM(CASE
                        WHEN tanggal >= (CURDATE() - INTERVAL 30 DAY) THEN total_pendapatan
                        ELSE 0
                    END), 0) AS rev_curr,
                    COALESCE(SUM(CASE
                        WHEN tanggal < (CURDATE() - INTERVAL 30 DAY)
                         AND tanggal >= (CURDATE() - INTERVAL 60 DAY) THEN total_pendapatan
                        ELSE 0
                    END), 0) AS rev_prev
                FROM penjualan_harian
                GROUP BY id_cabang
                """
            )
            growth_rows = cursor.fetchall() or []
            growth_map = {
                int(r["id_cabang"]): {
                    "rev_curr": safe_float(r.get("rev_curr"), 0),
                    "rev_prev": safe_float(r.get("rev_prev"), 0),
                }
                for r in growth_rows
                if r.get("id_cabang") is not None
            }

            for b in branches:
                gid = int(b.get("id"))
                g = growth_map.get(gid, {"rev_curr": 0.0, "rev_prev": 0.0})
                rev_curr = safe_float(g.get("rev_curr"), 0)
                rev_prev = safe_float(g.get("rev_prev"), 0)

                if rev_prev > 0:
                    growth_pct = ((rev_curr - rev_prev) / rev_prev) * 100.0
                else:
                    growth_pct = 100.0 if rev_curr > 0 else 0.0

                b["growth_pct"] = float(growth_pct)

                # health status sederhana
                # - kalau cabang tidak aktif -> warning
                # - kalau revenue 0 -> critical
                # - kalau growth turun tajam -> warning
                if (b.get("status_cabang") or "").lower() != "aktif":
                    b["health_status"] = "warning"
                elif (b.get("total_pendapatan") or 0) <= 0:
                    b["health_status"] = "critical"
                elif b["growth_pct"] < -10:
                    b["health_status"] = "warning"
                else:
                    b["health_status"] = "normal"

            # kalau user pilih sort_by=growth, sortir di python
            if sort_by == "growth":
                branches.sort(key=lambda x: safe_float(x.get("growth_pct"), 0), reverse=True)
        except Exception as e:
            # jangan bikin page error kalau growth query gagal
            print("Error computing growth/health:", e)

    # --- summary untuk cards atas ---
    summary = {
        "total_cabang": len(branches),
        "total_pendapatan": sum(b["total_pendapatan"] for b in branches) if branches else 0,
        "total_pesanan": sum(b["total_pesanan"] for b in branches) if branches else 0,
    }

    # --- list negara & kota untuk dropdown filter ---
    cursor.execute("SELECT DISTINCT negara FROM toko_cabang ORDER BY negara")
    negara_list = [r["negara"] for r in (cursor.fetchall() or []) if r.get("negara")]

    cursor.execute("SELECT DISTINCT kota FROM toko_cabang ORDER BY kota")
    kota_list = [r["kota"] for r in (cursor.fetchall() or []) if r.get("kota")]

    # --- detail branch (chart + top 5 product) ---
    detail_branch = None
    monthly_chart = []
    chart_max = 0.0
    top_products = []
    peak_hour = None  # placeholder

    if detail_branch_id:
        cursor.execute("SELECT * FROM toko_cabang WHERE id = %s LIMIT 1", (detail_branch_id,))
        detail_branch = cursor.fetchone()

        if detail_branch:
            # 6 bulan terakhir
            cursor.execute(
                """
                SELECT
                    DATE_FORMAT(tanggal, '%Y-%m') AS bulan,
                    COALESCE(SUM(total_pendapatan), 0) AS total_pendapatan
                FROM penjualan_harian
                WHERE id_cabang = %s
                GROUP BY DATE_FORMAT(tanggal, '%Y-%m')
                ORDER BY bulan DESC
                LIMIT 6
                """,
                (detail_branch_id,),
            )
            rows = cursor.fetchall() or []
            rows = list(reversed(rows))  # lama -> baru

            monthly_chart = [
                {"bulan": r["bulan"], "total_pendapatan": safe_float(r.get("total_pendapatan"), 0)}
                for r in rows
            ]
            chart_max = max((r["total_pendapatan"] for r in monthly_chart), default=0.0)

            # top 5 produk di cabang ini
            cursor.execute(
                """
                SELECT
                    p.nama_produk,
                    COALESCE(SUM(pph.jumlah_terjual), 0) AS total_terjual,
                    COALESCE(SUM(pph.pendapatan), 0)     AS total_pendapatan
                FROM penjualan_produk_harian pph
                JOIN produk p ON pph.id_produk = p.id
                WHERE pph.id_cabang = %s
                GROUP BY p.id, p.nama_produk
                ORDER BY total_terjual DESC
                LIMIT 5
                """,
                (detail_branch_id,),
            )
            tp = cursor.fetchall() or []
            top_products = [
                {
                    "nama_produk": r["nama_produk"],
                    "total_terjual": safe_int(r.get("total_terjual"), 0),
                    "total_pendapatan": safe_float(r.get("total_pendapatan"), 0),
                }
                for r in tp
            ]

    cursor.close()
    connection.close()

    # Hitung status_counts dan branch_status_list dari data `branches`
    status_counts = {"aktif": 0, "tutup": 0, "renovasi": 0}
    for b in branches:
        s = (b.get("status_cabang") or "").strip().lower()
        if s in status_counts:
            status_counts[s] += 1

    branch_status_list = [
        {
            "id": b.get("id"),
            "nama_cabang": b.get("nama_cabang"),
            "kota": b.get("kota"),
            "negara": b.get("negara"),
            "status_cabang": (b.get("status_cabang") or "").strip().lower(),
        }
        for b in branches
    ]

    return render_template(
        "branch_dashboard.html",
        branches=branches,
        summary=summary,
        negara_list=negara_list,
        kota_list=kota_list,
        filter_negara=negara_filter,
        filter_kota=kota_filter,
        tanggal_filter=tanggal_filter,
        sort_by=sort_by,
        detail_branch_id=int(detail_branch_id) if detail_branch_id else None,
        detail_branch=detail_branch,
        monthly_chart=monthly_chart,
        chart_max=chart_max,
        top_products=top_products,
        peak_hour=peak_hour,
        status_counts=status_counts,
        branch_status_list=branch_status_list,
        full_name=session.get("full_name"),
        role=session.get("role"),
        active_menu="branches",
    )
# -------------------------------------------------
# TOGGLE / SET STATUS CABANG (kompatibel dengan template)
# Template branch_dashboard.html memanggil endpoint:
#   url_for('toggle_branch_status', branch_id=...)
# dan mengirim form field: set_status=aktif|tutup|renovasi
# -------------------------------------------------
@app.route("/branches/<int:branch_id>/toggle-status", methods=["POST"])
def toggle_branch_status(branch_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    if session.get("role") not in ("owner", "manager", "admin"):
        flash("Only management can change branch status.", "danger")
        return redirect(url_for("branch_performance"))

    # support 2 nama field: 'set_status' (template) atau 'status' (route baru)
    new_status = (
        request.form.get("set_status")
        or request.form.get("status")
        or ""
    ).strip().lower()

    # kalau ada hidden input next, pakai itu. Kalau tidak, pakai referrer.
    next_url = (
        request.form.get("next")
        or request.headers.get("Referer")
        or url_for("branch_performance")
    )

    allowed = {"aktif", "tutup", "renovasi"}
    if new_status not in allowed:
        flash("Invalid status.", "danger")
        return redirect(next_url)

    connection = get_db_connection()
    if not connection:
        flash("Cannot connect to database.", "danger")
        return redirect(next_url)

    cursor = connection.cursor(dictionary=True)
    try:
        cursor.execute(
            "UPDATE toko_cabang SET status_cabang = %s WHERE id = %s",
            (new_status, branch_id),
        )
        connection.commit()
        flash("Branch status updated.", "success")
    except Exception as e:
        print("Error toggle branch status:", e)
        connection.rollback()
        flash("Failed to update status.", "danger")
    finally:
        cursor.close()
        connection.close()

    return redirect(next_url)
# -------------------------------------------------
# SET STATUS CABANG (AKTIF / TUTUP / RENOVASI)
# -------------------------------------------------
@app.route("/branches/<int:branch_id>/set-status", methods=["POST"])
def set_branch_status(branch_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    if session.get("role") not in ("owner", "manager", "admin"):
        flash("Only management can change branch status.", "danger")
        return redirect(url_for("branch_performance"))

    new_status = (request.form.get("status") or "").strip().lower()
    next_url = request.form.get("next") or url_for("branch_performance")

    allowed = {"aktif", "tutup", "renovasi"}
    if new_status not in allowed:
        flash("Invalid status.", "danger")
        return redirect(next_url)

    connection = get_db_connection()
    if not connection:
        flash("Cannot connect to database.", "danger")
        return redirect(next_url)

    cursor = connection.cursor(dictionary=True)
    try:
        cursor.execute("UPDATE toko_cabang SET status_cabang = %s WHERE id = %s", (new_status, branch_id))
        connection.commit()
        flash("Branch status updated.", "success")
    except Exception as e:
        print("Error set branch status:", e)
        connection.rollback()
        flash("Failed to update status.", "danger")
    finally:
        cursor.close()
        connection.close()

    return redirect(next_url)

# ===============================
# ACCESS CONTROL (EXECUTIVE MENU)
# ===============================
@app.route("/access-control")
@require_owner_or_superadmin
def access_control():
    full_name = session.get("full_name")
    role = session.get("role")

    # one-time password display (hasil create/reset)
    temp_info = session.pop("one_time_password", None)

    connection = get_db_connection()
    if not connection:
        flash("Gagal konek ke database.", "danger")
        return render_template(
            "access_control.html",
            full_name=full_name,
            role=role,
            users=[],
            role_options=["owner","superadmin","manager","admin","staff","hr","finance"],
            temp_info=temp_info,
            active_menu="access"
        )

    cursor = connection.cursor(dictionary=True)

    # ambil list user + last login + last action
    users_query = """
        SELECT
            pu.id,
            pu.employee_id,
            pu.full_name,
            pu.email,
            pu.role,
            pu.is_active,
            pu.created_at,
            pu.phone_number,
            pu.date_birth,

            (SELECT MAX(us.login_at)
             FROM user_sessions us
             WHERE us.user_id = pu.id) AS last_login_at,

            (SELECT us2.ip_address
             FROM user_sessions us2
             WHERE us2.user_id = pu.id
             ORDER BY us2.login_at DESC
             LIMIT 1) AS last_login_ip,

            (SELECT MAX(ul.created_at)
             FROM user_activity_logs ul
             WHERE ul.user_id = pu.id) AS last_action_at,

            (SELECT ul2.action
             FROM user_activity_logs ul2
             WHERE ul2.user_id = pu.id
             ORDER BY ul2.created_at DESC
             LIMIT 1) AS last_action
        FROM portal_users pu
        ORDER BY pu.created_at DESC, pu.id DESC
        LIMIT 300
    """
    cursor.execute(users_query)
    users = cursor.fetchall() or []

    # role options (kalau enum belum di-alter, tetap aman)
    role_options = ["owner","superadmin","manager","admin","staff","hr","finance"]

    cursor.close()
    connection.close()

    return render_template(
        "access_control.html",
        full_name=full_name,
        role=role,
        users=users,
        role_options=role_options,
        temp_info=temp_info,
        active_menu="access"
    )
# ----------------
# CREATE NEW USER
# ----------------
@app.route("/access-control/create-user", methods=["POST"])
@require_owner_or_superadmin
def access_control_create_user():
    employee_id = (request.form.get("employee_id") or "").strip()
    full_name = (request.form.get("full_name") or "").strip()
    email = (request.form.get("email") or "").strip()
    role = (request.form.get("role") or "staff").strip()
    phone_number = (request.form.get("phone_number") or "").strip()
    date_birth = (request.form.get("date_birth") or "").strip()
    # NORMALISASI DATA OPSIONAL
    phone_db = phone_number if phone_number else None
    dob_db = date_birth if date_birth else None

    if not employee_id or not full_name:
        flash("Employee ID dan Full Name wajib diisi.", "danger")
        return redirect(url_for("access_control"))

    allowed_roles = {"owner","superadmin","manager","admin","staff","hr","finance"}
    if role not in allowed_roles:
        flash("Role tidak valid.", "danger")
        return redirect(url_for("access_control"))

    temp_password = generate_temp_password(10)
    password_hash = generate_password_hash(temp_password)

    connection = get_db_connection()
    if not connection:
        flash("Gagal konek ke database.", "danger")
        return redirect(url_for("access_control"))

    cursor = connection.cursor()
    try:
        # employee_id harus unik
        cursor.execute("SELECT id FROM portal_users WHERE employee_id=%s LIMIT 1", (employee_id,))
        if cursor.fetchone():
            flash("Employee ID sudah digunakan. Pakai ID lain.", "danger")
            return redirect(url_for("access_control"))

        cursor.execute(
            """
            INSERT INTO portal_users (employee_id, full_name, email, phone_number, date_birth, password_hash, role, is_active)
            VALUES (%s, %s, %s, %s, %s, %s, %s, 1)
            """,
            (employee_id, full_name, email or None, phone_db, dob_db, password_hash, role)
        )
        connection.commit()
        log_audit(action="create_user", status="success", target_type="portal_user", target_id=employee_id, details=f"role={role}")
        # simpan 1x tampilan password (owner copy lalu kirim manual)
        session["one_time_password"] = {
            "mode": "create",
            "employee_id": employee_id,
            "full_name": full_name,
            "role": role,
            "temp_password": temp_password
        }

        log_user_activity("access_control:create_user", {
            "employee_id": employee_id,
            "role": role
        })

        flash("User berhasil dibuat. Password sementara ditampilkan 1x.", "success")
    except Error as e:
        connection.rollback()
        print("Error create user:", e)
        log_audit(action="create_user", status="failed", target_type="portal_user", target_id=employee_id or "-", details=f"db_error:{str(e)[:120]}")
        flash("Gagal membuat user.", "danger")
    finally:
        cursor.close()
        connection.close()

    return redirect(url_for("access_control"))
# ------------------
# TOGGLE ACTIVE USER
# ------------------
@app.route("/access-control/toggle-active", methods=["POST"])
@require_owner_or_superadmin
def access_control_toggle_active():
    user_id = (request.form.get("user_id") or "").strip()
    next_state = (request.form.get("next_state") or "").strip()  # "0" atau "1"

    if not user_id.isdigit() or next_state not in ("0", "1"):
        flash("Request tidak valid.", "danger")
        return redirect(url_for("access_control"))

    # optional: jangan biarkan owner menonaktifkan dirinya sendiri
    if int(user_id) == int(session.get("user_id", -1)) and next_state == "0":
        flash("Tidak bisa menonaktifkan akun yang sedang login.", "danger")
        return redirect(url_for("access_control"))

    connection = get_db_connection()
    if not connection:
        flash("Gagal konek ke database.", "danger")
        return redirect(url_for("access_control"))

    cursor = connection.cursor()
    try:
        cursor.execute(
            "UPDATE portal_users SET is_active=%s WHERE id=%s LIMIT 1",
            (int(next_state), int(user_id))
        )
        connection.commit()
        log_audit(action="toggle_user_active", status="success", target_type="portal_user", target_id=int(user_id), details=f"is_active={int(next_state)}")
        log_user_activity("access_control:toggle_active", {
            "user_id": int(user_id),
            "is_active": int(next_state)
        })

        flash("Status user berhasil diperbarui.", "success")
    except Error as e:
        connection.rollback()
        print("Error toggle active:", e)
        log_audit(action="toggle_user_active", status="failed", target_type="portal_user", target_id=int(user_id) if user_id.isdigit() else user_id, details=f"db_error:{str(e)[:120]}")
        flash("Gagal update status user.", "danger")
    finally:
        cursor.close()
        connection.close()

    return redirect(url_for("access_control"))
# -----------------
# UPDATE ROLE USER
#------------------
@app.route("/access-control/update-role", methods=["POST"])
@require_owner_or_superadmin
def access_control_update_role():
    user_id = (request.form.get("user_id") or "").strip()
    new_role = (request.form.get("new_role") or "").strip()

    if not user_id.isdigit():
        flash("User ID tidak valid.", "danger")
        return redirect(url_for("access_control"))

    allowed_roles = {"owner","superadmin","manager","admin","staff","hr","finance"}
    if new_role not in allowed_roles:
        flash("Role tidak valid.", "danger")
        return redirect(url_for("access_control"))

    connection = get_db_connection()
    if not connection:
        flash("Gagal konek ke database.", "danger")
        return redirect(url_for("access_control"))

    cursor = connection.cursor()
    try:
        cursor.execute(
            "UPDATE portal_users SET role=%s WHERE id=%s LIMIT 1",
            (new_role, int(user_id))
        )
        connection.commit()
        log_audit(action="update_role_status", status="success", target_type="portal_user", target_id=int(user_id), details=f"role={new_role}")
        log_user_activity("access_control:update_role", {
            "user_id": int(user_id),
            "new_role": new_role
        })

        flash("Role user berhasil diupdate.", "success")
    except Error as e:
        connection.rollback()
        print("Error update role:", e)
        log_audit(action="update_role_status", status="failed", target_type="portal_user", target_id=int(user_id) if user_id.isdigit() else user_id, details=f"db_error:{str(e)[:120]}")
        flash("Gagal update role.", "danger")
    finally:
        cursor.close()
        connection.close()

    return redirect(url_for("access_control"))
# --------------------
# RESET PASSWORD USER
#---------------------
@app.route("/access-control/reset-password", methods=["POST"])
@require_owner_or_superadmin
def access_control_reset_password():
    user_id = (request.form.get("user_id") or "").strip()
    if not user_id.isdigit():
        flash("User ID tidak valid.", "danger")
        return redirect(url_for("access_control"))

    temp_password = generate_temp_password(10)
    password_hash = generate_password_hash(temp_password)

    connection = get_db_connection()
    if not connection:
        flash("Gagal konek ke database.", "danger")
        return redirect(url_for("access_control"))

    cursor = connection.cursor(dictionary=True)
    try:
        cursor.execute("SELECT employee_id, full_name, role FROM portal_users WHERE id=%s LIMIT 1", (int(user_id),))
        u = cursor.fetchone()
        if not u:
            flash("User tidak ditemukan.", "danger")
            return redirect(url_for("access_control"))

        cursor2 = connection.cursor()
        cursor2.execute(
            "UPDATE portal_users SET password_hash=%s WHERE id=%s LIMIT 1",
            (password_hash, int(user_id))
        )
        connection.commit()
        log_audit(action="reset_password", status="success", target_type="portal_user", target_id=int(user_id), details=f"employee_id={u['employee_id']}")
        session["one_time_password"] = {
            "mode": "reset",
            "employee_id": u["employee_id"],
            "full_name": u["full_name"],
            "role": u["role"],
            "temp_password": temp_password
        }

        log_user_activity("access_control:reset_password", {
            "user_id": int(user_id),
            "employee_id": u["employee_id"]
        })

        flash("Password berhasil di-reset. Password sementara ditampilkan 1x.", "success")
    except Error as e:
        connection.rollback()
        print("Error reset password:", e)
        log_audit(action="reset_password", status="failed", target_type="portal_user", target_id=int(user_id) if user_id.isdigit() else user_id, details=f"db_error:{str(e)[:120]}")
        flash("Gagal reset password.", "danger")
    finally:
        try:
            cursor2.close()
        except Exception:
            pass
        cursor.close()
        connection.close()

    return redirect(url_for("access_control"))
# --------------------
# UPDATE USER PROFILE
#---------------------
@app.route("/access-control/update-user", methods=["POST"])
@require_owner_or_superadmin
def access_control_update_user():
    user_id = (request.form.get("user_id") or "").strip()
    employee_id = (request.form.get("employee_id") or "").strip()
    full_name = (request.form.get("full_name") or "").strip()
    email = (request.form.get("email") or "").strip()
    phone_number = (request.form.get("phone_number") or "").strip()
    date_birth = (request.form.get("date_birth") or "").strip()  # format: YYYY-MM-DD

    if not user_id.isdigit():
        flash("User ID tidak valid.", "danger")
        return redirect(url_for("access_control"))

    if not employee_id or not full_name:
        flash("Employee ID dan Full Name wajib diisi.", "danger")
        return redirect(url_for("access_control"))

    # normalisasi optional
    email_db = email if email else None
    phone_db = phone_number if phone_number else None
    dob_db = date_birth if date_birth else None  # MySQL DATE

    connection = get_db_connection()
    if not connection:
        flash("Gagal konek ke database.", "danger")
        return redirect(url_for("access_control"))

    cursor = connection.cursor(dictionary=True)
    try:
        # cek user ada
        cursor.execute("SELECT id, employee_id FROM portal_users WHERE id=%s LIMIT 1", (int(user_id),))
        existing = cursor.fetchone()
        if not existing:
            flash("User tidak ditemukan.", "danger")
            return redirect(url_for("access_control"))

        # employee_id harus unik (kecuali milik user itu sendiri)
        cursor.execute(
            "SELECT id FROM portal_users WHERE employee_id=%s AND id<>%s LIMIT 1",
            (employee_id, int(user_id))
        )
        if cursor.fetchone():
            flash("Employee ID sudah digunakan user lain.", "danger")
            return redirect(url_for("access_control"))

        cur2 = connection.cursor()
        cur2.execute(
            """
            UPDATE portal_users
            SET employee_id=%s,
                full_name=%s,
                email=%s,
                phone_number=%s,
                date_birth=%s
            WHERE id=%s
            LIMIT 1
            """,
            (employee_id, full_name, email_db, phone_db, dob_db, int(user_id))
        )
        connection.commit()
        log_audit(action="update_user_profile", status="success", target_type="portal_user", target_id=int(user_id), details=f"employee_id={employee_id}")
        log_user_activity("access_control:update_user", {
            "user_id": int(user_id),
            "employee_id": employee_id
        })

        flash("Profil user berhasil diupdate.", "success")
    except Error as e:
        connection.rollback()
        print("Error update user:", e)
        log_audit(action="update_user_profile", status="failed", target_type="portal_user", target_id=int(user_id) if user_id.isdigit() else user_id, details=f"db_error:{str(e)[:120]}")
        flash("Gagal update user.", "danger")
    finally:
        try:
            cur2.close()
        except Exception:
            pass
        cursor.close()
        connection.close()

        log_audit(action="view_access_control", status="success", target_type="page", target_id="access-control")

    return redirect(url_for("access_control"))

#=================================
# SECURITY DASHBOARD / AUDIT LOGS
#=================================
@app.route("/security-dashboard", methods=["GET"])
@require_owner_or_superadmin
def security_dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if session.get("role") not in ("owner", "manager", "admin"):
        flash("Akses hanya untuk Owner / Management.", "danger")
        return redirect(url_for("login"))

    conn = get_db_connection()
    if not conn:
        flash("Gagal konek ke database. Cek XAMPP / konfigurasi DB.", "danger")
        return render_template(
            "security_dashboard.html",
            active_menu="security",
            full_name=session.get("full_name"),
            role=session.get("role"),
            users=[],
            action_options=[],
            logs=[],
            q_user_id="",
            q_action="",
            q_status="",
            q_date_from="",
            q_date_to="",
        )

    cur = conn.cursor(dictionary=True)

    # filter input (support nama lama juga)
    q_user_id = (request.args.get("user_id") or "").strip()
    q_action = (request.args.get("action") or "").strip()
    q_status = (request.args.get("status") or "").strip()

    q_date_from = (request.args.get("date_from") or request.args.get("from") or "").strip()
    q_date_to = (request.args.get("date_to") or request.args.get("to") or "").strip()

    # dropdown user
    cur.execute("SELECT id, employee_id, full_name FROM portal_users ORDER BY full_name ASC")
    users = cur.fetchall() or []

    # dropdown action
    cur.execute("SELECT DISTINCT action FROM audit_logs ORDER BY action ASC")
    action_options = [r["action"] for r in (cur.fetchall() or []) if r.get("action")]

    sql = """
        SELECT
          al.id, al.created_at,
          al.actor_employee_id AS employee_id,
          al.actor_full_name   AS full_name,
          al.actor_role        AS role,
          al.action, al.status,
          al.target_type, al.target_id,
          al.details, al.ip_address
        FROM audit_logs al
        WHERE 1=1
    """
    params = []

    if q_user_id:
        sql += " AND al.actor_user_id = %s "
        params.append(q_user_id)

    if q_action:
        sql += " AND al.action = %s "
        params.append(q_action)

    if q_status:
        sql += " AND al.status = %s "
        params.append(q_status)

    if q_date_from:
        sql += " AND DATE(al.created_at) >= %s "
        params.append(q_date_from)

    if q_date_to:
        sql += " AND DATE(al.created_at) <= %s "
        params.append(q_date_to)

    sql += " ORDER BY al.created_at DESC LIMIT 400 "

    cur.execute(sql, params)
    logs = cur.fetchall() or []

    cur.close()
    conn.close()

    # catat kunjungan halaman audit (non-blocking)
    try:
        log_audit("visit_security_dashboard", target_type="page", target_id="security-dashboard")
    except Exception:
        pass

    return render_template(
        "security_dashboard.html",
        active_menu="security",
        full_name=session.get("full_name"),
        role=session.get("role"),
        users=users,
        action_options=action_options,
        logs=logs,
        q_user_id=q_user_id,
        q_action=q_action,
        q_status=q_status,
        q_date_from=q_date_from,
        q_date_to=q_date_to,
    )

# ============================================================
# COMING SOON (universal placeholder for owner executive menu)
# ============================================================
@app.route("/coming-soon/<feature>")
def coming_soon(feature):
    if "user_id" not in session:
        return redirect(url_for("login"))
    if session.get("role") != "owner":
        flash("Akses ditolak. Hanya Owner.", "danger")
        return redirect(url_for("owner_dashboard"))

    labels = {
        "approvals": "Approvals",
        "finance": "Finance Overview",
        "inventory": "Inventory Watch",
        "announcements": "Announcements",
        "my_profile": "My Profile",
    }
    label = labels.get(feature, feature.title())
    flash(f"{label} (Coming Soon).", "info")
    return redirect(request.referrer or url_for("owner_dashboard"))
# ------------------------------------------------
# COMING SOON (Owner Executive Menu placeholders)
# ------------------------------------------------
@app.route("/owner-dashboard/approvals")
def owner_approvals_soon():
    return redirect(url_for("coming_soon", feature="approvals"))
@app.route("/owner-dashboard/finance")
def owner_finance_soon():
    return redirect(url_for("coming_soon", feature="finance"))
@app.route("/owner-dashboard/inventory")
def owner_inventory_soon():
    return redirect(url_for("coming_soon", feature="inventory"))
@app.route("/owner-dashboard/announcements")
def owner_announcements_soon():
    return redirect(url_for("coming_soon", feature="announcements"))

# =============
# ENTRY POINT
# =============
if __name__ == "__main__":
    app.run(debug=True)
