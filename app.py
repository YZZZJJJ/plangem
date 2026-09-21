from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3, os, uuid
from datetime import datetime, date, timedelta
import mimetypes  # 记得在文件顶部导入

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, "app.db")
UPLOAD_DIR = os.path.join(BASE, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-key")
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024
ALLOWED = {"png","jpg","jpeg","gif","webp","pdf","doc","docx","xls","xlsx","ppt","pptx","txt","zip"}

def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    con = db()
    con.executescript("""
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS plans(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      description TEXT DEFAULT '',
      start_date TEXT NOT NULL,
      interval_days INTEGER NOT NULL DEFAULT 1,
      end_date TEXT,
      created_at TEXT NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS checkins(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      plan_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      checkin_date TEXT NOT NULL,
      note TEXT DEFAULT '',
      file_name TEXT,
      stored_name TEXT,
      created_at TEXT NOT NULL,
      UNIQUE(plan_id, checkin_date),
      FOREIGN KEY(plan_id) REFERENCES plans(id),
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS follows(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      follower_id INTEGER NOT NULL,
      following_id INTEGER NOT NULL,
      UNIQUE(follower_id, following_id)
    );
    CREATE TABLE IF NOT EXISTS comments(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      plan_id INTEGER NOT NULL,
      checkin_id INTEGER,  --  新增：关联具体的打卡记录
      user_id INTEGER NOT NULL,
      content TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS nudges(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      plan_id INTEGER NOT NULL,
      from_user_id INTEGER NOT NULL,
      to_user_id INTEGER NOT NULL,
      created_at TEXT NOT NULL
    );
    """)
    con.commit()
    con.close()

def current_user():
    if "uid" not in session:
        return None
    con = db()
    u = con.execute("SELECT * FROM users WHERE id=?", (session["uid"],)).fetchone()
    con.close()

    if not u:
        session.pop("uid", None)
        return None
    return u

def login_required():
    return "uid" in session

def valid_file(name):
    return "." in name and name.rsplit(".",1)[1].lower() in ALLOWED

@app.context_processor
def inject():
    return {"me": current_user(), "today": date.today().isoformat()}

@app.after_request
def add_header(response):
    # 禁止所有浏览器（尤其是微信）缓存动态页面
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response

@app.route("/")
def index():
    return redirect(url_for("home") if login_required() else url_for("login"))

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        user_id = request.form.get("user_id","").strip()
        password = request.form.get("password","")
        con = db()
        u = con.execute("SELECT * FROM users WHERE user_id=?", (user_id,)).fetchone()
        con.close()
        if u and check_password_hash(u["password_hash"], password):
            session["uid"] = u["id"]
            return redirect(url_for("home"))
        flash("ID或密码错误")
    return render_template("login.html")

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        user_id = request.form.get("user_id","").strip()
        password = request.form.get("password","")
        if len(user_id) < 3 or len(user_id) > 24 or not user_id.replace("_","").isalnum():
            flash("ID需为3-24位字母、数字或下划线")
            return render_template("register.html")
        if len(password) < 6:
            flash("密码至少6位")
            return render_template("register.html")
        con = db()
        try:
            con.execute("INSERT INTO users(user_id,password_hash,created_at) VALUES(?,?,?)",
                        (user_id, generate_password_hash(password), datetime.now().isoformat()))
            con.commit()
            flash("注册成功，请登录")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("该ID已被使用，请换一个")
        finally:
            con.close()
    return render_template("register.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/home")
def home():
    if not login_required(): return redirect(url_for("login"))
    con = db()
    plans = con.execute("SELECT * FROM plans WHERE user_id=? ORDER BY start_date DESC, id DESC",
                        (session["uid"],)).fetchall()
    counts = {}
    for p in plans:
        counts[p["id"]] = con.execute("SELECT COUNT(*) c FROM checkins WHERE plan_id=?", (p["id"],)).fetchone()["c"]
    con.close()
    return render_template("home.html", plans=plans, counts=counts)

@app.route("/plan/new", methods=["GET","POST"])
def new_plan():
    if not login_required(): return redirect(url_for("login"))
    if request.method == "POST":
        title = request.form.get("title","").strip()
        desc = request.form.get("description","").strip()
        start = request.form.get("start_date","")
        interval = int(request.form.get("interval_days","1") or 1)
        end = request.form.get("end_date","") or None
        if not title or not start or interval < 1:
            flash("请完整填写计划信息")
            return render_template("plan_form.html")
        con = db()
        con.execute("""INSERT INTO plans(user_id,title,description,start_date,interval_days,end_date,created_at)
                       VALUES(?,?,?,?,?,?,?)""",
                    (session["uid"],title,desc,start,interval,end,datetime.now().isoformat()))
        con.commit(); con.close()
        return redirect(url_for("home"))
    return render_template("plan_form.html")

@app.route("/plan/<int:plan_id>")
def plan_detail(plan_id):
    if not login_required(): return redirect(url_for("login"))
    con = db()
    
    # 核心修复：给 u.user_id 起别名 AS creator_name，避免覆盖 p.user_id
    p = con.execute("""SELECT p.*, u.user_id AS creator_name FROM plans p JOIN users u ON p.user_id=u.id WHERE p.id=?""",
                    (plan_id,)).fetchone()
    if not p:
        con.close(); return "Not found",404
        
    checkins = con.execute("SELECT * FROM checkins WHERE plan_id=? ORDER BY checkin_date DESC", (plan_id,)).fetchall()
    
    # 同样的修复：给评论的用户名起别名 AS commenter_name
    comments = con.execute("""SELECT c.*, u.user_id AS commenter_name FROM comments c JOIN users u ON c.user_id=u.id
                              WHERE c.plan_id=? ORDER BY c.created_at DESC""",(plan_id,)).fetchall()
    con.close()
    
    return render_template("plan_detail.html", plan=p, checkins=checkins, comments=comments)

@app.route("/plan/<int:plan_id>/checkin", methods=["POST"])
def checkin(plan_id):
    if not login_required(): return redirect(url_for("login"))
    con = db()
    p = con.execute("SELECT * FROM plans WHERE id=?", (plan_id,)).fetchone()
    if not p:
        con.close(); return "Not found",404
    # Owner or followed users may view, but only owner can check in.
    if p["user_id"] != session["uid"]:
        con.close(); flash("只有计划创建者可以打卡"); return redirect(url_for("plan_detail",plan_id=plan_id))
    d = request.form.get("checkin_date") or date.today().isoformat()
    note = request.form.get("note","").strip()
    f = request.files.get("file")
    original = stored = None
    if f and f.filename:
        if not valid_file(f.filename):
            con.close(); flash("不支持的文件类型"); return redirect(url_for("plan_detail",plan_id=plan_id))
        original = secure_filename(f.filename)
        stored = f"{uuid.uuid4().hex}_{original}"
        f.save(os.path.join(UPLOAD_DIR, stored))
    try:
        con.execute("""INSERT INTO checkins(plan_id,user_id,checkin_date,note,file_name,stored_name,created_at)
                       VALUES(?,?,?,?,?,?,?)""",
                    (plan_id,session["uid"],d,note,original,stored,datetime.now().isoformat()))
        con.commit()
        flash("打卡成功")
    except sqlite3.IntegrityError:
        flash("这一天已经打卡")
    con.close()
    return redirect(url_for("plan_detail",plan_id=plan_id))


@app.route("/files/<path:name>")
def files(name):
    if not login_required(): return redirect(url_for("login"))
    # 猜测文件 MIME 类型
    mimetype, _ = mimetypes.guess_type(name)
    # 如果是图片，直接在浏览器内联显示（即预览大图）；其他文件依然作为附件下载
    as_attachment = not (mimetype and mimetype.startswith('image/'))
    return send_from_directory(UPLOAD_DIR, name, as_attachment=as_attachment)

@app.route("/plan/<int:plan_id>/comment", methods=["POST"])
def comment(plan_id):
    if not login_required(): return redirect(url_for("login"))
    content = request.form.get("content","").strip()
    checkin_id = request.form.get("checkin_id", type=int)  #  接收打卡ID
    if content:
        con=db()
        p=con.execute("SELECT id FROM plans WHERE id=?",(plan_id,)).fetchone()
        if p:
            con.execute("""INSERT INTO comments(plan_id, checkin_id, user_id, content, created_at) 
                           VALUES(?,?,?,?,?)""",
                        (plan_id, checkin_id, session["uid"], content, datetime.now().strftime("%Y-%m-%d %H:%M"))) #  精确到分钟
            con.commit()
        con.close()
    return redirect(request.referrer or url_for("plan_detail",plan_id=plan_id))

@app.route("/follow", methods=["POST"])
def follow():
    if not login_required(): return redirect(url_for("login"))
    target = request.form.get("user_id","").strip()
    con=db()
    u=con.execute("SELECT * FROM users WHERE user_id=?",(target,)).fetchone()
    if not u:
        flash("没有找到这个用户")
    elif u["id"] == session["uid"]:
        flash("不能关注自己")
    else:
        try:
            con.execute("INSERT INTO follows(follower_id,following_id) VALUES(?,?)",(session["uid"],u["id"]))
            con.commit()
            flash("已关注")
        except sqlite3.IntegrityError:
            flash("已经关注")
    con.close()
    return redirect(request.referrer or url_for("following"))

@app.route("/unfollow", methods=["POST"])
def unfollow():
    if not login_required(): return redirect(url_for("login"))
    con=db()
    con.execute("DELETE FROM follows WHERE follower_id=? AND following_id=?",(session["uid"],request.form["target_id"]))
    con.commit(); con.close()
    return redirect(request.referrer or url_for("following"))

@app.route("/following")
def following():
    if not login_required(): return redirect(url_for("login"))
    q = request.args.get("q","").strip()
    con = db()
    
    # 获取我关注的所有用户
    followed = con.execute("""SELECT u.id, u.user_id FROM follows f 
                              JOIN users u ON f.following_id = u.id
                              WHERE f.follower_id = ? ORDER BY u.user_id""", (session["uid"],)).fetchall()
    
    # 提取已关注用户的 id 列表，传给前端
    followed_ids = [f["id"] for f in followed]
    
    selected = None
    plans = []
    comments = []
    feed = []
    
    if q:
        # ========== 模式1：搜索或点击了 @xxx 链接，查看特定用户 ==========
        selected = con.execute("SELECT id, user_id FROM users WHERE user_id=?", (q,)).fetchone()
        if selected:
            plans = con.execute("""SELECT p.*, u.user_id AS creator_name FROM plans p 
                                   JOIN users u ON p.user_id = u.id 
                                   WHERE p.user_id=? ORDER BY p.start_date DESC""", (selected["id"],)).fetchall()
            for p in plans:
                comments += list(con.execute("""SELECT c.*, u.user_id AS commenter_name FROM comments c 
                                                JOIN users u ON c.user_id = u.id
                                                WHERE c.plan_id=? ORDER BY c.created_at DESC""", (p["id"],)).fetchall())
    else:
        # ========== 模式2：关注动态（时间线帖子流） ==========
        # ⭐ 注意：以下所有代码都必须缩进在 else 下面！
        feed_items = con.execute("""
            SELECT c.id, c.checkin_date, c.note, c.file_name, c.stored_name, c.created_at,
                   u.user_id AS creator_name, p.title AS plan_title, p.id AS plan_id
            FROM checkins c
            JOIN plans p ON c.plan_id = p.id
            JOIN users u ON p.user_id = u.id
            WHERE p.user_id IN (SELECT following_id FROM follows WHERE follower_id = ?)
            ORDER BY c.created_at DESC
        """, (session["uid"],)).fetchall()
        
        feed = []
        for item in feed_items:
            item_dict = dict(item)
            # 查询该打卡记录对应的评论
            item_dict['comments'] = con.execute("""
                SELECT c.*, u.user_id AS commenter_name 
                FROM comments c JOIN users u ON c.user_id = u.id
                WHERE c.checkin_id = ? ORDER BY c.created_at ASC
            """, (item['id'],)).fetchall()
            feed.append(item_dict)
        
    con.close()
    # ⭐ 这里也是平级的，不能被包进 else 里面
    return render_template("following.html", followed=followed, followed_ids=followed_ids, selected=selected, plans=plans, comments=comments, feed=feed, q=q)
@app.route("/nudge/<int:plan_id>", methods=["POST"])
def nudge(plan_id):
    if not login_required(): return redirect(url_for("login"))
    con=db()
    p=con.execute("SELECT * FROM plans WHERE id=?",(plan_id,)).fetchone()
    if p and p["user_id"] != session["uid"]:
        con.execute("INSERT INTO nudges(plan_id,from_user_id,to_user_id,created_at) VALUES(?,?,?,?)",
                    (plan_id,session["uid"],p["user_id"],datetime.now().isoformat()))
        con.commit(); flash("已发送催促")
    con.close()
    return render_template("following.html", followed=followed, followed_ids=followed_ids, selected=selected, plans=plans, comments=comments, feed=feed, q=q)

def due_on(p, d):
    start = date.fromisoformat(p["start_date"])
    if isinstance(d, date):
        target = d
    else:
        target = date.fromisoformat(d)
    if target < start:
        return False
    if p["end_date"] and target > date.fromisoformat(p["end_date"]):
        return False
    return ((target - start).days % p["interval_days"]) == 0

@app.route("/calendar")
def calendar():
    if not login_required(): return redirect(url_for("login"))
    month=request.args.get("month", date.today().strftime("%Y-%m"))
    try:
        y,m=map(int,month.split("-"))
        first=date(y,m,1)
    except:
        first=date.today().replace(day=1); y,m=first.year,first.month
    import calendar as cal
    days=cal.monthrange(y,m)[1]
    con=db()
    plans=con.execute("SELECT * FROM plans WHERE user_id=?",(session["uid"],)).fetchall()
    checks=con.execute("""SELECT c.checkin_date,c.plan_id FROM checkins c JOIN plans p ON c.plan_id=p.id
                          WHERE p.user_id=? AND c.checkin_date BETWEEN ? AND ?""",
                      (session["uid"],first.isoformat(),date(y,m,days).isoformat())).fetchall()
    con.close()
    checked={(r["checkin_date"],r["plan_id"]) for r in checks}
    cells=[]
    for i in range(first.weekday()):
        cells.append(None)
    for n in range(1,days+1):
        d=date(y,m,n)
        due=[{"id":p["id"],"title":p["title"],"done":(d.isoformat(),p["id"]) in checked}
             for p in plans if due_on(p,d)]
        cells.append({"date":d.isoformat(),"day":n,"due":due})
    while len(cells)%7: cells.append(None)
    prev=(first-timedelta(days=1)).strftime("%Y-%m")
    nxt=(first+timedelta(days=32)).replace(day=1).strftime("%Y-%m")
    return render_template("calendar.html", cells=cells, month=f"{y}年{m}月", prev=prev, nxt=nxt)

init_db()
if __name__ == "__main__":
    app.run(debug=True)
