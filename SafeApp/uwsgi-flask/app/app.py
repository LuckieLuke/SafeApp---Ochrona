from math import log2
from Crypto.Cipher import AES
from Crypto import Random
import base64
from flask import Flask, render_template, make_response, request, redirect
from flask import url_for, session, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import hashlib
import logging
import uuid
import os
import re
from jwt import encode, decode, InvalidTokenError
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__, static_url_path='')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'app/files/'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

app.permanent_session_lifetime = timedelta(minutes=10)
app.config['SESSION_COOKIE_SECURE'] = True
db = SQLAlchemy(app)
csrf = CSRFProtect(app)
log = app.logger
JWT_SECRET = os.environ.get('JWT_SECRET')
DEFAULT_CSP = os.environ.get('DEFAULT_CSP')


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(128), nullable=False)
    notes = db.relationship('Note', backref='author', lazy=True)
    hosts = db.relationship('Host', backref='ip_address', lazy=True)
    key = db.Column(db.String(16), nullable=False)
    salt = db.Column(db.String(16), nullable=False)

    def __init__(self, username, email, password, key, salt):
        self.username = username
        self.email = email
        self.password = password
        self.key = key
        self.salt = salt

    def __repr__(self):
        return self.username


class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(40), nullable=False)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(10), nullable=False)
    colab = db.Column(db.String(20), nullable=True)
    password = db.Column(db.String(128), nullable=True)
    note_type = db.Column(db.String(4), nullable=False)
    filename = db.Column(db.String(100), nullable=True)

    def __init__(self, title, content, user_id, status, note_type,
                 colab=None, password=None, filename=None):
        self.title = title
        self.content = content
        self.user_id = user_id
        self.status = status
        self.note_type = note_type
        self.colab = colab
        self.password = password
        self.filename = filename

    def __repr__(self):
        return f'Note("{self.title}")'

    def __eq__(self, other):
        if self.id == other.id:
            return True
        return False

    def __hash__(self):
        return self.id


class Host(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(15), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __init__(self, ip, user_id):
        self.ip = ip
        self.user_id = user_id

    def __repr__(self):
        return self.ip


class BlackList(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(15), nullable=False)
    failed_logins = db.Column(db.Integer, nullable=False)
    blocked_until = db.Column(db.DateTime, nullable=True)

    def __init__(self, ip, failed_logins, blocked_until=None):
        self.ip = ip
        self.failed_logins = failed_logins
        self.blocked_until = blocked_until


@ app.route('/')
def home():
    isLogged = False
    hacked = False
    if 'user' in session and session['user'] == 'adminplzdonthackme':
        hacked = True
    elif 'user' in session:
        isLogged = True
        is_new = request.args.get('new')
        if is_new == 'True':
            flash(
                f'New host ({request.remote_addr}) has logged in!'
            )
    resp = make_response(render_template(
        'index.html', logged=isLogged, hacked=hacked))
    if hacked:
        session.clear()
        resp.set_cookie('access_token', 'INVALID', max_age=-
                        1, httponly=True, secure=True)
    resp.headers['Server'] = 'cheater'
    resp.headers['Content-Security-Policy'] = DEFAULT_CSP
    return resp


@ app.route('/login', methods=['GET', 'POST'])
def login(msg=None):
    if 'user' in session:
        return redirect(url_for('home'))

    if request.method == 'GET':
        resp = make_response(render_template('login.html', msg=msg))
        resp.headers['Server'] = 'cheater'
        resp.headers['Content-Security-Policy'] = DEFAULT_CSP
        return resp
    elif request.method == 'POST':
        start = datetime.now()

        if is_blocked(request):
            resp = make_response(render_template(
                'login.html',
                msg='Logging limit reached! Wait a minute to try again.'
            ))
            resp.headers['Server'] = 'cheater'
            resp.headers['Content-Security-Policy'] = DEFAULT_CSP

            return resp

        form = request.form
        username = form['username']

        if not re.match(r'[a-zA-Z0-9]{5,}', username):
            while start + timedelta(seconds=1) > datetime.now():
                pass
            update_blacklist(request, False)
            return make_logger_cookie(request)

        password = form['password']
        user = User.query.filter_by(username=username).first()

        if not user:
            while start + timedelta(seconds=1) > datetime.now():
                pass
            update_blacklist(request, False)
            return make_logger_cookie(request)

        hashed = hashlib.sha512(
            (password + user.salt).encode('utf-8')).hexdigest()

        if user.password == hashed:
            session['user'] = username
            session['uid'] = user.id
            session.permanent = True
            update_blacklist(request, True)

            hosts = list(Host.query.filter_by(user_id=session['uid']).all())
            for i in range(len(hosts)):
                hosts[i] = str(hosts[i])

            if request.remote_addr not in hosts:
                host = Host(ip=request.remote_addr, user_id=user.id)
                db.session.add(host)
                db.session.commit()
                resp = make_response(redirect(url_for('home', new=True)))
                resp.headers['Server'] = 'cheater'
            else:
                resp = make_response(redirect(url_for('home')))
                resp.headers['Server'] = 'cheater'
            resp.headers['Content-Security-Policy'] = DEFAULT_CSP

            exp = datetime.now() + timedelta(seconds=600)
            access_token = encode(
                {'uname': session['user'], 'exp': exp}, JWT_SECRET, 'HS256')
            resp.set_cookie('access_token', access_token,
                            max_age=600, httponly=True, secure=True)
            resp.set_cookie('logger', 'INVALID', max_age=-
                            1, httponly=True, secure=True)
        else:
            while start + timedelta(seconds=1) > datetime.now():
                pass
            update_blacklist(request, False)
            resp = make_logger_cookie(request)

        if user.password == hashed:
            while start + timedelta(seconds=1) > datetime.now():
                pass

        return resp


@ app.route('/register', methods=['GET', 'POST'])
def register(msg=None):
    token = request.cookies.get('access_token')
    if 'user' in session or valid(token):
        resp = make_response(redirect(url_for('home')))
        resp.headers['Server'] = 'cheater'
        resp.headers['Content-Security-Policy'] = DEFAULT_CSP

        return resp
    if request.method == 'GET':
        resp = make_response(render_template('register.html', msg=msg))
        resp.headers['Server'] = 'cheater'
        resp.headers['Content-Security-Policy'] = DEFAULT_CSP

        return resp
    elif request.method == 'POST':
        start = datetime.now()
        form = request.form
        if entropy(form['password']) < 3:
            resp = make_response(render_template(
                'register.html', msg='Password too weak! Try again with \
                something stronger.'))
            resp.headers['Server'] = 'cheater'
            resp.headers['Content-Security-Policy'] = DEFAULT_CSP
            return resp
        elif form['password'] != form['repeatPassword']:
            resp = make_response(render_template(
                'register.html', msg="Password's need to be the same!"))
            resp.headers['Server'] = 'cheater'
            resp.headers['Content-Security-Policy'] = DEFAULT_CSP
            return resp

        password = form['password']
        salt = uuid.uuid4().hex[0:16]
        hashed = hashlib.sha512((password + salt).encode('utf-8')).hexdigest()
        key = uuid.uuid4().hex[0:16]

        user = User(username=form['username'], email=form['email'],
                    password=hashed, key=key, salt=salt)

        db.session.add(user)
        db.session.commit()

        while start + timedelta(seconds=1) > datetime.now():
            pass

        session['user'] = form['username']
        session['uid'] = user.id
        session.permanent = True

        host = Host(ip=request.remote_addr, user_id=user.id)
        saved_hosts = Host.query.filter_by(user_id=user.id).all()
        if host not in saved_hosts:
            db.session.add(host)
            db.session.commit()
            resp = make_response(redirect(url_for('home', new=True)))
            resp.headers['Server'] = 'cheater'
            resp.headers['Content-Security-Policy'] = DEFAULT_CSP
        else:
            resp = make_response(redirect(url_for('home')))
            resp.headers['Server'] = 'cheater'
            resp.headers['Content-Security-Policy'] = DEFAULT_CSP

        exp = datetime.now() + timedelta(seconds=600)
        access_token = encode(
            {'uname': session['user'], 'exp': exp}, JWT_SECRET, 'HS256')
        resp.set_cookie('access_token', access_token,
                        max_age=600, httponly=True, secure=True)

        return resp


@app.route('/logout')
def logout():
    session.clear()
    resp = make_response(redirect(url_for('home')))
    resp.set_cookie('access_token', 'INVALID', max_age=-1)
    resp.headers['Server'] = 'cheater'
    resp.headers['Content-Security-Policy'] = DEFAULT_CSP
    return resp


@app.route('/addnote', methods=['GET', 'POST'])
def add_note():
    token = request.cookies.get('access_token')
    if 'user' not in session or not valid(token):
        resp = make_response(redirect(url_for('logout')))
        resp.headers['Server'] = 'cheater'
        resp.headers['Content-Security-Policy'] = DEFAULT_CSP
        return resp
    else:
        if request.method == 'GET':
            resp = make_response(render_template('addnote.html'))
            resp.headers['Server'] = 'cheater'
            resp.headers['Content-Security-Policy'] = DEFAULT_CSP
            return resp
        elif request.method == 'POST':
            form = request.form
            if form['visibility'] == 'shared':
                collaborator = User.query.filter_by(
                    username=form['username']).first()
                if collaborator:
                    note = Note(
                        title=form['title'],
                        content=form['content'],
                        user_id=session['uid'],
                        status=form['visibility'],
                        note_type='note',
                        colab=collaborator.username
                    )
                else:
                    note = Note(
                        title=form['title'],
                        content=form['content'],
                        user_id=session['uid'],
                        status='private',
                        note_type='note'
                    )
            elif form['visibility'] == 'protected':
                user = User.query.filter_by(username=session['user']).first()
                aes = AESCipher(user.key)
                password = form['password']
                salt = user.salt
                hashed = hashlib.sha512(
                    (password + salt).encode('utf-8')).hexdigest()
                note = Note(
                    title=form['title'],
                    content=aes.encrypt(form['content']),
                    user_id=session['uid'],
                    status=form['visibility'],
                    password=hashed,
                    note_type='note'
                )
            else:
                note = Note(
                    title=form['title'],
                    content=form['content'],
                    user_id=session['uid'],
                    status=form['visibility'],
                    note_type='note'
                )
            db.session.add(note)
            db.session.commit()

            resp = make_response(redirect(url_for('notes')))
            resp.headers['Server'] = 'cheater'
            resp.headers['Content-Security-Policy'] = DEFAULT_CSP
            return resp


@app.route('/notes')
def notes():
    token = request.cookies.get('access_token')
    if 'user' not in session or not valid(token):
        resp = make_response(redirect(url_for('logout')))
        resp.headers['Server'] = 'cheater'
        resp.headers['Content-Security-Policy'] = DEFAULT_CSP
        return resp
    my_notes = set(Note.query.filter_by(user_id=session['uid']).all())
    pub_notes = set(Note.query.filter_by(status='public').all())
    shared_notes = set(Note.query.filter_by(colab=session['user']).all())

    notes = list(my_notes | pub_notes | shared_notes)

    resp = make_response(render_template('notes.html', notes=notes))
    resp.headers['Server'] = 'cheater'
    resp.headers['Content-Security-Policy'] = DEFAULT_CSP
    return resp


@app.route('/show')
def show():
    token = request.cookies.get('access_token')
    if 'user' not in session or not valid(token):
        resp = make_response(redirect(url_for('logout')))
        resp.headers['Server'] = 'cheater'
        resp.headers['Content-Security-Policy'] = DEFAULT_CSP
        return resp

    id = request.args['id']
    if request.method == 'GET':
        id = int(id)
        note = Note.query.filter_by(id=id).first()

        if not (str(note.author) == session['user'] or
                (str(note.status) == 'shared' and
                 str(note.colab) == session['user']) or
                str(note.status) == 'public'):
            resp = make_response(redirect(url_for('home')))
            resp.headers['Server'] = 'cheater'
            resp.headers['Content-Security-Policy'] = DEFAULT_CSP
            return resp

        if str(note.status) != 'protected':
            resp = make_response(render_template('note.html', note=note))
            resp.headers['Location'] = '/show' + '?id=' + str(id)
            resp.headers['Server'] = 'cheater'
            resp.headers['Content-Security-Policy'] = DEFAULT_CSP
        else:
            resp = make_response(redirect(url_for('show_protected', id=id)))
            resp.headers['Content-Security-Policy'] = DEFAULT_CSP

    return resp


@app.route('/showfile')
def show_file():
    token = request.cookies.get('access_token')
    if 'user' not in session or not valid(token):
        resp = make_response(redirect(url_for('logout')))
        resp.headers['Server'] = 'cheater'
        resp.headers['Content-Security-Policy'] = DEFAULT_CSP
        return resp

    id = request.args['id']
    id = int(id)
    note = Note.query.filter_by(id=id).first()

    if not str(note.author) == session['user']:
        resp = make_response(redirect(url_for('home')))
        resp.headers['Server'] = 'cheater'
        resp.headers['Content-Security-Policy'] = DEFAULT_CSP
        return resp

    resp = make_response(send_from_directory(
        app.config['UPLOAD_FOLDER'], note.filename, as_attachment=False
    ))
    resp.headers['Server'] = 'cheater'
    resp.headers['Content-Security-Policy'] = DEFAULT_CSP

    return resp


@app.route('/unlock', methods=['GET', 'POST'])
def show_protected(msg=None):
    token = request.cookies.get('access_token')
    id = int(request.args['id']) or 0
    if 'user' not in session or not valid(token):
        resp = make_response(redirect(url_for('logout')))
        resp.headers['Server'] = 'cheater'
        resp.headers['Content-Security-Policy'] = DEFAULT_CSP
        return resp
    if request.method == 'GET':
        resp = make_response(render_template(
            'unlock.html', id=id))
        resp.headers['Server'] = 'cheater'
        resp.headers['Content-Security-Policy'] = DEFAULT_CSP
        return resp
    elif request.method == 'POST':
        start = datetime.now()
        note = Note.query.filter_by(id=id).first()
        user = User.query.filter_by(username=session['user']).first()
        password = request.form['password']
        salt = user.salt
        hashed = hashlib.sha512(
            (password + salt).encode('utf-8')).hexdigest()

        while start + timedelta(seconds=1) > datetime.now():
            pass

        if str(note.password) != hashed:
            resp = make_response(render_template(
                'unlock.html', msg='Wrong password!', id=id))
            resp.headers['Location'] = '/unlock?id=' + str(id)
            resp.headers['Server'] = 'cheater'
            resp.headers['Content-Security-Policy'] = DEFAULT_CSP
            return resp
        else:
            user = User.query.filter_by(username=session['user']).first()
            aes = AESCipher(str(user.key))
            note.content = aes.decrypt(note.content)
            resp = make_response(render_template(
                'note.html', note=note
            ))
            resp.headers['Server'] = 'cheater'
            resp.headers['Content-Security-Policy'] = DEFAULT_CSP
            return resp


@app.route('/changepassword', methods=['GET', 'POST'])
def change_password(msg=None):
    token = request.cookies.get('access_token')
    if 'user' not in session or not valid(token):
        resp = make_response(redirect(url_for('logout')))
        resp.headers['Server'] = 'cheater'
        resp.headers['Content-Security-Policy'] = DEFAULT_CSP
        return resp
    if request.method == 'GET':
        resp = make_response(render_template('changepassword.html', msg=msg))
        resp.headers['/Server'] = 'cheater'
        resp.headers['Content-Security-Policy'] = DEFAULT_CSP
        return resp
    elif request.method == 'POST':
        form = request.form
        username = session['user']
        user = User.query.filter_by(username=username).first()
        oldpassword = form['oldpassword']
        salt = user.salt
        newpassword = form['newpassword']
        hashed = hashlib.sha512(
            (oldpassword + salt).encode('utf-8')).hexdigest()
        if hashed != user.password or newpassword != form['repassword']:
            resp = make_response(render_template(
                'changepassword.html', msg='Wrong password'))
            resp.headers['/Server'] = 'cheater'
            resp.headers['Content-Security-Policy'] = DEFAULT_CSP
            return resp
        if entropy(newpassword) < 3:
            resp = make_response(render_template(
                'changepassword.html', msg='Your password is too weak!'))
            resp.headers['/Server'] = 'cheater'
            resp.headers['Content-Security-Policy'] = DEFAULT_CSP
            return resp
        user.password = hashlib.sha512(
            (newpassword + salt).encode('utf-8')).hexdigest()
        db.session.commit()
        resp = make_response(redirect(url_for('home')))
        resp.headers['/Server'] = 'cheater'
        resp.headers['Content-Security-Policy'] = DEFAULT_CSP
        return resp


@app.route('/addfile', methods=['GET', 'POST'])
def add_file():
    token = request.cookies.get('access_token')
    if 'user' not in session or not valid(token):
        resp = make_response(redirect(url_for('logout')))
        resp.headers['Server'] = 'cheater'
        resp.headers['Content-Security-Policy'] = DEFAULT_CSP
        return resp
    if request.method == 'GET':
        resp = make_response(render_template('addfile.html'))
        resp.headers['Server'] = 'cheater'
        resp.headers['Content-Security-Policy'] = DEFAULT_CSP
        return resp
    elif request.method == 'POST':
        if 'file' not in request.files:
            return redirect(request.url)
        note = request.files['file']
        if note.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if note and allowed_file(note.filename):
            filename = secure_filename(note.filename)
            note.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            note = Note(
                title=request.form['filename'],
                content='',
                user_id=session['uid'],
                status='private',
                note_type='file',
                filename=note.filename
            )

            db.session.add(note)
            db.session.commit()

            resp = make_response(redirect(url_for('notes')))
            resp.headers['Server'] = 'cheater'
            resp.headers['Content-Security-Policy'] = DEFAULT_CSP
            return resp


@app.route('/checklogin/<uname>')
def check_login(uname):
    user = User.query.filter_by(username=uname).first()
    if user is None:
        resp = make_response('Go ahead', 200)
    else:
        resp = make_response('Login taken!', 404)
    resp.headers['Server'] = 'cheater'
    resp.headers['Content-Security-Policy'] = DEFAULT_CSP
    return resp


@app.route('/email/<uname>')
def get_email(uname):
    user = User.query.filter_by(username=uname).first()
    if user is None:
        resp = make_response({'user': 'No user'}, 404)
    else:
        resp = make_response({'email': user.email}, 202)
    resp.headers['Server'] = 'cheater'
    resp.headers['Content-Security-Policy'] = DEFAULT_CSP
    return resp


@app.route('/hosts')
def hosts():
    hosts = list(Host.query.filter_by(user_id=session['uid']).all())
    for i in range(len(hosts)):
        hosts[i] = str(hosts[i])
    return {'hosts': hosts}, 200


def valid(token):
    try:
        decode(token, JWT_SECRET)
    except InvalidTokenError:
        return False
    return True


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def make_logger_cookie(request):
    resp = make_response(render_template(
        'login.html', msg='Invalid data! Try again.'))
    resp.headers['Server'] = 'cheater'
    resp.headers['Content-Security-Policy'] = DEFAULT_CSP

    if not request.cookies.get('logger'):
        exp = datetime.now() + timedelta(seconds=300)
        logger = encode(
            {'ip': request.remote_addr, 'exp': exp, 'tries': 1},
            JWT_SECRET, 'HS256'
        )
        resp.set_cookie('logger', logger,
                        max_age=300, httponly=True, secure=True)
    else:
        cookie = decode(request.cookies.get('logger'), JWT_SECRET)
        cookie['tries'] += 1
        cookie = encode(cookie, JWT_SECRET, 'HS256')
        resp.set_cookie('logger', cookie,
                        max_age=300, httponly=True, secure=True)

    return resp


def is_blocked(request):
    ip = request.remote_addr
    host = BlackList.query.filter_by(ip=ip).first()
    if host and host.blocked_until:
        if str(host.blocked_until) > str(datetime.now()):
            return True
    return False


def update_blacklist(request, isLogged):
    ip = request.remote_addr
    host = BlackList.query.filter_by(ip=ip).first()
    if host is None:
        host = BlackList(ip, 0)
    if isLogged or (host.blocked_until and not is_blocked(request)):
        host.failed_logins = 0
        host.blocked_until = None
    else:
        if host.failed_logins < 3:
            host.failed_logins += 1
        else:
            host.blocked_until = datetime.now() + timedelta(minutes=1)
    db.session.add(host)
    db.session.commit()
    return


if __name__ == '__main__':
    db.create_all()
    logging.basicConfig(filename="error.log", level=logging.DEBUG)
    app.run(debug=True)


########################################


class AESCipher(object):

    def __init__(self, key):
        self.bs = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode()))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return \
            self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * \
            chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]


########################################


def entropy(d):
    c = {}
    length = 0

    for letter in d:
        length += 1
        if letter in c:
            c[letter] += 1
        else:
            c[letter] = 1

    stats = {}
    for el in c:
        stats[el] = c[el] / length

    entropy = 0
    for el in c:
        entropy -= stats[el] * log2(stats[el])
    return entropy
