from flask import Flask, jsonify, render_template, redirect, url_for, session, flash, request
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
import random
import string
import time
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, ValidationError
import bcrypt
import mysql.connector

app = Flask(__name__)

app.config['MYSQL_HOST'] = 'bbxohptxfb0igoeap0cb-mysql.services.clever-cloud.com'
app.config['MYSQL_USER'] = 'utu8q7k9fjpnu00h'
app.config['MYSQL_PASSWORD'] = 'SEjl0OtOlCI3mg9rm5yV'
app.config['MYSQL_DB'] = 'bbxohptxfb0igoeap0cb'
app.config['MYSQL_PORT'] = 3306

app.secret_key = 'your_secret_key_here'

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'kha.nguyen1705@hcmut.edu.vn'
app.config['MAIL_PASSWORD'] = 'ebbd uyhz zeus kasj'
app.config['MAIL_DEFAULT_SENDER'] = 'kha.nguyen1705@hcmut.edu.vn'

mail = Mail(app)
s = URLSafeTimedSerializer(app.secret_key)

def get_db_connection():
    return mysql.connector.connect(
        host=app.config['MYSQL_HOST'],
        user=app.config['MYSQL_USER'],
        password=app.config['MYSQL_PASSWORD'],
        database=app.config['MYSQL_DB']
    )

def update_points_in_db(user_id, new_points):
    db = get_db_connection()
    cursor = db.cursor()
    cursor.execute("UPDATE users SET points=%s WHERE id=%s", (new_points, user_id))
    db.commit()
    cursor.close()
    db.close()

def generate_qr_data(points):
    random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
    timestamp = str(int(time.time()))
    qr_data = f"{points}-{random_string}-{timestamp}"
    return qr_data

class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Register")

    def validate_email(self, field):
        db = get_db_connection()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE email=%s", (field.data,))
        user = cursor.fetchone()
        cursor.close()
        db.close()
        if user:
            raise ValidationError('Email Already Taken')

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/get_points', methods=['GET'])
def get_points():
    if 'user_id' not in session:
        return jsonify({"status": "error", "message": "Vui lòng đăng nhập để xem điểm."})
    user_id = session['user_id']
    db = get_db_connection()
    cursor = db.cursor()
    cursor.execute("SELECT points FROM users WHERE id=%s", (user_id,))
    user = cursor.fetchone()
    cursor.close()
    db.close()
    return jsonify({"status": "success", "points": user[0]}) if user else jsonify({"status": "error", "message": "Không tìm thấy người dùng."})

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        db = get_db_connection()
        cursor = db.cursor()
        cursor.execute("INSERT INTO users (name, email, password) VALUES (%s, %s, %s)", (name, email, hashed_password))
        db.commit()
        cursor.close()
        db.close()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        db = get_db_connection()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()
        cursor.close()
        db.close()
        if user and bcrypt.checkpw(password.encode('utf-8'), user[3].encode('utf-8')):
            session['user_id'] = user[0]
            session['points'] = user[4]
            return redirect(url_for('dashboard'))
        else:
            flash("Login failed. Please check your email and password")
            return redirect(url_for('login'))
    return render_template('login.html', form=form)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        db = get_db_connection()
        cursor = db.cursor()
        cursor.execute("SELECT id, email FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()
        cursor.close()
        db.close()
        if user:
            token = s.dumps(user[1], salt='password-reset-salt')
            reset_link = url_for('reset_password', token=token, _external=True)

            msg = Message("Password Reset Request", sender="your_email@gmail.com", recipients=[email])
            msg.html = f"""
            <html>
                <body>
                    <p>Hello,</p>
                    <p>We received a request to reset your password. Click the button below to reset it:</p>
                    <a href="{reset_link}" style="background-color: #4FD8C2; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; font-weight: bold;">Reset Password</a>
                    <p>Best regards,<br>App Team</p>
                </body>
            </html>
            """
            mail.send(msg)
            return redirect(url_for('login'))
        else:
            return redirect(url_for('forgot_password'))
    return render_template('forgot_password.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    token = request.args.get('token')
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=60)
    except Exception:
        flash("The link is invalid or has expired.")
        return redirect(url_for('login'))
    if request.method == 'POST':
        new_password = request.form['password']
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        db = get_db_connection()
        cursor = db.cursor()
        cursor.execute("UPDATE users SET password=%s WHERE email=%s", (hashed_password, email))
        db.commit()
        cursor.close()
        db.close()
        return redirect(url_for('login'))
    return render_template('reset_password.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        user_id = session['user_id']
        db = get_db_connection()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE id=%s", (user_id,))
        user = cursor.fetchone()
        cursor.close()
        db.close()
        return render_template('dashboard.html', user=user) if user else redirect(url_for('login'))
    return redirect(url_for('login'))

@app.route('/logout', methods=['POST'])
def logout():
    # Xóa thông tin người dùng khỏi session
    session.pop('user_id', None)
    session.pop('points', None)

    # Trả về phản hồi JSON xác nhận mà không có thông báo
    return jsonify({'status': 'success'})

@app.route('/process_qr', methods=['POST'])
def process_qr():
    if request.method == 'POST':
        qr_data = request.json.get('qr_data')

        # Kiểm tra nếu người dùng chưa đăng nhập
        if 'user_id' not in session:
            return jsonify({"status": "error", "message": "Vui lòng đăng nhập để tích điểm"}), 401

        user_id = session['user_id']
        db = get_db_connection()
        cursor = db.cursor()

        try:
            # Kiểm tra xem mã QR đã được quét bởi tài khoản nào khác chưa
            cursor.execute("SELECT user_id FROM user_qr_scans WHERE qr_data=%s", (qr_data,))
            previous_scan = cursor.fetchone()

            if previous_scan:
                # Nếu có bản ghi đã quét mã QR, kiểm tra tài khoản nào đã quét
                if previous_scan[0] == user_id:
                    message = "Mã QR đã được quét bởi tài khoản của bạn trước đó."
                else:
                    message = "Mã QR đã được sử dụng bởi tài khoản khác."
                cursor.fetchall()  # Đảm bảo rằng cursor được xử lý hết kết quả
                cursor.close()
                db.close()
                return jsonify({"status": "error", "message": message}), 400

            # Nếu mã QR chưa được quét, thêm mã QR vào bảng user_qr_scans
            cursor.execute("INSERT INTO user_qr_scans (user_id, qr_data) VALUES (%s, %s)", (user_id, qr_data))
            db.commit()

            # Lấy điểm từ dữ liệu QR (lấy điểm từ phần sau dấu ':' trong mã QR)
            try:
                random_string, points_to_add = qr_data.split(':')
                points_to_add = int(points_to_add)
            except ValueError:
                cursor.fetchall()  # Đảm bảo xử lý kết quả truy vấn nếu có lỗi
                cursor.close()
                db.close()
                return jsonify({"status": "error", "message": "QR không hợp lệ. Dữ liệu không thể phân tích."}), 400

            # Cập nhật điểm cho người dùng
            cursor.execute("SELECT points FROM users WHERE id=%s", (user_id,))
            current_points = cursor.fetchone()[0]

            new_points = current_points + points_to_add
            update_points_in_db(user_id, new_points)

            cursor.fetchall()  # Đảm bảo xử lý hết các kết quả của truy vấn trước khi đóng cursor
            cursor.close()
            db.close()

            return jsonify({"status": "success", "message": "Điểm đã được cộng vào tài khoản của bạn.", "new_points": new_points})

        except Exception as e:
            cursor.fetchall()  # Đảm bảo xử lý hết kết quả nếu có lỗi xảy ra
            cursor.close()
            db.close()
            return jsonify({"status": "error", "message": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True)
