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
import datetime
import re

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

def get_user_statistics(user_id):
    db = get_db_connection()
    cursor = db.cursor()

    # Lấy ngày đầu tháng hiện tại (ngày 1 của tháng hiện tại)
    current_month_start = datetime.datetime.now().replace(day=1).strftime('%Y-%m-%d')

    # Lấy ngày cuối tháng hiện tại (ngày 31 của tháng hiện tại)
    next_month = datetime.datetime.now().replace(day=28) + datetime.timedelta(days=4)  # Đảm bảo luôn chuyển sang tháng tiếp theo
    current_month_end = next_month.replace(day=1) - datetime.timedelta(days=1)  # Trở lại ngày cuối của tháng hiện tại
    current_month_end = current_month_end.strftime('%Y-%m-%d')

    # Truy vấn thống kê số lượng rác từ ngày 1 đến ngày 31 của tháng hiện tại
    cursor.execute("""
        SELECT waste_class, SUM(total_count) AS total_count
        FROM waste_statistics
        WHERE user_id=%s AND classification_month BETWEEN %s AND %s
        GROUP BY waste_class
    """, (user_id, current_month_start, current_month_end))

    statistics = cursor.fetchall()
    cursor.close()
    db.close()

    # Lưu trữ kết quả thống kê theo loại rác
    waste_statistics = []
    for row in statistics:
        waste_statistics.append({
            "waste_class": row[0],
            "total_count": row[1],
        })

    return waste_statistics
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

        # Truy vấn thông tin người dùng từ bảng users
        db = get_db_connection()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE id=%s", (user_id,))
        user = cursor.fetchone()

        # Kiểm tra nếu không có người dùng
        if not user:
            cursor.close()
            db.close()
            return redirect(url_for('login'))

        # Lấy thông tin thống kê phân loại rác của người dùng
        waste_statistics = get_user_statistics(user_id)

        cursor.close()
        db.close()

        # Trả về kết quả và render template với thông tin người dùng và thống kê
        return render_template('dashboard.html', user=user, waste_statistics=waste_statistics)

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
            # Kiểm tra nếu mã QR đã quét
            cursor.execute("SELECT user_id FROM user_qr_scans WHERE qr_data=%s", (qr_data,))
            previous_scan = cursor.fetchone()
            if previous_scan:
                message = "Mã QR đã được quét."
                cursor.close()
                db.close()
                return jsonify({"status": "error", "message": message}), 400

            # Phân tích dữ liệu từ qr_data
            try:
                waste_data, unique_id, points_to_add = qr_data.split(':')
                points_to_add = int(points_to_add)
            except ValueError:
                return jsonify({"status": "error", "message": "Dữ liệu QR không hợp lệ."}), 400

            # Tách các loại rác
            waste_classes = waste_data.split(',')
            current_month = datetime.datetime.now().strftime('%Y-%m-01')

            # Lưu từng loại rác vào bảng waste_statistics
            for waste in waste_classes:
                # Sử dụng regex để tách class_name và count
                match = re.match(r"([a-zA-Z]+)(\d+)", waste)
                if not match:
                    # Nếu không khớp định dạng, bỏ qua mục này
                    continue
                class_name = match.group(1)  # Lấy phần chữ
                count = int(match.group(2))  # Lấy phần số
                cursor.execute("""
                    INSERT INTO waste_statistics (user_id, waste_class, total_count, classification_month)
                    VALUES (%s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE total_count = total_count + VALUES(total_count)
                """, (user_id, class_name, count, current_month))

            # Cộng điểm vào bảng users
            cursor.execute("SELECT points FROM users WHERE id=%s", (user_id,))
            current_points = cursor.fetchone()[0]
            new_points = current_points + points_to_add
            cursor.execute("UPDATE users SET points=%s WHERE id=%s", (new_points, user_id))

            # Lưu mã QR đã quét
            cursor.execute("INSERT INTO user_qr_scans (user_id, qr_data) VALUES (%s, %s)", (user_id, qr_data))
            db.commit()

            return jsonify({"status": "success", "message": "Điểm đã được cộng.", "new_points": new_points})

        except Exception as e:
            db.rollback()
            return jsonify({"status": "error", "message": str(e)}), 500

        finally:
            cursor.close()
            db.close()
    return render_template('dashboard.html')


if __name__ == "__main__":
    app.run(debug=True)
