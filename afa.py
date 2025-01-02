from flask import *
from flask import Blueprint
from flask_sqlalchemy import SQLAlchemy
from flask_bootstrap import Bootstrap
from flask_login import *
from flask_wtf import FlaskForm
from wtforms import *
from wtforms.validators import *
from functools import wraps
from datetime import datetime
from flask_moment import Moment
import string
import random


app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///afa.db"

students_bp = Blueprint("students_bp", __name__)
db = SQLAlchemy(app)
app.secret_key = "46+-_"
login_manager = LoginManager(app)
st_login_manager = LoginManager(students_bp)
bootstrap = Bootstrap(app)
moment = Moment(app)


class Permission:
	CASHIER = 1
	TEACHER = 2
	HEADMASTER = 4
	ADMIN = 8


class RegistrationForm(FlaskForm):
	email = StringField("Email Address", validators=[DataRequired(), Email()])
	username = StringField("Username", validators=[Regexp("[A-Za-z][A-Za-z0-9_.]", 0, message="Username should contain alpha and numbers"), DataRequired()])
	password = PasswordField("Password", validators=[EqualTo("comfirm_password", message="Password does not match"), DataRequired()])
	comfirm_password = PasswordField("Comfirm Password")
	submit = SubmitField("Register")
	
	def __init__(self, **kwargs):
		super().__init__(**kwargs)
		self.email.render_kw = {"oninput": "this.value = this.value.toLowerCase();"}
		self.username.render_kw = {"oninput": "this.value = this.value.toLowerCase();"}
	
	def validate_email(self, field):
		if User.query.filter_by(email=field.data).first():
			raise ValidationError("Email used by another user")
	
	def validate_username(self, field):
		if User.query.filter_by(username=field.data).first():
			raise ValidationError("Username is already taken")
	
	def validate_password(self, field):
		if len(field.data) < 7:
			raise ValidationError("Password too short")


class LoginForm(FlaskForm):
	email = StringField("Email address", validators=[ DataRequired()])
	password = PasswordField("Password", validators=[DataRequired()])
	submit = SubmitField("Log In")
	
	def __init__(self, **kwargs):
		super().__init__(**kwargs)
		


class AdminEditForm(FlaskForm):
	role = SelectField("Role", coerce=int)
	submit = SubmitField("Update")
	
	def __init__(self, **kwargs):
		super().__init__(**kwargs)
		self.role.choices = [(role.id, role.name) for role in Role.query.order_by(Role.name).all()]


class AddStudentForm(FlaskForm):
	email = StringField("Email Address", validators=[Email(), DataRequired()])
	username = StringField("Username", validators=[DataRequired()])
	classes = SelectField("Select Class", validators=[DataRequired()])
	submit = SubmitField("Submit")
	
	def __init__(self, **kwargs):
		super().__init__(**kwargs)
		self.classes.choices = [(clas.id, clas.name) for clas in Classes.query.order_by(Classes.name).all()]
	
	def validate_email(self, field):
		if Student.query.filter_by(email=field.data).first():
			raise ValidationError("Email already exists")
	
	def validate_username(self, field):
		if Student.query.filter_by(username=field.data).first():
			raise ValidationError("Email already exists")


class AssignTeacherForm(FlaskForm):
	name_select = SelectField("Select", validators=[DataRequired()])
	submit = SubmitField("Submit")
	
	def __init__(self, **kwargs):
		super().__init__(**kwargs)
		self.name_select.choices = [(teacher.id, teacher.username) for teacher in Teachers.query.order_by(Teachers.username).all()]


class AddClassForm(FlaskForm):
	name = StringField("Class Name")
	submit = SubmitField("Submit")
	
	def validate_name(self, field):
		if Classes.query.filter_by(name=field.data).first():
			raise ValidationError("Class already exists")


class StudentsLoginForm(FlaskForm):
	reg_num = StringField("Reg number or Email Address", validators=[DataRequired()])
	password = PasswordField("Password", validators=[DataRequired()])
	submit = SubmitField("Log In")


class Role(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.String, unique=True)
	permissions = db.Column(db.Integer)
	default = db.Column(db.Boolean, default=False)
	users = db.relationship("User", backref="role", lazy="dynamic")
	
	def __init__(self, **kwargs):
		super().__init__(**kwargs)
	
	def add_permission(self, perm):
		if not self.has_permission(perm):
			self.permissions += perm
	
	def remove_permision(self, perm):
		if self.has_permission(perm):
			self.permissions -= perm
	
	def has_permission(self, perm):
		return self.permissions & perm == perm
	
	def reset_permissions(self):
		self.permissions = 0
	
	@staticmethod
	def insert_roles():
		roles = {
			"Teacher": [Permission.TEACHER],
			"Headmaster": [Permission.TEACHER, Permission.HEADMASTER],
			"Cashier": [Permission.CASHIER],
			"Admin": [Permission.TEACHER, Permission.HEADMASTER, Permission.ADMIN],
		}
		default_role = "User"
		for r in roles:
			role = Role(name=r)
			role.reset_permissions()
			for perm in roles[r]:
				role.add_permission(perm)
			role.default = (role.name==default_role)
			db.session.add(role)
		db.session.commit()


class Teachers(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String, unique=True)
	classes = db.relationship("Classes", backref="teachers", lazy="dynamic")
	

class User(UserMixin, db.Model):
	id = db.Column(db.Integer, primary_key=True)
	email = db.Column(db.String, unique=True)
	username = db.Column(db.String, unique=True)
	password = db.Column(db.String)
	timestamp = db.Column(db.DateTime, default=datetime.utcnow)
	role_id = db.Column(db.Integer, db.ForeignKey("role.id"))
	
	def __init__(self, **kwargs):
		super().__init__(**kwargs)
		if self.role is None:
			if self.email == "afanyoschools@gmail.com":
				self.role = Role.query.filter_by(name="Admin").first()
			if self.role is None:
				self.role = Role.query.filter_by(default=True).first()

	def can(self, perm):
		return self.role is not None and self.role.has_permission(perm)
	
	def is_administrator(self):
		return self.can(Permission.ADMIN)
	
	def verify_password(self, psw):
		return self.password == psw


class Classes(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.String, unique=True)
	timestamp = db.Column(db.DateTime, default=datetime.utcnow)
	students = db.relationship("Student", backref="class_", lazy="dynamic")
	subjects = db.relationship("Subject", backref="classes", lazy="dynamic")
	teachers_id = db.Column(db.Integer, db.ForeignKey("teachers.id"))
	
	def assign_teacher(self, teacher):
		if self.teachers is None:
			self.teachers = Teachers.query.get_or_404(teacher)
		flash("teacher already assigned to class")
	
	def remove_teacher(self):
		self.teachers = None
		


class Subject(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.String, unique=True)
	timestamp = db.Column(db.DateTime, default=datetime.utcnow)
	class_id = db.Column(db.Integer, db.ForeignKey("classes.id"))
	students = db.relationship("Student", backref="subject", lazy="dynamic")


class Student(UserMixin, db.Model):
	id = db.Column(db.Integer, primary_key=True)
	email = db.Column(db.String, unique=True)
	username = db.Column(db.String, unique=True)
	reg_num = db.Column(db.String, unique=True)
	class_rep = db.Column(db.Boolean)
	password=db.Column(db.String)
	class_id = db.Column(db.Integer, db.ForeignKey("classes.id"))
	subject_id = db.Column(db.Integer, db.ForeignKey("subject.id"))
	
	def assign_class_rep(self):
		if Student.query.filter_by(class_rep=True).first() is not None:
			flash("There is already a class rep")
		else:
			self.class_rep = True
	
	def is_class_rep(self):
		return self.class_rep == True
	
	def remove_class_rep(self):
		self.class_rep = False
	
	def verify_password(self, psw):
		return self.password == psw
	
	def verify_reg_email(self, data):
		return self.email == data or self.reg_num == data


def search_add_teachers():
	role = Role.query.filter_by(name="Teacher").first()
	teacher = User.query.filter_by(role=role).all()
	if teacher:
		for t in teacher:
			if Teachers.query.filter_by(username=t.username).first() is None:
				t = Teachers(username=t.username)
				db.session.add(t)
				db.session.commit()


def generate_reg():
	rand = random.SystemRandom()
	reg_deg = "".join(rand.choice(string.digits) for _ in range(8))
	reg_alp = "".join(rand.choice(string.ascii_uppercase) for _ in range(2))
	registration_number = reg_deg.__str__() + reg_alp
	return registration_number


with app.app_context():
	db.create_all()
	if not Role.query.all():
		Role.insert_roles()
	s = Student.query.all()
	print(s[0].password)

def permission_required(permission):
	def decorator(f):
		@wraps(f)
		def decorated_function(*args, **kwargs):
			if not current_user.can(permission):
				abort(403)
			return f(*args, **kwargs)
		return decorated_function
	return decorator


def admin_required(f):
	return permission_required(Permission.ADMIN)(f)

@login_manager.user_loader
def load_user(user_id):
	return User.query.get_or_404(int(user_id))



@st_login_manager.user_loader
def load_user(user_id):
	return Student.query.get_or_404(int(user_id))

@app.context_processor
def inject_permision():
	return dict(Permission=Permission)


@app.route("/")
def index():
	search_add_teachers()
	users = User.query.all()
	sss1 = Classes.query.filter_by(name="SSS1").first()
	sss2 = Classes.query.filter_by(name="SSS2").first()
	sss3 = Classes.query.filter_by(name="SSS3").first()
	sss1_students = Student.query.filter_by(class_=sss1).all()
	sss2_students = Student.query.filter_by(class_=sss2).all()
	sss3_students = Student.query.filter_by(class_=sss3).all()
	
	class_pagination = Classes.query.order_by(Classes.name).paginate(page=request.args.get("page", 1, type=int), per_page=1, error_out=False)
	classes = class_pagination.items
	return render_template(
	"index.html",
	users=users,
	sss1_students=sss1_students,
	classes=classes,
	sss2_students=sss2_students,
	class_pagination=class_pagination,
	sss3_students=sss3_students,
	)


@app.route("/register", methods=["POST", "GET"])
def register():
	if current_user.is_authenticated:
		return redirect(url_for("index"))
	form = RegistrationForm()
	if form.validate_on_submit():
		user = User(
			email=form.email.data,
			username=form.username.data,
			password=form.password.data,
			timestamp=datetime.utcnow()
		)
		db.session.add(user)
		db.session.commit()
		print(user.timestamp)
		return redirect(url_for("login"))
	return render_template("register.html", form=form)


@app.route("/login", methods=["POST", "GET"])
def login():
	if current_user.is_authenticated:
		return redirect(url_for("index"))
	form = LoginForm()
	if form.validate_on_submit():
		user = User.query.filter_by(email=form.email.data).first()
		student = Student.query.filter_by(reg_num=form.email.data).first()
		if user is not None and user.verify_password(form.password.data):
			login_user(user)
			return redirect(url_for("index"))
		elif student is not None and student.verify_password(form.password.data):
			login_user(student)
			return redirect(url_for("students_bp.students_dashboard"))
		flash("Invalid email or password")
	return render_template("login.html", form=form)


@app.route("/admin_view_users/<username>")
@login_required
@admin_required
def view_user(username):
	user = User.query.filter_by(username=username).first()
	roles = Role.query.all()
	return render_template("admin_v_user.html", user=user, roles=roles)


@app.route("/set_role/<int:id>", methods=["POST", "GET"])
@login_required
@admin_required
def admin_edit(id):
	user = User.query.get_or_404(id)
	form = AdminEditForm()
	if form.validate_on_submit():
		user.role = Role.query.get_or_404(form.role.data)
		db.session.add(user)
		db.session.commit()
		search_add_teachers()
		return redirect(url_for("view_user", username=user.username))
		if user.role is not None:
			user.role = form.role.data
	return render_template("admin_edit.html", user=user, form=form)


@app.route("/add_student", methods=["POST", "GET"])
@permission_required(Permission.TEACHER)
@login_required
def add_student():
	form = AddStudentForm()
	if form.validate_on_submit():
		reg = generate_reg()
		student = Student(
			email=form.email.data,
			username=form.username.data,
			class_=Classes.query.get(form.classes.data),
			reg_num=reg,
			password=reg
		)
		db.session.add(student)
		db.session.commit()
		return redirect(url_for("index"))
	return render_template("add_student.html", form=form)


@app.route("/add_class", methods=["POST", "GET"])
@permission_required(Permission.HEADMASTER)
@login_required
def class_ad():
	form = AddClassForm()
	if form.validate_on_submit():
		class_ = Classes(name=form.name.data, timestamp=datetime.utcnow())
		db.session.add(class_)
		db.session.commit()
		return redirect(url_for("index"))
	return render_template("add_class.html", form=form)


@app.route("/assign_rep/<int:id>")
@login_required
@permission_required(Permission.TEACHER)
def assign_rep(id):
	user = Student.query.get_or_404(id)
	user.assign_class_rep()
	db.session.add(user)
	db.session.commit()
	return redirect(url_for("index"))


@app.route("/remove_rep/<int:id>")
@permission_required(Permission.TEACHER)
@login_required
def remove_rep(id):
	user = Student.query.get_or_404(id)
	user.remove_class_rep()
	db.session.add(user)
	db.session.commit()
	return redirect(url_for("index"))


@app.route("/assign_teacher/<int:id>", methods=["POST", "GET"])
@login_required
@admin_required
def assign_teacher(id):
	form = AssignTeacherForm()
	classs = Classes.query.get_or_404(id)
	teachers = Teachers.query.all()
	if form.validate_on_submit():
		classs.assign_teacher(form.name_select.data)
		db.session.add(classs)
		db.session.commit()
		return redirect(url_for("index"))
	return render_template("assign_teacher.html", classs=classs, teachers=teachers, form=form)


@app.route("/remove_teacher/<int:id>")
@login_required
@admin_required
def remove_teacher(id):
	cl = Classes.query.get_or_404(id)
	cl.remove_teacher()
	db.session.add(cl)
	db.session.commit()
	return redirect(url_for("index"))


@app.route("/admin_view_student/<username>")
@login_required
@permission_required(Permission.HEADMASTER)
def admin_view_student(username):
	student = Student.query.filter_by(username=username).first()
	print(student)
	return render_template("admin_view_st.html", student=student)


@students_bp.route("/students")
def students():
	return render_template("students_bp/st_dashboard.html")


@students_bp.route("/students_login", methods=["POST", "GET"])
def st_login():
	form = StudentsLoginForm()
	if form.validate_on_submit():
		student = Student.query.filter_by(reg_num=form.reg_num.data).first()
		if student and student.verify_password(form.password.data):
			login_user(student)
			return redirect(url_for("students_bp.students"))
	return render_template("students_bp/students_login.html", form=form)


@app.route("/logout")
def logout():
	logout_user()
	return redirect(url_for("index"))


app.register_blueprint(students_bp)
app.run()
