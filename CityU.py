from flask import Flask, render_template, url_for, request, redirect, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, login_required, logout_user, current_user, LoginManager
from flask_wtf import FlaskForm, form
from wtforms import StringField, PasswordField, SubmitField, SelectField, BooleanField, IntegerField, FloatField, DateField
from wtforms.validators import InputRequired, Length, ValidationError
from wtforms.validators import DataRequired,Optional, NumberRange
from flask_bcrypt import Bcrypt
from datetime import datetime
from urllib.parse import urlparse
from sqlalchemy import CheckConstraint
import os

app = Flask(__name__)
db = SQLAlchemy()
bcrypt = Bcrypt(app)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(app.instance_path, "tracker.db")
app.config["SECRET_KEY"] = 'thisisasecretkey'
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@ login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

class ApplicationResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    faculty = db.Column(db.String(50), nullable=False)
    school = db.Column(db.String(120), nullable=False)
    program = db.Column(db.String(120), nullable=False)
    status = db.Column(db.String(20), nullable=False)
    region = db.Column(db.String(50))

    gpa = db.Column(db.Float)

    gre_total = db.Column(db.Integer)
    gre_v = db.Column(db.Integer)
    gre_q = db.Column(db.Integer)
    gre_awa = db.Column(db.Float)

    gmat_total = db.Column(db.Integer)
    gmat_q = db.Column(db.Integer)
    gmat_v = db.Column(db.Integer)
    gmat_di = db.Column(db.Integer)

    ielts_total = db.Column(db.Integer)
    ielts_l = db.Column(db.Float)
    ielts_r = db.Column(db.Float)
    ielts_w = db.Column(db.Float)
    ielts_s = db.Column(db.Float)

    toefl_total = db.Column(db.Integer)
    toefl_r = db.Column(db.Integer)
    toefl_l = db.Column(db.Integer)
    toefl_s = db.Column(db.Integer)
    toefl_w = db.Column(db.Integer)

    is_public = db.Column(db.Boolean, default=False)
    submission_date = db.Column(db.Date)
    result_date = db.Column(db.Date)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='applications')

    __table_args__ = (
        # GPA
        CheckConstraint('(gpa IS NULL) OR (gpa >= 0 AND gpa <= 4.0)', name='gpa_range'),

        # GRE
        CheckConstraint('(gre_total IS NULL) OR (gre_total BETWEEN 0 AND 340)', name='gre_total_range'),
        CheckConstraint('(gre_q IS NULL) OR (gre_q BETWEEN 130 AND 170)', name='gre_q_range'),
        CheckConstraint('(gre_v IS NULL) OR (gre_v BETWEEN 130 AND 170)', name='gre_v_range'),
        CheckConstraint('(gre_awa IS NULL) OR (gre_awa BETWEEN 0 AND 6)', name='gre_awa_range'),

        # GMAT
        CheckConstraint('(gmat_total IS NULL) OR (gmat_total BETWEEN 205 AND 805)', name='gmat_total_range'),

        # IELTS
        CheckConstraint('(ielts_total IS NULL) OR (ielts_total BETWEEN 0 AND 9)', name='ielts_total_range'),
        CheckConstraint('(ielts_l IS NULL) OR (ielts_l BETWEEN 0 AND 9)', name='ielts_l_range'),
        CheckConstraint('(ielts_r IS NULL) OR (ielts_r BETWEEN 0 AND 9)', name='ielts_r_range'),
        CheckConstraint('(ielts_w IS NULL) OR (ielts_w BETWEEN 0 AND 9)', name='ielts_w_range'),
        CheckConstraint('(ielts_s IS NULL) OR (ielts_s BETWEEN 0 AND 9)', name='ielts_s_range'),

        # TOEFL
        CheckConstraint('(toefl_total IS NULL) OR (toefl_total BETWEEN 0 AND 120)', name='toefl_total_range'),
        CheckConstraint('(toefl_r IS NULL) OR (toefl_r BETWEEN 0 AND 30)', name='toefl_r_range'),
        CheckConstraint('(toefl_l IS NULL) OR (toefl_l BETWEEN 0 AND 30)', name='toefl_l_range'),
        CheckConstraint('(toefl_s IS NULL) OR (toefl_s BETWEEN 0 AND 30)', name='toefl_s_range'),
        CheckConstraint('(toefl_w IS NULL) OR (toefl_w BETWEEN 0 AND 30)', name='toefl_w_range'),
    )

class UserProfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)

    gpa = db.Column(db.Float)

    gre_total = db.Column(db.Integer)
    gre_v = db.Column(db.Integer)
    gre_q = db.Column(db.Integer)
    gre_awa = db.Column(db.Float)

    gmat_total = db.Column(db.Integer)
    gmat_q = db.Column(db.Integer)
    gmat_v = db.Column(db.Integer)
    gmat_di = db.Column(db.Integer)

    ielts_total = db.Column(db.Integer)
    ielts_l = db.Column(db.Float)
    ielts_r = db.Column(db.Float)
    ielts_w = db.Column(db.Float)
    ielts_s = db.Column(db.Float)

    toefl_total = db.Column(db.Integer)
    toefl_r = db.Column(db.Integer)
    toefl_l = db.Column(db.Integer)
    toefl_s = db.Column(db.Integer)
    toefl_w = db.Column(db.Integer)

    user = db.relationship('User', backref='profile', uselist=False)


class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)],
                           render_kw={"class": "form-control", "placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)],
                             render_kw={"class": "form-control", "placeholder": "Password"})
    submit= SubmitField("Register", render_kw={"class": "btn btn-primary w-100"})

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError("Username already exists. Please choose another username.")


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)],
                           render_kw={"class": "form-control", "placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)],
                             render_kw={"class": "form-control", "placeholder": "Password"})
    submit= SubmitField("Login",render_kw={"class": "btn btn-primary w-100"})

class SubmissionForm(FlaskForm):
    # required
    faculty = SelectField(
        "Faculty",
        choices=[
            ("business", "Business"),
            ("data_science", "Data Science"),
            ("finance", "Finance"),
            ("humanities_social_sciences", "Humanities and Social Sciences"),
            ("health_wellness", "Health and Wellness"),
            ("innovation_design", "Inovation and Design"),
            ("international_tourism_management", "International Tourism and Managment"),
            ("education", "Education"),
            ("law", "Law"),
        ],
        validators=[DataRequired()],
        render_kw={"class": "form-control"}
    )
    school = StringField("School", validators=[DataRequired()],
                         render_kw={"class": "form-control", "placeholder": "e.g. NYU, HKU, Imperial"})
    program = StringField("Program", validators=[DataRequired()],
                          render_kw={"class": "form-control", "placeholder": "e.g. MS Financial Engineering"})

    status = SelectField(
        "Status",
        choices=[
            ("pending", "Pending"),
            ("accept", "Accepted"),
            ("reject", "Rejected"),
            ("waitlist", "Waitlisted"),
            ("enroll", "Enrolled"),
        ],
        validators=[DataRequired()],
        render_kw={"class": "form-control"}
    )

    region = SelectField(
        "Region",
        choices=[
            ("hk", "HK"),
            ("singapore", "Singapore"),
            ("uk", "United Kingdom"),
            ("europe", "Europe"),
            ("us_canada", "United States & Canada"),
            ("australia", "Australia"),
        ],
        validators=[Optional()],
        render_kw={"class": "form-control"}
    )

    submission_date = DateField("Submission Date", validators=[Optional()])
    result_date = DateField("Result Date", validators=[Optional()])

    is_public = BooleanField("Share anonymously with community?", default=False)

    # optional GPA
    gpa = FloatField("GPA (0–4.0)", validators=[Optional(), NumberRange(0, 4)])

    # optional GRE
    gre_total = IntegerField("GRE Total (0–340)", validators=[Optional(), NumberRange(0, 340)])
    gre_q = IntegerField("GRE Quant (130–170)", validators=[Optional(), NumberRange(130, 170)])
    gre_v = IntegerField("GRE Verbal (130–170)", validators=[Optional(), NumberRange(130, 170)])
    gre_awa = FloatField("GRE AWA (0–6)", validators=[Optional(), NumberRange(0, 6)])

    # optional GMAT (your model includes DI too)
    gmat_total = IntegerField("GMAT Total (205–805)", validators=[Optional(), NumberRange(205, 805)])
    gmat_q = IntegerField("GMAT Quant", validators=[Optional()])
    gmat_v = IntegerField("GMAT Verbal", validators=[Optional()])
    gmat_di = IntegerField("GMAT Data Insights", validators=[Optional()])

    # optional IELTS (total is usually 0–9 with 0.5 steps, but your model uses Integer)
    ielts_total = IntegerField("IELTS Overall (0–9)", validators=[Optional(), NumberRange(0, 9)])
    ielts_l = FloatField("IELTS Listening (0–9)", validators=[Optional(), NumberRange(0, 9)])
    ielts_r = FloatField("IELTS Reading (0–9)", validators=[Optional(), NumberRange(0, 9)])
    ielts_w = FloatField("IELTS Writing (0–9)", validators=[Optional(), NumberRange(0, 9)])
    ielts_s = FloatField("IELTS Speaking (0–9)", validators=[Optional(), NumberRange(0, 9)])

    # optional TOEFL
    toefl_total = IntegerField("TOEFL Total (0–120)", validators=[Optional(), NumberRange(0, 120)])
    toefl_l = IntegerField("TOEFL Listening (0–30)", validators=[Optional(), NumberRange(0, 30)])
    toefl_r = IntegerField("TOEFL Reading (0–30)", validators=[Optional(), NumberRange(0, 30)])
    toefl_s = IntegerField("TOEFL Speaking (0–30)", validators=[Optional(), NumberRange(0, 30)])
    toefl_w = IntegerField("TOEFL Writing (0–30)", validators=[Optional(), NumberRange(0, 30)])

    submit = SubmitField("Submit", render_kw={"class": "btn btn-primary w-100"})

class UserProfileForm(FlaskForm):
    gpa = FloatField("GPA (0–4.0)", validators=[Optional(), NumberRange(0, 4)])

    gre_total = IntegerField("GRE Total (0–340)", validators=[Optional(), NumberRange(0, 340)])
    gre_q = IntegerField("GRE Quant (130–170)", validators=[Optional(), NumberRange(130, 170)])
    gre_v = IntegerField("GRE Verbal (130–170)", validators=[Optional(), NumberRange(130, 170)])
    gre_awa = FloatField("GRE AWA (0–6)", validators=[Optional(), NumberRange(0, 6)])

    gmat_total = IntegerField("GMAT Total (205–805)", validators=[Optional(), NumberRange(205, 805)])
    gmat_q = IntegerField("GMAT Quant", validators=[Optional()])
    gmat_v = IntegerField("GMAT Verbal", validators=[Optional()])
    gmat_di = IntegerField("GMAT Data Insights", validators=[Optional()])

    ielts_total = IntegerField("IELTS Overall (0–9)", validators=[Optional(), NumberRange(0, 9)])
    ielts_l = FloatField("IELTS Listening (0–9)", validators=[Optional(), NumberRange(0, 9)])
    ielts_r = FloatField("IELTS Reading (0–9)", validators=[Optional(), NumberRange(0, 9)])
    ielts_w = FloatField("IELTS Writing (0–9)", validators=[Optional(), NumberRange(0, 9)])
    ielts_s = FloatField("IELTS Speaking (0–9)", validators=[Optional(), NumberRange(0, 9)])

    toefl_total = IntegerField("TOEFL Total (0–120)", validators=[Optional(), NumberRange(0, 120)])
    toefl_l = IntegerField("TOEFL Listening (0–30)", validators=[Optional(), NumberRange(0, 30)])
    toefl_r = IntegerField("TOEFL Reading (0–30)", validators=[Optional(), NumberRange(0, 30)])
    toefl_s = IntegerField("TOEFL Speaking (0–30)", validators=[Optional(), NumberRange(0, 30)])
    toefl_w = IntegerField("TOEFL Writing (0–30)", validators=[Optional(), NumberRange(0, 30)])

    submit = SubmitField("Save Defaults", render_kw={"class": "btn btn-primary w-100"})

@app.route("/")
def home():
    recent = (ApplicationResult.query
              .filter_by(is_public=True)
              .order_by(ApplicationResult.created_at.desc())
              .limit(8)
              .all())
    return render_template("home.html", current="home", submissions=recent)

@app.route("/tracker", methods=["GET", "POST"])
@login_required
def tracker():
    form = SubmissionForm()
    profile = UserProfile.query.filter_by(user_id=current_user.id).first()

    if request.method == "GET" and profile:
        default_fields = [
            "gpa",
            "gre_total", "gre_q", "gre_v", "gre_awa",
            "gmat_total", "gmat_q", "gmat_v", "gmat_di",
            "ielts_total", "ielts_l", "ielts_r", "ielts_w", "ielts_s",
            "toefl_total", "toefl_l", "toefl_r", "toefl_s", "toefl_w",
        ]
        for field_name in default_fields:
            form_field = getattr(form, field_name)
            if form_field.data in (None, ""):
                profile_value = getattr(profile, field_name)
                if profile_value is not None:
                    form_field.data = profile_value

    if form.validate_on_submit():
        submission = ApplicationResult(
            user_id=current_user.id,
            faculty=form.faculty.data,
            school=form.school.data,
            program=form.program.data,
            status=form.status.data,
            region=form.region.data,
            submission_date=form.submission_date.data,
            result_date=form.result_date.data,
            gpa=form.gpa.data,
            gre_total=form.gre_total.data,
            gre_q=form.gre_q.data,
            gre_v=form.gre_v.data,
            gre_awa=form.gre_awa.data,
            gmat_total=form.gmat_total.data,
            gmat_q=form.gmat_q.data,
            gmat_v=form.gmat_v.data,
            gmat_di=form.gmat_di.data,
            ielts_total=form.ielts_total.data,
            ielts_l=form.ielts_l.data,
            ielts_r=form.ielts_r.data,
            ielts_w=form.ielts_w.data,
            ielts_s=form.ielts_s.data,
            toefl_total=form.toefl_total.data,
            toefl_l=form.toefl_l.data,
            toefl_r=form.toefl_r.data,
            toefl_s=form.toefl_s.data,
            toefl_w=form.toefl_w.data,
            is_public=form.is_public.data,
        )
        db.session.add(submission)
        db.session.commit()
        flash("Submission added!", "success")
        return redirect(url_for("tracker"))  # prevents duplicate submits on refresh

    submissions = (ApplicationResult.query
                   .order_by(ApplicationResult.created_at.desc())
                   .limit(20)
                   .all())

    return render_template(
        "tracker.html",
        current="tracker",
        form=form,
        submissions=submissions
    )

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    profile = UserProfile.query.filter_by(user_id=current_user.id).first()
    if not profile:
        profile = UserProfile(user_id=current_user.id)
        db.session.add(profile)
        db.session.commit()

    form = UserProfileForm(obj=profile)
    if form.validate_on_submit():
        profile.gpa = form.gpa.data
        profile.gre_total = form.gre_total.data
        profile.gre_q = form.gre_q.data
        profile.gre_v = form.gre_v.data
        profile.gre_awa = form.gre_awa.data
        profile.gmat_total = form.gmat_total.data
        profile.gmat_q = form.gmat_q.data
        profile.gmat_v = form.gmat_v.data
        profile.gmat_di = form.gmat_di.data
        profile.ielts_total = form.ielts_total.data
        profile.ielts_l = form.ielts_l.data
        profile.ielts_r = form.ielts_r.data
        profile.ielts_w = form.ielts_w.data
        profile.ielts_s = form.ielts_s.data
        profile.toefl_total = form.toefl_total.data
        profile.toefl_l = form.toefl_l.data
        profile.toefl_r = form.toefl_r.data
        profile.toefl_s = form.toefl_s.data
        profile.toefl_w = form.toefl_w.data
        db.session.commit()
        flash("Defaults updated.", "success")
        return redirect(url_for("profile"))

    return render_template("profile.html", current="profile", form=form)

@app.route("/edit/<int:id>", methods=["GET", "POST"])
@login_required
def edit_submission(id):
    submission = ApplicationResult.query.get_or_404(id)
    if submission.user_id != current_user.id:
        flash("You do not have permission to edit that submission.", "error")
        return redirect(url_for("tracker"))

    form = SubmissionForm(obj=submission)
    if form.validate_on_submit():
        submission.faculty = form.faculty.data
        submission.school = form.school.data
        submission.program = form.program.data
        submission.status = form.status.data
        submission.region = form.region.data
        submission.submission_date = form.submission_date.data
        submission.result_date = form.result_date.data
        submission.gpa = form.gpa.data
        submission.gre_total = form.gre_total.data
        submission.gre_q = form.gre_q.data
        submission.gre_v = form.gre_v.data
        submission.gre_awa = form.gre_awa.data
        submission.gmat_total = form.gmat_total.data
        submission.gmat_q = form.gmat_q.data
        submission.gmat_v = form.gmat_v.data
        submission.gmat_di = form.gmat_di.data
        submission.ielts_total = form.ielts_total.data
        submission.ielts_l = form.ielts_l.data
        submission.ielts_r = form.ielts_r.data
        submission.ielts_w = form.ielts_w.data
        submission.ielts_s = form.ielts_s.data
        submission.toefl_total = form.toefl_total.data
        submission.toefl_l = form.toefl_l.data
        submission.toefl_r = form.toefl_r.data
        submission.toefl_s = form.toefl_s.data
        submission.toefl_w = form.toefl_w.data
        submission.is_public = form.is_public.data
        db.session.commit()
        flash("Submission updated.", "success")
        return redirect(url_for("tracker"))

    return render_template("edit_submission.html", current="tracker", form=form, submission=submission)

@app.route("/submission/<int:id>")
def submission_detail(id):
    submission = ApplicationResult.query.get_or_404(id)
    if submission.is_public or (current_user.is_authenticated and submission.user_id == current_user.id):
        return render_template("submission_detail.html", current="tracker", submission=submission)
    abort(403)

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/login",methods=["GET","POST"])
def login():
    form = LoginForm()
    next_page = request.args.get("next")
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            if next_page and urlparse(next_page).netloc == "":
                return redirect(next_page)
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid username or password", "error")

    return render_template("login.html",form=form)

@app.route("/register",methods=["GET","POST"])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode("utf-8")
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        profile = UserProfile(user_id=new_user.id)
        db.session.add(profile)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("profile"))


    return render_template("register.html",form=form)

@app.route("/dashboard",methods=["GET","POST"])
@login_required
def dashboard():
    return render_template("dashboard.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/delete/<int:id>", methods=["POST"])
@login_required
def delete(id):
    submission = ApplicationResult.query.get_or_404(id)
    if submission.user_id != current_user.id:
        flash("You do not have permission to delete that submission.", "error")
        return redirect(url_for("tracker"))

    try:
        db.session.delete(submission)
        db.session.commit()
        flash("Submission deleted.", "success")
        return redirect(url_for("tracker"))
    except Exception as e:
        return f"There was an issue deleting your task: {e}"

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
