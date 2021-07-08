__author__ = 'chernobyl'

from locale import str
from flask import Flask, render_template, request, redirect, flash, url_for
from flask_talisman import Talisman
from flask.helpers import make_response
from flask_login.login_manager import LoginManager
from flask_wtf import FlaskForm
from flask_login import login_required, login_manager, login_user, logout_user, current_user, UserMixin
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import uuid
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash, gen_salt
import os
import re
from flask_admin import Admin, AdminIndexView
from flask_admin.contrib.sqla import ModelView




app = Flask(__name__)

#SELF = "'self'"
#'\'self\''

#csp = {
# 'default-src': [
#        SELF
#    ],
#    'script-src': [
#        SELF
#    ],
#    'style-src': [
#        SELF
#    ]
#}

#talisman = Talisman(
#                    app,
#                    content_security_policy=csp,
#                    content_security_policy_nonce_in=["script-src", 'style-src']
#)

#This enforces CSP in talisman but also provide a reporting url for when it breaks
#content_security_policy_report_only=True
#content_security_policy_report_uri="<reporting_url>p"


app.config['SECRET_KEY'] = os.environ.get('SECRET')
#app.config['SECRET_KEY'] = "fghfjghjfhgjdhgjfdg32$#RDFGRTWER@#$!EDASF$%werf4rjh45u8"


app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_BINDS'] = {'two': os.environ.get('HEROKU_POSTGRESQL_COPPER_URL'),
                                  'three': os.environ.get('HEROKU_POSTGRESQL_CRIMSON_URL'),
                                  'four': os.environ.get('HEROKU_POSTGRESQL_IVORY_URL'),
                                  'five': os.environ.get('HEROKU_POSTGRESQL_NAVY_URL'),
                                  'six': os.environ.get('HEROKU_POSTGRESQL_ONYX_URL'),
                                  'seven': os.environ.get('HEROKU_POSTGRESQL_PUCE_URL'),
                                  'eight': os.environ.get('HEROKU_POSTGRESQL_YELLOW_URL')}


"""
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///main.db'
app.config['SQLALCHEMY_BINDS'] = {'two': 'sqlite:///two.db',
                                  'three': 'sqlite:///three.db',
                                  'four': 'sqlite:///four.db',
                                  'five': 'sqlite:///five.db',
                                  'six': 'sqlite:///six.db',
                                  'seven': 'sqlite:///seven.db',
                                  'eight': 'sqlite:///eight.db'}
"""

login_manager.session_protection = "strong"


db = SQLAlchemy(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'registration'


"""
___________________Remove admin view in future.__________________________
"""

class MyModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('index'))


class MyAdminIndexView(AdminIndexView):
    def is_accessible(self):
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('index'))


admin = Admin(app, index_view = MyAdminIndexView(), name = 'Bayly Diagnostics', template_mode = 'bootstrap3')



class Record(db.Model):
    user_id = db.Column(db.Text, unique=True, nullable=False, primary_key=True, default=uuid.uuid4().hex)
    patient = db.Column(db.Text, nullable=False, default=user_id)
    address = db.Column(db.Text, nullable=False, default="N\A")
    physician = db.Column(db.Text, nullable=False, default="N\A")
    status = db.Column(db.Text, nullable=False, default='N/A')
    age = db.Column(db.Text, nullable=False, default='N/A')
    gender = db.Column(db.Text, nullable=False, default='N/A')
    date_posted = db.Column(db.DateTime(9000000000000000000000000000000), nullable=False, default=datetime.utcnow)
    preexisting_conditions = db.Column(db.Text, nullable=False, default="No known preexisting conditions")
    hospital = db.Column(db.Text, nullable=False, default="N\A")
    admission_date = db.Column(db.DateTime(9000000000000000000000000000000), nullable=False, default=datetime.utcnow)
    triggers = db.Column(db.Text, nullable=False, default="N\A")
    insurance = db.Column(db.Text, nullable=False, default="N\A")
    preference = db.Column(db.Text, nullable=False, default="N\A")
    beliefs = db.Column(db.Text, nullable=False, default="N\A")
    organ_donor = db.Column(db.Text, nullable=False, default="N\A")
    allergies = db.Column(db.Text, nullable=False, default="N\A")
    current_medication = db.Column(db.Text, nullable=False, default="N\A")
    emergency_contact_person = db.Column(db.Text, nullable=False, default="N\A")
    previous_medical_history = db.Column(db.Text, nullable=False, default="N\A")
    lifestyle_choices = db.Column(db.Text, nullable=False, default="N\A")
    episodes = db.Column(db.Integer, nullable=False, default=0)
    current_condition = db.Column(db.Text, nullable=False, default="No Incident")
    number_of_contacts = db.Column(db.Integer, nullable=False, default=0)
    discharge_date = db.Column(db.DateTime(9000000000000000000000000000000), nullable=False, default=datetime.utcnow)
    request_start_time = db.Column(db.DateTime(9000000000000000000000000000000), nullable=False, default=datetime.utcnow)
    status_message = db.Column(db.Text, nullable=False, default="None")
    response_start_time = db.Column(db.DateTime(9000000000000000000000000000000), nullable=False, default=datetime.utcnow)
    time_waited = db.Column(db.DateTime(9000000000000000000000000000000), nullable=False, default=datetime.utcnow)
    current_condition = db.Column(db.Text, nullable=False, default="No Incident To Report")
    current_location = db.Column(db.Text, nullable=False, default="N\A")
    blood_group = db.Column(db.Text, nullable=False, default="N\A")

    def __repr__(self):
        return 'Record' + self.patient


class Register(UserMixin, db.Model):
    __bind_key__ = 'two'
    id = db.Column(db.Integer, primary_key=True)
    practitioner_id = db.Column(db.Text, unique=True, nullable=False)
    user_name = db.Column(db.Text, nullable=True, default=practitioner_id)
    email = db.Column(db.Text, nullable=False, default="N\A")
    password = db.Column(db.Text, nullable=False, default="Quacken9130ire" + uuid.uuid4().hex)

    def __repr__(self):
        return 'Register' + str(self.id)


class Occurrence(UserMixin, db.Model):
    __bind_key__ = 'three'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Text, nullable=False)
    user_name = db.Column(db.Text, nullable=True, default=user_id)
    date_happen = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    events = db.Column(db.Text, nullable=False, default="Information Not Privy")
    notes = db.Column(db.Text, nullable=False, default="No Notes")

    def __repr__(self):
        return 'Occurrence' + str(self.id)


class Message(UserMixin, db.Model):
    __bind_key__ = 'four'
    id = db.Column(db.Integer, primary_key=True)
    sender_name = db.Column(db.Text, nullable=True, default="User")
    user_id = db.Column(db.Text, nullable=False)
    date_happen = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    message = db.Column(db.Text, nullable=False, default="Information Not Privy")

    def __repr__(self):
        return 'Message' + str(self.id)


class LocationHistory(UserMixin, db.Model):
    __bind_key__ = 'five'
    user_id = db.Column(db.Text, nullable=False, primary_key=True)
    place_of_contact = db.Column(db.Text, nullable=False, default="N\A")
    contact_id = db.Column(db.Text, nullable=False)
    contact_name = db.Column(db.Text, nullable=True, default=contact_id)
    contact_main_address = db.Column(db.Text, nullable=False, default="N\A")
    date_happen = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    relationship = db.Column(db.Text, nullable=False, default="Information Not Privy")
    cumulative_contact_hours = db.Column(db.Integer, nullable=False)


    def __repr__(self):
        return 'LocationHistory' + self.user_id


class Dispatch(UserMixin, db.Model):
    __bind_key__ = 'seven'
    id = db.Column(db.Integer, primary_key=True)
    request_start_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    dispatch_start_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    dispatch_wait_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Text, nullable=False, default="new_user_new")
    patient = db.Column(db.Text, nullable=False, default='user_id')
    status = db.Column(db.Text, nullable=False, default='N/A')
    address = db.Column(db.Text, nullable=False, default="N\A")
    current_condition = db.Column(db.Text, nullable=False, default="N\A")
    status_message = db.Column(db.Text, nullable=False, default="Dispatched")

    def __repr__(self):
        return 'Dispatch' + self.user_id



class Happen(UserMixin, db.Model):
    __bind_key__ = 'eight'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Text, nullable=False)
    post = db.Column(db.Text, nullable=False, default="TTO")
    post_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return 'Happen' + self.user_id




class RequestForm(FlaskForm):
    patient_name = StringField('Patient Name', validators=[InputRequired()])
    current_condition = StringField('Current Condition', validators=[InputRequired()])
    current_location = StringField('Current Location', validators=[InputRequired()])
    submit = SubmitField('Submit')


class DispatchForm(FlaskForm):
    submit = SubmitField('Confirm & Dispatch EMT')


class SendForm(FlaskForm):
    submit = SubmitField('Dispatch')


class LocationForm(FlaskForm):
    place_of_contact = StringField('Place of Contact', validators=[InputRequired()])
    contact_name = StringField('Contact Name', validators=[InputRequired()])
    relationship =StringField('Type of Relation', validators=[InputRequired()])
    cumulative_contact_hours = StringField('Number of Hours in Contact', validators=[InputRequired()])


class MessageForm(FlaskForm):
    message = StringField('Message To User', validators=[InputRequired()])


class OccurenceForm(FlaskForm):
    events = StringField('Events', validators=[InputRequired()])
    notes = StringField("Doctor's Notes", validators=[InputRequired()])


class RegisterForm(FlaskForm):
    user_name = StringField('User name', validators=[InputRequired()])
    email = StringField('Email', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Sign Up')


class LoginForm(FlaskForm):
    user_name = StringField('User name / Email', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Login')


class InputForm(FlaskForm):
    patients = StringField('Patient name', validators=[InputRequired()])
    address = StringField('Location', validators=[InputRequired()])
    physician = StringField('Physician', validators=[InputRequired()])
    status = StringField('Status', validators=[InputRequired()])
    age = StringField('Age', validators=[InputRequired()])
    gender = StringField('Gender', validators=[InputRequired()])
    preexisting_conditions = StringField('Pre-existing conditions', validators=[InputRequired()])
    hospital = StringField('Hospital name', validators=[InputRequired()])
    triggers = StringField('Triggers', validators=[InputRequired()])
    insurance = StringField('Insurance Policy', validators=[InputRequired()])
    preference = StringField('Preferences', validators=[InputRequired()])
    beliefs = StringField('Beliefs', validators=[InputRequired()])
    organ_donor = StringField('Organ Donor', validators=[InputRequired()])
    allergies = StringField('Allergies', validators=[InputRequired()])
    current_medication = StringField('Current Medication', validators=[InputRequired()])
    previous_medical_history = StringField('Previous Medical History', validators=[InputRequired()])
    lifestyle_choices = StringField('Lifestyle choices', validators=[InputRequired()])
    emergency_contact_person = StringField('Emergency Contact Person', validators=[InputRequired()])
    submit = SubmitField('Register')


@login_manager.user_loader
def load_user(user_id):
    return Register.query.get(user_id)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('registration'))


@app.after_request
def add_header(response):
    response.headers['X-UA-Compatible'] = 'IE=Edge, chrome=1'
    if 'Cache-Control' not in response.headers:
        response.headers['Cache-Control'] = 'public, max-age=100'

    return response



@app.errorhandler(HTTPException)
def handle_exception(e):
    e.get_response()
    code = e.code
    name = e.name
    d = e.description
    if code >= 500:
        m = "Sorry For Any Inconvenience."

        return render_template('custom_error.html', m=m, e=name, code=code, d=d)

    else:
        m = "Go Somewhere Nice..."

        return render_template('custom_error.html', m=m, e=name, code=code, d=d)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/egg')
def egg():
    return render_template('egg.html')


@app.route('/sars')
def sars():
    return render_template('sars.html')


@app.route('/chart')
def chart():
    return render_template('chart.html')


@app.route('/dashboard')
@login_required
def dashboard():
    base_record = Record.query.order_by(Record.date_posted.desc()).all()
    occurrence = Occurrence.query.all()

    v = datetime(1970, 1, 1)

    name = current_user.user_name
    response = make_response(render_template('dashboard.html', name = name,
                                             database = base_record, occurrence=occurrence, v=v))

    response.headers["Cache-Control"]= "no-cache, no-store, must-revalidate"
    response.headers['Pragma'] = 'no-cache'

    return response




@app.route('/profile/<string:id>', methods=['POST', 'GET'])
@login_required
def view_patient_info(id):
    if request.method == "GET":
        charts = Record.query.filter_by(user_id = id).first()

        if charts is None:
            flash("No Such Patient Record")

            return redirect(url_for('dashboard'))


    locForm = LocationForm()
    form = OccurenceForm()
    mess = MessageForm()
    charts = Record.query.filter_by(user_id = id).first()

    turnip = Happen.query.filter_by(user_id = id).order_by(Happen.post_time.desc()).all()

    location = LocationHistory.query.filter_by(user_id = id).order_by(LocationHistory.date_happen.desc()).all()
    events = Occurrence.query.filter_by(user_id = id).order_by(Occurrence.date_happen.desc()).all()
    msg = Message.query.filter_by(user_id = id).order_by(Message.id.desc()).all()
    name = current_user.user_name

    response = make_response(render_template('patient_profile.html',
                                             chart = charts, form = form,
                                             mess = mess, msg=msg, events=events,
                                             location=location, locForm=locForm,
                                             name=name, turnip =turnip))

    response.headers["Cache-Control"]= "no-cache, no-store, must-revalidate"
    response.headers['Pragma'] = 'no-cache'

    if request.method == "POST":
        if mess.validate_on_submit():
            user_id = id
            sender = current_user.user_name
            db.session.add(Message(sender_name=sender, message = mess.message.data, user_id=user_id))
            db.session.commit()
            return redirect(url_for('view_patient_info', id=id))

        if form.validate_on_submit():
            user_id = id
            upt = Record.query.filter_by(user_id = id).first()
            upt.episodes += 1

            user_name = charts.patient
            db.session.add(Occurrence(events = form.events.data,
                                      notes = form.notes.data, user_id=user_id,
                                      user_name=user_name))
            db.session.commit()
            return redirect(url_for('view_patient_info', id=id))

        if locForm.validate_on_submit():
            user_id = id

            con = Record.query.filter_by(patient=locForm.contact_name.data).first()
            contact_id = con.user_id
            contact_main_address = con.address

            y = Record.query.filter_by(user_id = contact_id).first()
            y.number_of_contacts += 1

            x = Record.query.filter_by(user_id=id).first()
            x.number_of_contacts += 1

            place_of_contact = locForm.place_of_contact.data
            contact_name = locForm.contact_name.data
            relationship = locForm.relationship.data
            cumulative_contact_hours = locForm.cumulative_contact_hours.data

            db.session.add(LocationHistory(contact_id=contact_id,
                                           contact_main_address=y.address,
                                           user_id=user_id,
                                           place_of_contact=place_of_contact,
                                           contact_name=contact_name,
                                           relationship=relationship,
                                           cumulative_contact_hours=cumulative_contact_hours))

            db.session.add(LocationHistory(contact_id=user_id,
                                           contact_main_address=x.address,
                                           user_id=contact_id,
                                           place_of_contact=place_of_contact,
                                           contact_name=x.patient,
                                           relationship=relationship,
                                           cumulative_contact_hours=cumulative_contact_hours))

            db.session.commit()
            return redirect(url_for('view_patient_info', id=id))

    return response


@app.route('/suspected')
@login_required
def suspected():
    name = current_user.user_name

    s = "Suspected"
    charts = Record.query.filter_by(status=s).all()

    response = make_response(render_template('suspected.html', charts=charts, name = name))
    response.headers["Cache-Control"]= "no-cache, no-store, must-revalidate"
    response.headers['Pragma'] = 'no-cache'
    return response


@app.route('/infected')
@login_required
def infected():
    name = current_user.user_name

    i = "Infected"
    charts = Record.query.filter_by(status=i).all()

    response = make_response(render_template('infected.html', charts=charts, name = name))
    response.headers["Cache-Control"]= "no-cache, no-store, must-revalidate"
    response.headers['Pragma'] = 'no-cache'
    return response


@app.route('/exposed')
@login_required
def exposed():
    name = current_user.user_name

    e = "Exposed"
    charts = Record.query.filter_by(status=e).all()

    response = make_response(render_template('exposed.html', charts=charts, name = name))
    response.headers["Cache-Control"]= "no-cache, no-store, must-revalidate"
    response.headers['Pragma'] = 'no-cache'
    return response


@app.route('/dispatch', methods=['POST', 'GET'])
@login_required
def dispatch():
    name = current_user.user_name

    n = 3000

    show = "none"

    r = "Requesting"
    emerge = Record.query.filter_by(status=r).order_by(Record.request_start_time.desc()).all()
    mail = Record.query.filter_by(status="Accepted For Dispatch").order_by(Record.response_start_time.desc()).all()
    sent = Record.query.filter_by(status="Dispatching").order_by(Record.response_start_time.desc()).all()

    gh = Record.query.filter_by(status_message = "None").filter_by(status = r).all()

    for ft in gh:
        ft.status_message = "Requesting EMS"
        put = ft.request_start_time
        db.session.add(Happen(user_id = ft.user_id, post = ft.status_message,
                                  post_time = put))
        db.session.commit()

    v = datetime(1970, 1, 1)
    elf = DispatchForm()
    req = RequestForm()
    santa = SendForm()

    response = make_response(render_template('dispatch.html', santa=santa, elf=elf, sent=sent, emerge=emerge,
                                             req=req, v=v, n=n, mail=mail, name = name, show =show))
    response.headers["Cache-Control"]= "no-cache, no-store, must-revalidate"
    response.headers['Pragma'] = 'no-cache'

    if req.validate_on_submit():
        p_n = req.patient_name.data
        c_d = req.current_condition.data
        adr = req.current_location.data

        tr = Record.query.filter_by(patient = p_n).first()
        tr.request_start_time = datetime.utcnow()
        tr.current_condition = c_d
        tr.current_location = adr

        db.session.commit()

        return redirect(url_for('dispatch'))

    if elf.validate_on_submit():
        id = request.form.get("accept")
        if id is not None:
            tr = Record.query.filter_by(user_id = id).first()
            tr.status_message = "Accepted For Dispatch"
            tr.status = "Dispatching"
            tr.response_start_time = datetime.utcnow()

            put = tr.response_start_time
            db.session.add(Happen(user_id = id, post = tr.status_message,
                                  post_time = put))

            db.session.add(Dispatch(user_id = id, patient=tr.patient,
                                    address=tr.current_location,
                                    request_start_time=tr.request_start_time,
                                    dispatch_start_time=datetime.utcnow(),
                                    current_condition=tr.current_condition,
                                    status_message="Accepted For Dispatch"))

            db.session.commit()

            return redirect(url_for('dispatch'))

    if santa.validate_on_submit():
        id = request.form.get("patch")
        st = Record.query.filter_by(user_id = id).first()
        st.status = "Accepted For Dispatch"

        dt = Dispatch.query.filter_by(user_id = id).first()
        dt.dispatch_wait_time = datetime.utcnow()

        st.time_waited = datetime.utcnow()
        st.status_message = "Dispatching"

        put = st.time_waited
        db.session.add(Happen(user_id = id, post = st.status_message,
                                  post_time = put))

        db.session.commit()

        return redirect(url_for('dispatch'))

    return response



@app.route('/progress')
@login_required
def progress():
    name = current_user.user_name

    h = "Hospitalized"
    a = "Recovered"
    charts = Record.query.filter_by(status=h).all()
    register = Record.query.filter_by(status=a).all()

    response = make_response(render_template('progress.html', charts=charts, register=register, name = name))
    response.headers["Cache-Control"]= "no-cache, no-store, must-revalidate"
    response.headers['Pragma'] = 'no-cache'
    return response


@app.route('/add patient', methods=['POST', 'GET'])
@login_required
def patient():
    form = InputForm()

    if request.method == "GET":
        name = current_user.user_name
        response = make_response(render_template('form_input_new_patient_to_database.html',
                                                 name = name, form = form))
        response.headers["Cache-Control"]= "no-cache, no-store, must-revalidate"
        response.headers['Pragma'] = 'no-cache'

        return response

    patients = form.patients.data
    address = form.address.data
    physician = form.physician.data
    user_id = uuid.uuid4().hex
    status = form.status.data
    age = form.age.data
    gender = form.gender.data
    date_posted = datetime.utcnow()
    preexisting_conditions = form.preexisting_conditions.data
    hospital = form.hospital.data
    admission_date = datetime.utcnow()
    triggers = form.triggers.data
    insurance = form.insurance.data
    preference = form.preference.data
    beliefs = form.beliefs.data
    organ_donor = form.organ_donor.data
    allergies = form.allergies.data
    current_medication = form.current_medication.data
    previous_medical_history = form.previous_medical_history.data
    lifestyle_choices = form.lifestyle_choices.data
    episodes = 0


    db.session.add(Record(user_id=user_id, patient=patients, address=address,
                          physician=physician, status=status, age=age,
                          gender=gender, date_posted=date_posted,
                          preexisting_conditions=preexisting_conditions,
                          hospital=hospital, admission_date=admission_date,
                          triggers=triggers, insurance=insurance,
                          preference=preference, beliefs=beliefs,
                          organ_donor=organ_donor, allergies=allergies,
                          current_medication=current_medication,
                          previous_medical_history=previous_medical_history,
                          lifestyle_choices=lifestyle_choices,
                          episodes=episodes))

    if status == "Requesting":
        trx = Record.query.filter_by(user_id = user_id).first()
        trx.status_message = "Requesting EMS"
        put = trx.request_start_time
        db.session.add(Happen(user_id = trx.user_id, post = trx.status_message,
                                  post_time = put))

    db.session.commit()

    return redirect(url_for('dashboard'))


@app.route('/registration', methods=['GET', 'POST'])
def registration():
    form = RegisterForm()
    Login = LoginForm()

    regex = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,6}$'


    def redirect_destination(default):
        destination_url = request.args.get("next")

        if not destination_url:
            destination_url = url_for(default)

        return redirect(destination_url)

    if request.method == "GET":
        return render_template('registration.html', form = form, login = Login)

    else:
        if form.validate_on_submit():
            hashed_password = generate_password_hash(form.password.data, method='sha512', salt_length=8)

            username = form.user_name.data
            email = form.email.data
            password = hashed_password
            practitioner_id = uuid.uuid4().hex

            user = Register.query.filter_by(user_name = form.user_name.data).first()
            mail = Register.query.filter_by(email = form.email.data).first()

            expression = (re.search(regex, email))
            if expression:
                if user:
                    flash("That User Name Is Taken - Please Try Again")
                    return redirect(url_for('registration'))

                elif mail:
                    flash("That Email Is Taken - Please Try Again")
                    return redirect(url_for('registration'))

                else:
                    db.session.add(Register(user_name = username, email = email,
                                            password=password,
                                            practitioner_id=practitioner_id))
                    db.session.commit()

                    new_user = Register.query.order_by(Register.id.desc()).first()
                    login_user(new_user)

                    flash("Registration completed - ")

                    return redirect(url_for('dashboard'))

            else:
                flash("That is not a valid Email format - Please use the following format - 'person@example.com'")
                return redirect(url_for('registration'))

        if Login.validate_on_submit():
            user = Register.query.filter_by(user_name = Login.user_name.data).first()
            mail = Register.query.filter_by(email = Login.user_name.data).first()

            if user:
                if check_password_hash(user.password, Login.password.data):
                    login_user(user)

                    flash("Welcome")

                    return redirect_destination(default='dashboard')

                else:
                    flash("Invalid Password - Please Try Again")
                    return redirect(url_for('registration'))

            elif mail:
                if check_password_hash(mail.password, Login.password.data):
                    login_user(mail)

                    flash("Welcome")

                    return  redirect(url_for('dashboard'))

                else:
                    flash("Invalid Password - Please Try Again")
                    return redirect(url_for('registration'))

            flash("Invalid Login Credentials - Please Try Again")
            return redirect(url_for('registration'))



@app.route('/Requesting', methods=['GET', 'POST'])
def req():
    return dispatch()


@app.route('/Accepted For Dispatch', methods=['GET', 'POST'])
def afd():
    return dispatch()


@app.route('/Dispatching', methods=['GET', 'POST'])
def dpg():
    return dispatch()


admin.add_view(MyModelView(Record, db.session))
admin.add_view(MyModelView(Register, db.session))
admin.add_view(MyModelView(Occurrence, db.session))
admin.add_view(MyModelView(Message, db.session))
admin.add_view(MyModelView(LocationHistory, db.session))
admin.add_view(MyModelView(Dispatch, db.session))
admin.add_view(MyModelView(Happen, db.session))


if __name__ == "__main__":
    app.run(debug=True)
