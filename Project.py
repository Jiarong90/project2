#!/usr/bin/python
from flask import Flask, render_template,  request , flash , redirect, url_for , session , send_from_directory
from wtforms import Form, StringField, TextAreaField, RadioField, SelectField , validators , PasswordField
from flask_security import SQLAlchemyUserDatastore, Security
from flask_sqlalchemy import SQLAlchemy
from flask_bootstrap import Bootstrap
from flask_mail import Mail
from flask_security import UserMixin, RoleMixin, login_required

from articleinfo import ArticleInfo
from Magazine import Magazine
from Book import Book
from Clinic import Clinic
from Disease import Disease

from flask_wtf.file import FileField, FileAllowed , FileRequired
from flask_uploads import UploadSet, configure_uploads, IMAGES, patch_request_class
from flask_wtf import FlaskForm

from chat import Chat
import random
from pubmotd import healthtips
import firebase_admin
from firebase_admin import credentials, db


cred = credentials.Certificate('./cred/oopp-shaq-firebase-adminsdk-1j479-4539b4b30b.json')
default_app = firebase_admin.initialize_app(cred, {
    'databaseURL': 'https://oopp-shaq.firebaseio.com/'
})


root = db.reference()


#Set up locations where uploaded file will be stored
UPLOAD_PHOTOS_DEST = 'C:\Garena\Libary\static\images'





app = Flask(__name__)
app.config.update(
    DEBUG=False,
    SQLALCHEMY_DATABASE_URI='sqlite:///users.db',
    SECRET_KEY='James Bond',
    SECURITY_REGISTERABLE=True,
    SECURITY_PASSWORD_SALT = 'Some_salt',
    SECURITY_SEND_REGISTER_EMAIL = False
)
app.config['SECRET_KEY'] = 'I have a dream'
app.config['UPLOADED_PHOTOS_DEST'] = UPLOAD_PHOTOS_DEST
#only upload photo by UploadSet function
photos = UploadSet('photos', IMAGES)
#call configure_upload to store configuration of flask upload into flask app
configure_uploads(app, photos)
patch_request_class(app)  # set maximum file size, default is 16MB


db = SQLAlchemy(app)

Bootstrap(app)
Mail(app)
roles_users = db.Table('roles_users', db.Column('user_id', db.Integer(),
                                                db.ForeignKey('user.id')),
                       db.Column('role_id', db.Integer(),
                                 db.ForeignKey('role.id')))


class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    active = db.Column(db.Boolean())
    confirmed_at = db.Column(db.DateTime())
    roles = db.relationship('Role', secondary=roles_users,
                            backref=db.backref('users', lazy='dynamic'))

user_datastore = SQLAlchemyUserDatastore(db, User, Role)
Security(app, user_datastore)




class INFO(Form):
    title = StringField('Title', [
        validators.DataRequired()
    ])
    info = TextAreaField('Description', [
        validators.DataRequired()
    ])
@app.route('/admin')
def motdhome():
    return render_template('motdhome.html')


@app.route('/motdpage')
def motd():
    tips = root.child('healthtips').get()
    list = []  # create a list to store all the publication objects
    for pubid in tips:
        eachpub = tips[pubid]
        print(eachpub)
        pub = healthtips(eachpub['title'], eachpub['description'])
        pub.set_pubid(pubid)
        print(pub.get_pubid())
        list.append(pub)
    rndmsg = random.choice(list)
    print(rndmsg.get_title())

    return render_template('MOTD.html', rndmsg=rndmsg)

@app.route('/viewtips')
def viewtips():
    tips = root.child('healthtips').get()
    list = []  # create a list to store all the publication objects
    for pubid in tips:
        eachpub = tips[pubid]
        print(eachpub)
        pub = healthtips(eachpub['title'], eachpub['description'])
        pub.set_pubid(pubid)
        print(pub.get_pubid())
        list.append(pub)
    print(list)
    return render_template('view_all_motd.html', publications=list)


class SendMessage(Form):
    message = TextAreaField('Message', [
        validators.Length(min=1),
        validators.DataRequired()
    ])


@app.route('/chatroom/<email>', methods=['GET', 'POST'])
def msgs(email):
    user = User.query.filter_by(email=email).first()
    form = SendMessage(request.form)
    if request.method == 'POST' and form.validate():
        session['username'] = email
        userlist = []
        username = session['username']
        print(username)
        if username not in userlist:
            userlist.append(username)
        chatnumber = 1
        for user in userlist:
            chatnumber += 1
        message = form.message.data
        msg = Chat(message, username, chatnumber)
        msg_db = root.child('chathistory')
        msg_db.push({
            'message': msg.get_message(),
            'username': msg.get_username(),
            'chatnumber': msg.get_chatnumber()

        })

        flash('Message Sent', 'success')





    chathist = root.child('chathistory').get()
    list = []
    if chathist is not None:
        for chatid in chathist:
            eachmsg = chathist[chatid]
            print(eachmsg)
            msg = Chat(eachmsg['message'], user , 1)
            msg.set_chatid(chatid)
            print(msg.get_chatid())
            list.append(msg)
    print(list)
    print(chathist)

    return render_template('chat.html', form=form, chathist=list)


class LoginForm(Form):
    username = StringField('Username', [validators.DataRequired()])
    password = PasswordField('Password', [validators.DataRequired()])




class MotdForm(Form):
    title = StringField('Title', [
        validators.Length(min=1, max=150),
        validators.DataRequired()])
    description = TextAreaField('Description')


@app.route('/createtip', methods=['GET', 'POST'])
def newtip():
    form = MotdForm(request.form)
    if request.method == 'POST' and form.validate():
        title = form.title.data
        description = form.description.data
        pub = healthtips(title, description)
        pub_db = root.child('healthtips')
        pub_db.push({
            'title': pub.get_title(),
            'description': pub.get_description()
        })

        flash('Message Inserted Successfully.', 'success')

        return redirect(url_for('viewtips'))

    return render_template('create_motd.html', form=form)


@app.route('/update/<string:id>/', methods=['GET', 'POST'])
def update_motd(id):
    form = MotdForm(request.form)
    if request.method == 'POST' and form.validate():
        title = form.title.data
        description = form.description.data
        pub = healthtips(title, description)

        pub_db = root.child('tips/' + id)
        pub_db.set({
            'title': pub.get_title(),
            'description': pub.get_description()
            })

        flash('Magazine Updated Sucessfully.', 'success')

        return redirect(url_for('viewpublications'))
    else:
        url = 'tips/' + id
        eachpub = root.child(url).get()
        pub = healthtips(eachpub['title'], eachpub['description'])
        pub.set_pubid(id)

        return render_template('update_motd.html', form=form)

@app.route('/article')
def home():
    newinfo = root.child('newinfo').get()
    list = []
    for i in newinfo:
        eachinfo = newinfo[i]
        info = ArticleInfo(eachinfo['title'],
                           eachinfo['info'])
        list.append(info)


    return render_template('admin.html', newinfo=list)

@app.route('/ch')
def homech():
    translator ('en', 'zh-TW', home.html)
    return render_template('admin.html')


@app.route('/editarticle', methods=['GET', 'POST'])
def edit():
    form = INFO(request.form)
    if request.method == 'POST' and form.validate():
        title = form.title.data
        info = form.info.data

        information = ArticleInfo(title, info)

        information_db = root.child('newinfo')
        information_db.push({
            'title': information.get_title(),
            'info': information.get_info()
        })

        flash('Article Information Updated Successfully', 'success')

        return redirect(url_for('home'))

    return render_template('editarticle1.html', form=form)




@app.route('/chat/<email>')
def profile(email):
    user = User.query.filter_by(email=email).first()
    form='form'
    return render_template('chat.html',email=email,user=user,form=form)
@app.route('/post_user',methods=['POST'])
def post_user():
    user = User(request.form['username'],request.form['email'])
    db.session.add(user)
    db.session.commit()
    return redirect(url_for('home'))

@app.route('/login')
def Login():

    return render_template('login_user.html')

@app.route('/clinichome')
def clinichome():
    cliniclist = get_clinics()
    diseaselist = get_diseases()
    print('clinichomeee')
    print(cliniclist)
    countclinic = len(cliniclist)
    print(countclinic)
    countdisease = len(diseaselist)
    print(countdisease)


    newinfo = root.child('newinfo').get()
    countarticles = len(newinfo)
    print(countarticles)
    tips = root.child('healthtips').get()
    counttips = len(tips)
    print(counttips)

    totalcount = countclinic + countdisease + countarticles + counttips

    clinicpercent = '{0:.1f}'.format((countclinic / totalcount * 100))

    diseasepercent = '{0:.1f}'.format((countdisease / totalcount * 100))

    articlepercent = '{0:.1f}'.format((countarticles / totalcount * 100))

    tippercent = '{0:.1f}'.format((counttips / totalcount * 100))
    print(totalcount)

    return render_template('clinichome.html', countclinic=countclinic,countdisease=countdisease,countarticles=countarticles,counttips=counttips
                           ,clinicpercent=clinicpercent,diseasepercent=diseasepercent,articlepercent=articlepercent,tippercent=tippercent)



class RequiredIf(object):

    def __init__(self, *args, **kwargs):
        self.conditions = kwargs

    def __call__(self, form, field):
        for name, data in self.conditions.items():
            if name not in form._fields:
                validators.Optional()(field)
            else:
                condition_field = form._fields.get(name)
                if condition_field.data == data:
                    validators.DataRequired().__call__(form, field)
                else:
                    validators.Optional().__call__(form, field)

@app.route('/register',methods=['GET','POST'])
def index():
 return render_template('register_user.html')




@app.route('/Logout')
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return render_template('home.html')


class RequiredIf(object):

    def __init__(self, *args, **kwargs):
        self.conditions = kwargs

    def __call__(self, form, field):
        for name, data in self.conditions.items():
            if name not in form._fields:
                validators.Optional()(field)
            else:
                condition_field = form._fields.get(name)
                if condition_field.data == data:
                    validators.DataRequired().__call__(form, field)
                else:
                    validators.Optional().__call__(form, field)

@app.route('/monitor')
def monitor():
    return render_template('monitoring.html')


@app.route('/main')
def main():
    return render_template('home.html')


@app.route('/')
def loggedin():
    return render_template('home2.html')

@app.route('/viewbookings')
def viewbookings():
    bookings = root.child('bookings').get()
    list = []  # create a list to store all the booking objects
    for pubid in bookings:

        eachbooking = bookings[pubid]

        if eachbooking['type'] == 'smag':
            magazine = Magazine(eachbooking['title'], eachbooking['publisher'], eachbooking['status'],
                                eachbooking['created_by'], eachbooking['category'], eachbooking['type'],
                                eachbooking['frequency'])
            magazine.set_pubid(pubid)
            print(magazine.get_pubid())
            list.append(magazine)
        else:
            book = Book(eachbooking['title'], eachbooking['publisher'], eachbooking['status'],
                        eachbooking['created_by'], eachbooking['category'], eachbooking['type'],
                        eachbooking['synopsis'], eachbooking['author'], eachbooking['isbn'])
            book.set_pubid(pubid)
            list.append(book)

    return render_template('view_all_booking.html', bookings=list)


class  bookingForm(Form):
    title = StringField('NRIC', [
        validators.Length(min=1, max=150),
        validators.DataRequired()])
    pubtype = RadioField('Gender', choices=[('sbook', 'Male'), ('smag', 'Female')], default='sbook')
    category = StringField('Email', [validators.DataRequired()],

                           default='')
    publisher = StringField('Name', [
        validators.Length(min=1, max=100),
        validators.DataRequired()])
    status = StringField('Birthday', [validators.DataRequired()])

    isbn = StringField('Choice Of Clinic', [
        validators.Length(min=1, max=100),
        RequiredIf(pubtype='sbook')])
    author = StringField('Drug Allergies', [
        validators.Length(min=1, max=100),
        RequiredIf(pubtype='sbook')])
    synopsis = TextAreaField('Reason for Appointment', [
        RequiredIf(pubtype='sbook')])
    frequency =  StringField('Phone Number', [RequiredIf(pubtype='sbook')],)




@app.route('/newbooking', methods=['GET', 'POST'])
def new():
    form = bookingForm(request.form)
    if request.method == 'POST' and form.validate():
        if  form.pubtype.data == 'smag':
            title = form.title.data
            type = form.pubtype.data
            category = form.category.data
            status = form.status.data
            frequency = form.frequency.data
            publisher = form.publisher.data
            created_by = "U0001" # hardcoded value

            mag = Magazine(title, publisher, status, created_by, category, type, frequency)

            mag_db = root.child('bookings')
            mag_db.push({
                    'title': mag.get_title(),
                    'type': mag.get_type(),
                    'category': mag.get_category(),
                    'status': mag.get_status(),
                    'frequency': mag.get_frequency(),
                    'publisher': mag.get_publisher(),
                    'created_by': mag.get_created_by(),
                    'create_date': mag.get_created_date()
            })

            flash('Magazine Inserted Sucessfully.', 'success')

        elif form.pubtype.data == 'sbook':
            title = form.title.data
            type = form.pubtype.data
            category = form.category.data
            status = form.status.data
            isbn = form.isbn.data
            author = form.author.data
            synopsis = form.synopsis.data
            publisher = form.publisher.data
            created_by = "U0001"  # hardcoded value

            book = Book(title, publisher, status, created_by, category, type, synopsis, author, isbn)
            book_db = root.child('bookings')
            book_db.push({
                'title': book.get_title(),
                'type': book.get_type(),
                'category': book.get_category(),
                'status': book.get_status(),
                'author': book.get_author(),
                'publisher': book.get_publisher(),
                'isbn': book.get_isbnno(),
                'synopsis': book.get_synopsis(),
                'created_by': book.get_created_by(),
                'create_date': book.get_created_date()
            })

            flash('Appointment Sucessfully Sent.', 'success')




    return render_template('create_booking.html', form=form)





@app.route('/delete_chat/<string:id>', methods=['POST'])
def delete_chat(id):
    pub_db = root.child('publications/' + id)
    pub_db.delete()
    flash('Publication Deleted', 'success')

    return redirect(url_for('viewtips'))


@app.route('/delete_msg/<string:id>', methods=['POST'])
def delete_msg(id):
    msg_db = root.child('chathistory/' + id)
    msg_db.delete()
    flash('Message Deleted', 'success')

    return redirect(url_for('msgs'))


@app.route('/motdlogin', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate():
        username = form.username.data
        password = form.password.data

        if username == 'admin' and password == 'P@ssw0rd':  # hardcoded username and password=
            session['logged_in'] = True  # this is to set a session to indicate the user is login into the system.
            session['username'] = username
            return redirect(url_for('viewtips'))
        else:
            error = 'Invalid login'
            flash(error, 'danger')
            return render_template('chatlogin.html', form=form)

    return render_template('chatlogin.html', form=form)




@app.route('/update/<string:id>/', methods=['GET', 'POST'])
def update_booking(id):
    form = bookingForm(request.form)
    if request.method == 'POST' and form.validate():
        if form.pubtype.data == 'smag':
            title = form.title.data
            type = form.pubtype.data
            category = form.category.data
            status = form.status.data
            frequency = form.frequency.data
            publisher = form.publisher.data
            created_by = "U0001"  # hardcoded value
            mag = Magazine(title, publisher, status, created_by, category, type, frequency)
            # create the magazine object
            mag_db = root.child('bookings/' + id)
            mag_db.set({
                    'title': mag.get_title(),
                    'type': mag.get_type(),
                    'category': mag.get_category(),
                    'status': mag.get_status(),
                    'frequency': mag.get_frequency(),
                    'publisher': mag.get_publisher(),
                    'created_by': mag.get_created_by(),
                    'create_date': mag.get_created_date()
            })

            flash('Magazine Updated Sucessfully.', 'success')

        elif form.pubtype.data == 'sbook':
            title = form.title.data
            type = form.pubtype.data
            category = form.category.data
            status = form.status.data
            isbn = form.isbn.data
            author = form.author.data
            synopsis = form.synopsis.data
            publisher = form.publisher.data
            created_by = "U0001"  # hardcoded value

            book = Book(title, publisher, status, created_by, category, type, synopsis, author, isbn)
            mag_db = root.child('bookings/' + id)
            mag_db.set({
                'title': book.get_title(),
                'type': book.get_type(),
                'category': book.get_category(),
                'status': book.get_status(),
                'author': book.get_author(),
                'publisher': book.get_publisher(),
                'isbn': book.get_isbnno(),
                'synopsis': book.get_synopsis(),
                'created_by': book.get_created_by(),
                'create_date': book.get_created_date()
            })
        else:
            url = 'bookings/' + id
            eachpub = root.child(url).get()

            if eachpub['type'] == 'smag':
                magazine = Magazine(eachpub['title'], eachpub['publisher'], eachpub['status'], eachpub['created_by'],
                                    eachpub['category'], eachpub['type'], eachpub['frequency'])

                magazine.set_pubid(id)
                form.title.data = magazine.get_title()
                form.pubtype.data = magazine.get_type()
                form.category.data = magazine.get_category()
                form.publisher.data = magazine.get_publisher()
                form.status.data = magazine.get_status()
                form.frequency.data = magazine.get_frequency()
            elif eachpub['type'] == 'sbook':
                book = Book(eachpub['title'], eachpub['publisher'], eachpub['status'], eachpub['created_by'],
                            eachpub['category'], eachpub['type'],
                            eachpub['synopsis'], eachpub['author'], eachpub['isbn'])
                book.set_pubid(id)
                form.title.data = book.get_title()
                form.pubtype.data = book.get_type()
                form.category.data = book.get_category()
                form.publisher.data = book.get_publisher()
                form.status.data = book.get_status()
                form.synopsis.data = book.get_synopsis()
                form.author.data = book.get_author()
                form.isbn.data = book.get_isbnno()

            return render_template('update_publication.html', form=form)

    flash('Book Updated Successfully.', 'success')

    return redirect(url_for('viewbookings'))




@app.route('/viewclinic')
def viewclinic():
    clinics = root.child('clinics').get()
    countNorth = 0
    countCentral = 0
    countEast = 0
    countWest = 0
    cliniclist = []  # create a list to store all the publication objects
    for clinicid in clinics:
        eachclinic = root.child('clinics/'+clinicid).get() #or eachpublication = publications[pubid]
        print(eachclinic)
        clinic = Clinic(eachclinic['title'],eachclinic['address'],eachclinic['phone'],
                            eachclinic['openingHour'],eachclinic['busNo'],eachclinic['mrtStation'],
                            eachclinic['hospital'],eachclinic['created_by'],eachclinic['areaName'],
                            eachclinic['region'],eachclinic['photo'])
        clinic.set_clinicid(clinicid)

        cliniclist.append(clinic)
        if clinic.get_region()=='N':
            countNorth += 1
        elif clinic.get_region()=='C':
            countCentral += 1
        elif clinic.get_region()=='E':
            countEast += 1
        elif clinic.get_region()=='W':
            countWest += 1

    return render_template('viewclinic.html', clinics=cliniclist,countNorth = countNorth,countCentral=countCentral,countEast=countEast,countWest=countWest)


@app.route('/viewdisease')
def viewdisease():
    diseasepublication = root.child('diseases').get()
    diseaselist = []  # create a list to store all the publication objects
    for diseaseid in diseasepublication:
        eachdisease = root.child('diseases/'+diseaseid).get() #or eachpublication = publications[pubid]
        print(eachdisease)
        disease = Disease(eachdisease['title'],  eachdisease['cause'],
                          eachdisease['symptom'],
                          eachdisease['treatment'],
                          eachdisease['complication'], eachdisease['specialist'],
                          eachdisease['created_by'])
        disease.set_diseaseid(diseaseid)

        diseaselist.append(disease)

    return render_template('viewdisease.html', diseasepublication=diseaselist)




class ClinicForm(FlaskForm):
    title = StringField('Name', [
        validators.Length(min=1, max=150),
        validators.DataRequired()])

    address = StringField('Address', [validators.Length(min=1, max=100) ] )
    phone = StringField('Phone No', [validators.Length(min=1, max=100) ])

    openingHour = StringField('Opening hours', [validators.Length(min=1, max=100) ])
    busNo = StringField('bus No', [validators.Length(min=1, max=100) ])
    mrtStation = StringField('Nearest mrt', [validators.Length(min=1, max=100) ])
    hospital = StringField('Nearest hospitals', [validators.Length(min=1, max=100) ])
    areaName = StringField('Area name(eg Tampines)',[validators.Length(min=1,max=100)  ])
    region = SelectField('Region',
        choices=[('N','North') , ('C','Central'), ('E','East'),('W','West')] )
    photo = FileField('Enter image of clinic',validators=[FileRequired(),FileAllowed(photos, u'Image only!')])



class DiseaseForm(Form):
    title = StringField('Name', [
        validators.Length(min=1, max=1500),
        validators.DataRequired()])
    cause = StringField('Causes', [
        validators.Length(min=1, max=1000),
        ])
    symptom = StringField('Symptoms', [
        validators.Length(min=1, max=1000),
        ])
    treatment = StringField('Treatments', [
        validators.Length(min=1, max=1000),
        ])
    complication = StringField('Complications', [
        validators.Length(min=1, max=1000),
        ])
    specialist = StringField('Specialists', [
        validators.Length(min=1, max=1000),
        ])



@app.route('/createclinic',methods=['GET','POST'])
def upload_clinic():
    clinicform = ClinicForm() #(request.form)
    if clinicform.validate_on_submit(): #form.validate()
        title = clinicform.title.data
        address = clinicform.address.data
        phone = clinicform.phone.data
        openingHour = clinicform.openingHour.data
        busNo = clinicform.busNo.data
        mrtStation = clinicform.mrtStation.data
        hospital = clinicform.hospital.data
        areaName = clinicform.areaName.data
        region = clinicform.region.data
        filename = photos.save(clinicform.photo.data)
        file_url = photos.url(filename)
        created_by = "U0001"
        #mag = Magazine(title, publisher, status, created_by, category, type, frequency)
        cli = Clinic(title,address,phone,openingHour,busNo,mrtStation,hospital,created_by,areaName,region,
                         filename)
        cli_db = root.child('clinics')
        cli_db.push({
                'title': cli.get_title(),
                'address': cli.get_address(),
                'phone': cli.get_phone(),
                'openingHour': cli.get_openingHour(),
                'busNo': cli.get_busNo(),
                'mrtStation': cli.get_mrtStation(),
                'hospital': cli.get_hospital(),
                'areaName': cli.get_areaName(),
                'region': cli.get_region(),
                'photo': cli.get_photo(),
                'created_by': cli.get_created_by(),
                'created_date': cli.get_created_date()
            })
        flash('Clinic Inserted Sucessfully.', 'success')


        return redirect(url_for('viewclinic'))


    return render_template('createclinic.html',clinicform=clinicform)


@app.route('/createdisease',methods=['GET','POST'])
def createdisease():
    diseaseform = DiseaseForm(request.form) #(request.form)
    if request.method =='POST' and diseaseform.validate():
        title = diseaseform.title.data
        cause = diseaseform.cause.data
        symptom = diseaseform.symptom.data
        treatment = diseaseform.treatment.data
        complication = diseaseform.complication.data
        specialist = diseaseform.specialist.data
        created_by = "U0001"  # hardcoded value
        #mag = Magazine(title, publisher, status, created_by, category, type, frequency)
        dis = Disease(title, cause, symptom, treatment, complication, specialist, created_by)
        dis_db = root.child('diseases')
        dis_db.push({
            'title': dis.get_title(),
            'cause': dis.get_cause(),
            'symptom': dis.get_symptom(),
            'treatment': dis.get_treatment(),
            'complication': dis.get_complication(),
            'specialist': dis.get_specialist(),
            'created_by': dis.get_created_by(),
            'created_date': dis.get_created_date()
        })

        flash('Disease Inserted Sucessfully.', 'success')

        return redirect(url_for('viewdisease'))

    return render_template('createdisease.html',diseaseform=diseaseform)


@app.route('/uploads/<filename>')
def send_image(filename):
    return send_from_directory("static/images", filename)

@app.route('/update_clinic/<string:id>/', methods=['GET', 'POST'])
def update_clinic(id):
    clinicform = ClinicForm()
    if clinicform.validate_on_submit():
        title = clinicform.title.data
        address = clinicform.address.data
        phone = clinicform.phone.data
        openingHour = clinicform.openingHour.data
        busNo = clinicform.busNo.data
        mrtStation = clinicform.mrtStation.data
        hospital = clinicform.hospital.data
        areaName = clinicform.areaName.data
        region = clinicform.region.data
        filename = photos.save(clinicform.photo.data)
        file_url = photos.url(filename)
        created_by = "U0001"  # hardcoded value
        #             cli = Clinic(title,type,address,phone,openingHour,busNo,mrtStation,hospital,created_by,areaName,region,photo)
            # create the clinic object
        #             cli_db = root.child('publications/'+ id )
        cli = Clinic(title, address, phone, openingHour, busNo, mrtStation, hospital, created_by, areaName,
                     region,filename)
        cli_db = root.child('clinics/'+id)
        cli_db.set({
            'title': cli.get_title(),
            'address': cli.get_address(),
            'phone': cli.get_phone(),
            'openingHour': cli.get_openingHour(),
            'busNo': cli.get_busNo(),
            'mrtStation': cli.get_mrtStation(),
            'hospital': cli.get_hospital(),
            'areaName': cli.get_areaName(),
            'region': cli.get_region(),
            'photo': cli.get_photo(),
            'created_by': cli.get_created_by(),
            'created_date':cli.get_created_date()
            })

        flash('Clinic Updated Sucessfully.', 'success')

        return redirect(url_for('viewclinic'))

    else:
        url = 'clinics/' + id
        eachcli = root.child(url).get()


        clinic = Clinic(eachcli['title'] , eachcli['address'],eachcli['phone'],
                         eachcli['openingHour'],eachcli['busNo'],eachcli['mrtStation'],eachcli['hospital'],
                            eachcli['created_by'],eachcli['areaName'], eachcli['region'],eachcli['photo'])

        clinic.set_clinicid(id)
        clinicform.title.data = clinic.get_title()
        clinicform.address.data = clinic.get_address()
        clinicform.phone.data = clinic.get_phone()
        clinicform.openingHour.data = clinic.get_openingHour()
        clinicform.busNo.data = clinic.get_busNo()
        clinicform.mrtStation.data = clinic.get_mrtStation()
        clinicform.hospital.data = clinic.get_hospital()
        clinicform.areaName.data = clinic.get_areaName()
        clinicform.region.data = clinic.get_region()
        clinicform.photo.data = clinic.get_photo()

        return render_template('update_clinic.html', clinicform=clinicform)


@app.route('/update_disease/<string:id>/', methods=['GET', 'POST'])
def update_disease(id):
    diseaseform = DiseaseForm(request.form)
    if request.method =='POST' and diseaseform.validate():
        title = diseaseform.title.data
        # this should be pubtype
        cause = diseaseform.cause.data
        symptom = diseaseform.symptom.data
        treatment = diseaseform.treatment.data
        complication = diseaseform.complication.data
        specialist = diseaseform.specialist.data
        created_by = "U0001"  # hardcoded value
        #             cli = Clinic(title,type,address,phone,openingHour,busNo,mrtStation,hospital,created_by,areaName,region,photo)
            # create the clinic object
        #             cli_db = root.child('publications/'+ id )
        dis = Disease(title, cause, symptom, treatment, complication, specialist, created_by)
        dis_db = root.child('diseases/' + id)
        dis_db.set({
            'title': dis.get_title(),
            'cause': dis.get_cause(),
            'symptom': dis.get_symptom(),
            'treatment': dis.get_treatment(),
            'complication': dis.get_complication(),
            'specialist': dis.get_specialist(),
            'created_by': dis.get_created_by(),
            'created_date': dis.get_created_date()
        })

        flash('Disease Updated Sucessfully.', 'success')

        return redirect(url_for('viewdisease'))

    else:
        url = 'diseases/' + id
        eachdis = root.child(url).get()
        disease = Disease(eachdis['title'], eachdis['cause'], eachdis['symptom'],
                              eachdis['treatment'],
                              eachdis['complication'], eachdis['specialist'],
                              eachdis['created_by'])
        disease.set_diseaseid(id)
        diseaseform.title.data = disease.get_title()
        diseaseform.cause.data = disease.get_cause()
        diseaseform.symptom.data = disease.get_symptom()
        diseaseform.treatment.data = disease.get_treatment()
        diseaseform.complication.data = disease.get_complication()
        diseaseform.specialist.data = disease.get_specialist()


        return render_template('update_disease.html', diseaseform=diseaseform)

@app.route('/delete_clinic/<string:id>', methods=['POST'])
def delete_clinic(id):
    cli_db = root.child('clinics/' + id)
    cli_db.delete()
    flash('Clinic information deleted', 'success')
    return redirect(url_for('viewclinic'))

@app.route('/delete_disease/<string:id>', methods=['POST'])
def delete_disease(id):
    dis_db = root.child('diseases/'+id)
    dis_db.delete()
    flash('Disease information deleted','success')
    return redirect(url_for('viewdisease'))


@app.route('/searchclinic')
def searchclinic():
    cliniclist = get_clinics()
    return render_template('searchclinic.html', specific_clinic=cliniclist)

@app.route('/searchdisease')
def searchdisease():
    diseaselist = get_diseases()
    return render_template('searchdisease.html', specific_disease=diseaselist)

def get_clinics(): #get clinic_list from firebase
    clinics = root.child('clinics').get()
    cliniclist = []  # create a list to store all the publication objects

    for clinicid in clinics:

        eachclinic = clinics[clinicid]


        print(eachclinic)
        clinic = Clinic(eachclinic['title'],eachclinic['address'], eachclinic['phone'],
                            eachclinic['openingHour'], eachclinic['busNo'], eachclinic['mrtStation'],
                            eachclinic['hospital'], eachclinic['created_by'], eachclinic['areaName'],
                            eachclinic['region'], eachclinic['photo'])
        print(eachclinic)
        clinic.set_clinicid(clinicid)
        print(clinic.get_clinicid())
        cliniclist.append(clinic)

    return cliniclist


def get_diseases(): #get clinic_list from firebase
    diseases = root.child('diseases').get()
    diseaselist = []  # create a list to store all the publication objects

    for diseaseid in diseases:

        eachdisease = diseases[diseaseid]


        print(eachdisease)
        disease = Disease(eachdisease['title'], eachdisease['cause'],
                          eachdisease['symptom'],
                          eachdisease['treatment'], eachdisease['complication'],
                          eachdisease['specialist'],
                          eachdisease['created_by'])
        print(eachdisease)
        disease.set_diseaseid(eachdisease)
        print(disease.get_diseaseid())
        diseaselist.append(disease)

    return diseaselist

def get_clinic(keyword):
    cliniclist = get_clinics()
    specific_clinic = []
    for clinic in cliniclist:
        if clinic.get_title().find(keyword) >= 0:
            specific_clinic.append(clinic)
    return specific_clinic

def get_disease(keyword):
    diseaselist = get_diseases()
    specific_disease = []
    for disease in diseaselist:
        if disease.get_title().find(keyword) >= 0:
            specific_disease.append(disease)
    return specific_disease


@app.route('/clinicinfo/<title>' , methods=['GET','POST'])
def get_clinic(title):
    cliniclist = get_clinics()    #get list of clinics from firebase
    clinicnames = get_clinicnames()  #get list of names of clinics
    print('Hellocliniclist from firebase')
    print(cliniclist)
    specific_clinic = []
    clinic_name = [] # list for clinic
    print('TESTING@@@@')
    for clinic in cliniclist:
        if clinic.get_title().find(title) >= 0:
            specific_clinic.append(clinic)
    display_specific_clinic = specific_clinic
    print(display_specific_clinic)

    print('Hello clinicnames')
    print(clinicnames)
    return render_template('/clinicinfo.html', display_clinic=display_specific_clinic)

@app.route('/diseaseinfo/<title>')
def get_disease(title):
    diseaselist = get_diseases()    #get list of clinics from firebase
    print('below is the diseaselisttttttts')
    print(diseaselist)
    specific_disease = []
    for disease in diseaselist:
        if disease.get_title().find(title) >= 0:
            specific_disease.append(disease)
    display_specific_disease = specific_disease
    print('below is teh list of specific one disease!')
    print(display_specific_disease)
    print(specific_disease)

    return render_template('/diseaseinfo.html', display_disease=display_specific_disease)

def get_clinicnames(): #get list of names of the clinics
    cliniclist = get_clinics()
    clinicnames = []  # create a list to store all the clinicnames objects
    for clinic in cliniclist:
        clinicnames.append(clinic.get_title())
    return clinicnames

@app.route('/delete_booking/<string:id>', methods=['POST'])
def delete_booking(id):
    mag_db = root.child('bookings/' + id)
    mag_db.delete()
    flash('booking Deleted', 'success')

    return redirect(url_for('viewbookings'))

@app.route('/adminhome')
def adminhome():
    return render_template('adminhome.html')

@app.route('/lcbgod')
def lcbgod():
    cliniclist = get_clinics()
    countEast = 0
    for clinic in cliniclist:
        if clinic.get_region()=='E':
            countEast +=1
    return render_template('lcbgod.html',specific_clinic=cliniclist,countEast=countEast)

if __name__ == '__main__':
    app.secret_key = 'secret123'
    app.run(port='80')


