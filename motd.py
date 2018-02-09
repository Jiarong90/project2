from flask import Flask, render_template, request, flash, redirect, url_for, session
from pubmotd import healthtips
from _datetime import datetime
from monitoring import Monitoring
from bson import json_util
import json
import time
from Book import Book
from Magazine import Magazine
from chat import Chat
import firebase_admin
from firebase_admin import credentials, db
from wtforms import Form, StringField, TextAreaField, RadioField, SelectField, validators, PasswordField
import random
from flask_wtf.file import FileField, FileAllowed , FileRequired
from flask_wtf import FlaskForm

cred = credentials.Certificate(
    'cred/motd-4d9cb-firebase-adminsdk-4hl57-1a90475830.json')
default_app = firebase_admin.initialize_app(cred, {
    'databaseURL': 'https://motd-4d9cb.firebaseio.com/a'
})

root = db.reference()
app = Flask(__name__)



@app.route('/home')
def home():
    return render_template('motdhome.html')


@app.route('/chathome')
def chathome():

    return render_template('userchathome.html')


@app.route('/chathomedoc')
def chathomedoc():
    username = session['username']
    print(username)

    return render_template('doctorchathome.html')


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


class SendMessage(Form):
    message = TextAreaField('Message', [
        validators.Length(min=1),
        validators.DataRequired()
    ])


userlist = []


@app.route('/chatroom', methods=['GET', 'POST'])
def msgs():
    form = SendMessage(request.form)
    if request.method == 'POST' and form.validate():
        username = session['username']
        print(username)
        if username not in userlist:
            userlist.append(username)

        message = form.message.data
        chatnumber = datetime.time(datetime.now())
        chatnumber = str(chatnumber)

        msg = Chat(message, username, chatnumber)
        msg_db = root.child('chathistory' + username)
        print(username)
        msg_db.push({
            'message': msg.get_message(),
            'username': msg.get_username(),
            'chatnumber': msg.get_chatnumber()

        })

        flash('Message Sent', 'success')
    print(userlist)
    username = session['username']
    timenow = datetime.time(datetime.now())
    print(timenow)
    chathist = root.child('chathistory' + username).get()
    list = []
    if chathist is not None:
        for chatid in chathist:
            eachmsg = chathist[chatid]
            msg = Chat(eachmsg['message'], eachmsg['username'], eachmsg['chatnumber'])
            msg.set_chatid(chatid)
            list.append(msg)

    return render_template('chat.html', form=form, chathist=list, username=username, now=timenow)


@app.route('/viewusers')
def viewusers():
    print(userlist)
    return render_template('viewusers.html', userlist=userlist)


@app.route('/viewchat', methods=['GET', 'POST'])
def viewchat():
    form = SendMessage(request.form)
    if request.method == 'POST' and form.validate():
        username = session['username']
        print(username)
        chatnumber = 1
        message = form.message.data
        msg = Chat(message, 'Doctor', chatnumber)
        chatno = str(chatnumber)
        msg_db = root.child('chathistory' + username)
        print(username)
        msg_db.push({
            'message': msg.get_message(),
            'username': msg.get_username(),
            'chatnumber': msg.get_chatnumber()

        })

        flash('Message Sent', 'success')
    print(id)
    username = request.args.get('id')
    print(username)
    timenow = datetime.time(datetime.now())
    now = datetime.now()
    chathist = root.child('chathistory' + username).get()
    list = []
    if chathist is not None:
        for chatid in chathist:
            eachmsg = chathist[chatid]
            msg = Chat(eachmsg['message'], eachmsg['username'], 1)
            msg.set_chatid(chatid)
            list.append(msg)
        print(chathist)

    return render_template('viewchat.html', form=form, chathist=list, username=username, timenow=timenow, now=now)

# @app.route('/viewpublications')
# def viewpublications():
#     publications = root.child('publications').get()
#     list = []  # create a list to store all the publication objects
#     for pubid in publications:
#         eachpub = publications[pubid]
#         print(eachpub)
#         pub = Publication(eachpub['title'], eachpub['description'])
#         pub.set_pubid(pubid)
#         print(pub.get_pubid())
#         list.append(pub)
#     print(list)
#     return render_template('view_all_motd.html', publications=list)


@app.route('/monitor')
def monitor():

    queues = root.child('queues').get()
    list = []  # create a list to store all the booking objects


    if queues is not None:
      for pubid in queues:
        eachqueue = queues[pubid]
        if eachqueue['type'] == 'smag':
            magazine = Magazine(eachqueue['title'], eachqueue['publisher'], eachqueue['status'],
                                eachqueue['created_by'], eachqueue['category'], eachqueue['type'],
                                eachqueue['frequency'])
            magazine.set_pubid(pubid)
            print(magazine.get_pubid())
            list.append(magazine)
        else:
            queue = Book(eachqueue['title'], eachqueue['publisher'], eachqueue['status'],
                        eachqueue['created_by'], eachqueue['category'], eachqueue['type'],
                        eachqueue['synopsis'], eachqueue['author'], eachqueue['isbn'],eachqueue['patient_status'])
            queue.set_pubid(pubid)
            list.append(queue)
    return render_template('Monitoring.html',queues=list)


class MonitorForm(Form):
    name = StringField('Name', [
        validators.Length(min=1, max=50),
        validators.DataRequired()])
    status = TextAreaField('Status')

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
    synopsis = StringField('Reason for Appointment', [
        RequiredIf(pubtype='sbook')])
    frequency =  StringField('Phone Number', [RequiredIf(pubtype='sbook')],)

    patient_status = StringField('Patient status', [RequiredIf(pubtype='sbook')], )


@app.route('/viewbookings', methods=['GET', 'POST'])
def viewbookings():
    bookings = root.child('bookings').get()
    list = []  # create a list to store all the booking objects
    form = bookingForm(request.form)
    if bookings is not None:
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
                        eachbooking['synopsis'], eachbooking['author'], eachbooking['isbn'],
                        eachbooking['patient_status']
                        )
            book.set_pubid(pubid)
            list.append(book)

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
                patient_status = form.patient_status.data
                book = Book(title, publisher, status, created_by, category, type, synopsis, author, isbn,patient_status)
                book_db = root.child('queues')
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
                    'create_date': book.get_created_date(),
                    'patient_status': book.get_patient_status()
                })

                flash('Appointment Sucessfully Sent.', 'success')

    return render_template('view_all_booking.html', bookings=list, form=form)


class MotdForm(Form):
    title = StringField('Title', [
        validators.Length(min=1, max=150),
        validators.DataRequired()])
    description = TextAreaField('Description')


@app.route('/createtip', methods=['GET', 'POST'])
def new():
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


@app.route('/updatemonitor/<string:id>/', methods=['GET', 'POST'])
def update_monitor(id):
    print(id)
    url = 'Monitoring/' + id
    eachqueue = root.child(url).get()
    detail = Monitoring(Book(eachqueue['title'], eachqueue['publisher'], eachqueue['status'],
                        eachqueue['created_by'], eachqueue['category'], eachqueue['type'],
                        eachqueue['synopsis'], eachqueue['author'], eachqueue['isbn'],eachqueue['patient_status']))
    patient_status = 'Currently serving'
    name = detail.get_name()
    book = Book(title, publisher, status, created_by, category, type, synopsis, author, isbn, patient_status)
    monitor_db = root.child('Monitoring/' + id)
    monitor_db.set({
        'title': book.get_title(),
        'type': book.get_type(),
        'category': book.get_category(),
        'status': book.get_status(),
        'author': book.get_author(),
        'publisher': book.get_publisher(),
        'isbn': book.get_isbnno(),
        'synopsis': book.get_synopsis(),
        'created_by': book.get_created_by(),
        'create_date': book.get_created_date(),
        'patient_status': book.get_patient_status()
        })

    flash('Magazine Updated Sucessfully.', 'success')

    return redirect(url_for('monitor'))



@app.route('/update/<string:id>/', methods=['GET', 'POST'])
def update_motd(id):
    print(id)
    form = MotdForm(request.form)
    if request.method == 'POST' and form.validate():
        title = form.title.data
        description = form.description.data
        pub = healthtips(title, description)
        pub_db = root.child('healthtips/' + id)
        pub_db.set({
            'title': pub.get_title(),
            'description': pub.get_description()
            })

        flash('Magazine Updated Sucessfully.', 'success')

        return redirect(url_for('viewtips'))
    else:
        url = 'healthtips/' + id
        eachpub = root.child(url).get()
        pub = healthtips(eachpub['title'], eachpub['description'])
        pub.set_pubid(id)

        return render_template('update_motd.html', form=form)


@app.route('/delete_booking/<string:id>', methods=['POST'])
def delete_booking(id):
    monitor_db = root.child('Monitoring/' + id)
    monitor_db.delete()
    flash('Publication Deleted', 'success')
    return redirect(url_for('monitor'))


@app.route('/delete_publication/<string:id>', methods=['POST'])
def delete_publication(id):
    pub_db = root.child('healthtips/' + id)
    pub_db.delete()
    flash('Publication Deleted', 'success')

    return redirect(url_for('viewtips'))


@app.route('/delete_msg/<string:id>', methods=['POST'])
def delete_msg(id):
    msg_db = root.child('chathistory/' + id)
    msg_db.delete()
    flash('Message Deleted', 'success')

    return redirect(url_for('msgs'))


class logintest(Form):
    username = StringField('username', [
        validators.length(min=5, max=30),
        validators.DataRequired()],
                           render_kw={'placeholder': 'Full Name'})


@app.route('/logintest')
def index():
    if 'username' in session:
        username = session['username']
        if username is not None:
            return 'Logged in as ' + username + '<br>' + \
                   "<b><a href = '/logout'>click here to log out</a></b>"
    return "You are not logged in <br><a href = '/login'></b>" + \
        "click here to log in</b></a>"

# @app.route('/createtip', methods=['GET', 'POST'])
# def new():
#     form = MotdForm(request.form)
#     if request.method == 'POST' and form.validate():
#         title = form.title.data
#         description = form.description.data
#         pub = healthtips(title, description)
#         pub_db = root.child('healthtips')
#         pub_db.push({
#             'title': pub.get_title(),
#             'description': pub.get_description()
#         })
#
#         flash('Message Inserted Successfully.', 'success')
#
#         return redirect(url_for('viewtips'))
#
#     return render_template('create_motd.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = logintest(request.form)
    if request.method == 'POST':
        username = form.username.data
        session['username'] = username
        print(session['username'])

        flash('Login successful')
        return redirect(url_for('msgs'))
    return render_template('chatlogin.html', form=form)


@app.route('/logout')
def logout():
    # remove the username from the session if it is there
    session.pop('username', None)
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.secret_key = 'sekret123'
    app.run()

