#importing required libraries
import itertools
from ntpath import join
from pickle import TRUE
from tkinter import END, N
from flask import Flask, url_for, render_template, flash, request, redirect, session,logging,request,jsonify
from flask_sqlalchemy import SQLAlchemy
import numpy as np
import pandas as pd
from sklearn import metrics
import warnings
warnings.filterwarnings('ignore')
from feature import generate_data_set
# Gradient Boosting Classifier Model
from sklearn.ensemble import GradientBoostingClassifier
import sqlite3 as sql
import os
from forms import LoginForm, RegisterForm
from werkzeug.security import generate_password_hash, check_password_hash


currentdirectory = os.path.dirname(os.path.abspath(__file__))


data = pd.read_csv("phishing.csv")
#droping index column
data = data.drop(['Index'],axis = 1)
# Splitting the dataset into dependant and independant fetature

X = data.drop(["class"],axis =1)
y = data["class"]

# instantiate the model
gbc = GradientBoostingClassifier(max_depth=4,learning_rate=0.7)

# fit the model
gbc.fit(X,y)

app = Flask(__name__)

# Database Configuration and Creating object of SQLAlchemy

app.config['SECRET_KEY'] = '!9m@S-dThyIlW[pHQbN^'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:/Project/URL_DETECTION/Save_URL.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
# Create User Model which contains id [Auto Generated], name, username, email and password
class User(db.Model):
    __tablename__ = 'userdata'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(256), unique=True)



@app.route("/signin",methods = ['GET', 'POST'])
def signin():
    # Creating Login form object
    form = LoginForm(request.form)
    # verifying that method is post and form is valid
    if request.method == 'POST' and form.validate:
        # checking that user is exist or not by email
        user = User.query.filter_by(email = form.email.data).first()

        if user:
            # if user exist in database than we will compare our database hased password and password come from login form 
            if check_password_hash(user.password, form.password.data):
                # if password is matched, allow user to access and save email and username inside the session
                # flash('You have successfully logged in.', "success")
                session['logged_in'] = True
                session['email'] = user.email 
                session['username'] = user.username
                # After successful login, redirecting to home page
                resp = redirect(url_for('home'))
                resp.set_cookie('email',  user.email)
                return resp

            else:
                # if password is in correct , redirect to login page
                # flash('Username or Password Incorrect', "Danger")


                return redirect(url_for('signin'))
    # rendering login page
    return render_template("signin.html")


@app.route("/signup",methods = ['GET', 'POST'])
def signup():
    # Creating RegistrationForm class object
    form = RegisterForm(request.form)

    # Cheking that method is post and form is valid or not.
    if request.method == 'POST' and form.validate():

        # if all is fine, generate hashed password
        hashed_password = generate_password_hash(form.password.data, method='sha256')

        # create new user model object
        new_user = User(

            username = form.username.data, 

            email = form.email.data,

            password = hashed_password )

        # saving user object into data base with hashed password
        db.session.add(new_user)

        db.session.commit()

        # flash('You have successfully registered', 'success')

        # if registration successful, then redirecting to login Api
        return redirect(url_for('signin'))

    else:
        # if method is Get, than render registration form
     	return render_template("signup.html")



@app.route("/")
def home():
    sepr = " "
    connection = sql.connect("Save_URL.db",timeout=10)
    Cursor = connection.cursor()
    query1 = "Select Fake from FakeURL where Fake_Count > 5 "
    Cursor.execute(query1)
    connection.commit()
    FakeList = list(itertools.chain.from_iterable(Cursor.fetchall()))
    print(FakeList)
    print(len(FakeList))
    return render_template("home.html",xx= -1,FakeList = FakeList)




@app.route("/addreview",methods=["GET", "POST"])
def addreview():
    if request.method == "POST":
        if not session.get("logged_in"):
            return redirect("/signin")
        else :
            fullname = request.form["review_name"]
            Review = request.form["review_message"]
            connection = sql.connect("Save_URL.db")
            Cursor = connection.cursor()
            query1 = "insert into ReviewSection values ('{n}','{n1}')" .format(n= fullname, n1 = Review)
            Cursor.execute(query1)
            connection.commit()
            return render_template('home.html',fullname=fullname,Review=Review )

def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d

@app.route('/showAllReviews',methods=["GET"])
def showAllReviews():
    connection = sql.connect("Save_URL.db")
    connection.row_factory = dict_factory
    Cursor = connection.cursor()
    query1 = "select * from ReviewSection" 
    reviews = Cursor.execute(query1).fetchall()
    return jsonify(list(reviews))

@app.route("/predict", methods=["GET", "POST"])
def predict():
    if request.method == "POST":

        url = request.form["url"]
        x = np.array(generate_data_set(url)).reshape(1,30)
        y_pred =gbc.predict(x)[0]
        #1 is safe
        #-1 is unsafe
        y_pro_phishing = gbc.predict_proba(x)[0,0]
        y_pro_non_phishing = gbc.predict_proba(x)[0,1]
        # if(y_pred ==1 ):
        if(y_pred == 1):
            pred = "It is {0:.2f} % safe to go ".format(y_pro_phishing*100)
            return render_template('home.html',xx =round(y_pro_non_phishing,2),url=url )
        else:
            connection = sql.connect("Save_URL.db",timeout=10)
            Cursor = connection.cursor()
            query1 = "Select Fake,Fake_Count from FakeURL where Fake  =  ('{n}')" .format(n= url) 
            Cursor.execute(query1)
            connection.commit()
            # sepr = ""

            data = list(itertools.chain.from_iterable(Cursor.fetchall()))
            if len(data) == 0:
                query1 = "insert into FakeURL values( ('{n}'),1)".format(n= url)
                Cursor.execute(query1)
                connection.commit()
            else:
                if data[1] == 1:
                    data.insert(1,2)
                else:
                    val = data[1]
                    val = int(val)
                    val = int(val+1)
                    data[1] = val
                    print(data[1])
                query1 ="update FakeURL set fake_count = ('{d}') where Fake  =  ('{n}')".format(d=data[1],n=url) 
                Cursor.execute(query1)
                connection.commit()


            #  Function To Display Records
                query1 = "Select Fake from FakeURL where Fake_Count  > 5 "
                Cursor.execute(query1)
                connection.commit()
                FakeList = list(itertools.chain.from_iterable(Cursor.fetchall()))
                print(FakeList)

            Cursor.close()
            data.clear
            pred = "It is {0:.2f} % unsafe to go ".format(y_pro_non_phishing*100)
            return render_template('home.html',x =y_pro_non_phishing,url=url, data = data )

    #return render_template("index.html", xx =-1)


@app.route("/logout")
def logout():
    session['logged_in'] = None
    session['email'] = None
    session['username'] = None
    return redirect("/")


if __name__ == "__main__":
    db.create_all()
    app.run(debug=True)
