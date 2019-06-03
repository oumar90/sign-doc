from Crypto.PublicKey import RSA
import os
from flask import Flask, render_template, redirect, request, url_for, session, flash
from werkzeug.utils import secure_filename
from flask_mysqldb import MySQL, MySQLdb
from flask_avatars import Avatars
import bcrypt

from module import *

# UPLOAD_FOLDER = '/home/oudjira/Devs/Sign/sign-doc/medias/uploads'
# ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])

app = Flask(__name__)
avatars = Avatars(app)
# app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# app.config['IMAGES_PATH'] = UPLOAD_FOLDER
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
app.config['MYSQL_HOST'] = "localhost"
app.config['MYSQL_USER'] = "admin"
app.config['MYSQL_PASSWORD'] = "admin123"
app.config['MYSQL_DB'] = "flaskapp"
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

mysql = MySQL(app)

@app.route('/')
def home():
	return render_template("home.html")



# création de compte
@app.route('/register', methods=['GET', 'POST'])
def register():
	# Si ya rien on redirige l'user sur la même pas
	if request.method == 'GET':
		return render_template("register.html")

	# Si l'utilisateur remplit le formulaire on les capture dans les variables 
	else:
		nom = request.form['nom']
		prenom = request.form['prenom']
		pseudo = request.form['pseudo']
		email = request.form['email']
		password = request.form['password'].encode('utf-8')
		confirm_password = request.form['password1'].encode('utf-8')

		# On verifie si le deux mot de passe correspondent
		if password == confirm_password:
			# on hache le mot de passe
			hash_password = bcrypt.hashpw(password, bcrypt.gensalt())
			# on verifie si l'email existe déjà, si oui on notifie l'utilisateur
			if len(is_email_exist())>0:
				flash("Le pseudo existe déjà", "danger")
				return render_template("register.html")

			# Si non on continue, et on insert les infos dans la BD 
			else:
				cur = mysql.connection.cursor()
				cur.execute(""" INSERT INTO users(nom, prenom, pseudo, email, password)
							 VALUES(%s, %s, %s, %s, %s)""",(nom,prenom,pseudo,email,hash_password,))
				mysql.connection.commit()
				session['nom'] = nom
				session['prenom'] = prenom
				session['pseudo'] = pseudo
				session['email'] = email

				flash("Votre compte a été crée avec succès", "success")
				return redirect(url_for('login'))
		# Si les mots de passe ne correspondent pas
		else:
			flash("Les mot de passe de ne correspondent pas!", "info")
			return render_template('register.html')


# Fonction pour verifier si l'email exixte déjà
def is_email_exist():
	pseudo = request.form['pseudo']
	cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cur.execute(''' SELECT * FROM users WHERE pseudo=%s ''', (pseudo,))
	user_existe = cur.fetchall()
	return user_existe

# Se connecter
@app.route('/login', methods=['GET', 'POST'])
def login():
	if request.method == 'POST':
		pseudo = request.form['pseudo']
		password = request.form['password'].encode('utf-8')

		cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
		cur.execute(''' SELECT * FROM users WHERE pseudo=%s ''', (pseudo,))
		user = cur.fetchone()
		cur.close()

		if user is None:
			flash("Le pseudo n'existe pas, veiller crée une compte svp!","danger")

		elif len(user) > 0:
			if bcrypt.hashpw(password, user['password'].encode('utf-8')) == user['password'].encode('utf-8'):
				session['nom'] = user['nom']
				session['prenom'] = user['prenom']
				session['pseudo'] = user['pseudo']
				session['email'] = user['email']
				flash("Vous êtes connecté avec succès", "success")

				return redirect(url_for('profile'))
			else:
				flash("Erreur de connexion, verifier votre pseudo an mot de passe!", "danger")
				return render_template('login.html')
		else:
			flash("Erreur de connexion, verifier votre pseudo an mot de passe!", "danger")
			return render_template('login.html')

	return render_template("login.html")

@app.route('/profile')
def profile():
	return render_template("profile.html")


@app.route('/logout',methods=['GET', 'POST'])
def logout():
	session.clear()
	return render_template("login.html")



@app.route('/generatekey', methods=['GET', 'POST'])
def generatekey():
	
	if request.method == 'GET':
		return render_template("generatekey.html")

	else:

		taille = request.form['taille']

		pub, priv, key = generate_keys_rsa()

		pub_key,priv_key = pub.decode('utf-8'), priv.decode('utf-8')

		return render_template("generatekey.html", pub=pub_key, priv=priv_key)





@app.route('/generatecert', methods=['GET', 'POST'])
def generatecert():

	if request.method == 'GET':
		return render_template("generatecert.html")

	else:
		contryname = request.form['contryname']
		provincename = request.form['provincename']
		localityname = request.form['localityname']
		orgname = request.form['orgname']
		orgunitname = request.form['orgunitname']
		commonname = request.form['commonname']
		domainename = request.form['domainename']
		print("OK ici!")
		privatekey =  open("keypriv.txt", 'r')

		private = privatekey.read()

		print("OK ici aussi!")


		cert = generate_certificat_auto_sign(
							private,
							contryname,
							provincename,
							localityname,
							orgname,
							commonname,
							domainename
				)

		privatekey.close()

		return render_template('generatecert.html', private=private)

# gerere la date de footer
@app.context_processor
def inject_now():
	from datetime import datetime
	return {'now': datetime.utcnow()}



# Fonction principale
if __name__ == '__main__':
	app.secret_key = "sqhfçàç=)=!:;*ù$*/9878fqiuf"
	app.run(debug=True)



















































