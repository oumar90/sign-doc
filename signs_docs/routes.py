from flask import (Flask, render_template, redirect, 
request, url_for, session, flash, jsonify,g, current_app, send_file)
from signs_docs import db, bcrypt, app, login_manager, allowed_file
from flask_login import login_user, logout_user, login_required, current_user
from signs_docs.models import User, Message, GenerateKeys, StockeKeys
from sqlalchemy import text 
from werkzeug.utils import secure_filename


from signs_docs.module import  *
from oudjirasign import *
import os
import secrets 
from base64 import b64encode




def save_file(fichier):
	hash_fichier = secrets.token_urlsafe(10)
	_,file_extention = os.path.splitext(fichier.filename)
	nom_fichier = hash_fichier + file_extention
	path_fichier = os.path.join(current_app.root_path, "static/medias", nom_fichier)
	fichier.save(path_fichier)
	return nom_fichier


# APP_ROOT = os.path.dirname(os.path.abspath(__file__))

# Route qui retourne la page d'accueil
@app.route('/home')
@app.route('/')
def home():
	return render_template("home.html")
# Route qui retourne la page d'accueil
@app.route('/')
def index():
	return render_template("index.html")

# Route qui gère l'enregistremenet d'un utilisateur
@app.route('/register', methods=['GET', 'POST'])
def register():

	if request.method == 'POST':
		nom = request.form.get('nom')
		prenom = request.form.get('prenom')
		pseudo = request.form.get('pseudo')
		password = request.form.get('password')
		confirm_password = request.form.get('password1')

		if password == confirm_password:
			user = User.query.filter_by(pseudo=pseudo).first()
			if user:
				flash("le pseudo est déjà pris, veillez choisir un autre svp!", "danger")
				return redirect(url_for('register'))
			email = User.query.filter_by(email=request.form.get('email')).first()
			if email:
				flash("l'emil est déjà pris, veillez choisir un autre svp!", "danger")
				return redirect(url_for('register'))

			email = request.form.get('email')
			hashed_password = bcrypt.generate_password_hash(password)

			user = User(nom=nom,prenom=prenom,pseudo=pseudo,email=email,password=hashed_password)
			db.session.add(user)
			db.session.commit()

			flash("Votre compte a été cré avec succès", "success")

			return redirect(url_for('login'))
		else:
			flash("Les mot de passe ne correspondent pas", "danger")
			return render_template("register.html")

				
	return render_template("register.html")

# Route qui gère la connexion (login)
@app.route('/login', methods=['GET', 'POST'])
def login():

	if request.method == 'POST':
		pseudo = request.form.get('pseudo')
		password = request.form.get('password')

		user = User.query.filter_by(pseudo=pseudo).first()
		
		if user and  bcrypt.check_password_hash(user.password, password):
			login_user(user)
			
			# flash("Vous êtes connecté avec succès", "success")
			next = request.args.get('next')
			return redirect(next or url_for('home'))

		flash("pseudo ou mot de passe incorrect, veillez verifier et réeseyer", "danger")
		return redirect(url_for('login'))
	
	return render_template('login.html')

# Route qui gère la déconnexion
@app.route('/logout', methods=['GET', 'POST'])
@login_required 
def logout():
	logout_user()
	return redirect(url_for('login'))

# Route qui gère l'affichage du profile
@app.route('/profile', methods=['GET', 'POST'])
@login_required 
def profile():
	return render_template('profiles/profile.html')

# gerere la date de footer
@app.context_processor
def inject_now():
	from datetime import datetime
	return {'now': datetime.utcnow()}

# Route qui permet de generer les clés
@app.route('/profile/generatekey', methods=['GET', 'POST'])
@login_required
def generatekey():

	user = User.query.all()

	if request.method == 'GET':
		return render_template("profiles/generatekey.html")

	else:
		priv,pub = generatersakeys()
		pub=pub.decode('utf-8')
		priv=priv.decode('utf-8')

		# alea_string = secrets.token_urlsafe(4)

		try:
			private_key_name = current_user.pseudo + "private.pem"
			public_key_name = current_user.pseudo + "public.pem"

			private_name = open("signs_docs/static/keys/" + private_key_name, "w")
			private_name.write(priv)
			private_name.close()

			public_nale = open("signs_docs/static/keys/" + public_key_name, "w")
			public_nale.write(pub)
			public_nale.close()

			date = request.form.get('date')

			
			# user1 = User.query.filter_by(email=email).first()
			

			new_key = GenerateKeys(nom_public_key=public_key_name, date_end_key=date)
			db.session.add(new_key)
			db.session.commit()
			

			stocke = StockeKeys(id_user=current_user.id, key_id=new_key.id_key)
			db.session.add(stocke)
			db.session.commit()
			flash("Votre paire de clef a été générer avec succès", "success")
			return render_template("profiles/generatekey.html", pub=pub, priv=priv)
		except :
			flash("Vous avez déjà une paire de clef. Mais si vous avez perdu ou vous voulez revoquer votre clef,\
				veillez supprimer la clef public", "info")
			return  redirect(url_for("show_keys"))

# Route qui gère la sauvegarde de paire de clef
@app.route('/profile/save_key/', methods=['GET', 'POST'])
def save_key():
	user = User.query.fiter_by().first()

	if request.method == 'GET':
		return render_template("profiles/save_key.html")

	else:
		publickeys = request.form.get('publickeys')
		privatekeys = request.form.get('privatekeys')


		return render_template("profiles/save_key.html")
@app.route('/delete', methods=['POST'])
def delete():
	public_key = request.form['public_key']
	
	key = GenerateKeys.query.filter_by(nom_public_key=public_key).first()
	db.session.delete(key)
	db.session.commit()
	return redirect(url_for('show_keys'))

# Route qui gère la génération du certificat
@app.route('/generatecert', methods=['GET', 'POST'])
@login_required
def generatecert():

	if request.method == 'GET':
		return render_template("generatecert.html")

	# Dans le cas de POST, on recupère tous les données des champs 
	# et on appelle la fonction generate_certificat_auto_sign() pour générer le certificat auto signé
	else:
		contryname = request.form['contryname']
		provincename = request.form['provincename']
		localityname = request.form['localityname']
		orgname = request.form['orgname']
		commonname = request.form['commonname']
		domainename = request.form['domainename']
		p,pr,key = generate_keys_rsa()
		
		cert = generate_certificat_auto_sign(
							key,
							contryname,
							provincename,
							localityname,
							orgname,
							commonname,
							domainename
				)
		cert = cert.decode('utf-8')

		return render_template('generatecert.html', cert=cert)


# route pour insère le message à envoyer à un user
@app.route('/profile/send_message', methods=['GET', 'POST'])
@login_required
def send_message():

	user = User.query.all()

	if request.method == 'GET':
		return render_template("profiles/send_message.html", user=user)
	else:

		description = request.form.get('description')
		email= request.form.get('email')
		customFile = save_file(request.files.get('customFile'))
		user1 = User.query.filter_by(email=email).first()
		private_path = request.files['privatekey']

		if private_path:
			privatekey = private_path.read()
			privatekey1 = importPrivateKey(privatekey)
			signature = signer(description, privatekey1)


			if user1.email:
				message = Message(contenu=description,user_id=user1.id,signature=signature,fichier=customFile,author=current_user)
				db.session.add(message)
				db.session.commit()
				flash("Votre message a été envoyé avec succès", "success")
				return render_template("profiles/send_message.html", user=user)
			else:
				flash("Votre message n'a été envoyé, verifier l'utilisateur", "info")
				return render_template("profiles/send_message.html", user=user)
		else:
			flash("Vous n'avez pas selectionner la clef privée", "info")
			return render_template("profiles/send_message.html", user=user)
		

# Route qui gère la reception des messages
@app.route('/profile/receive_message', methods=['GET', 'POST'])
@login_required
def receive_message():
	# On recupère tous les messages par date d'envoi le plus recent
	messages = Message.query.order_by(Message.date_envoi.desc())

	return render_template("profiles/receive_message.html", messages=messages)

# Route qui gère un la verification de l'integrité d'un message
@app.route('/profile/single_message/<int:id_msg>', methods=['GET', 'POST'])
@login_required
def single_message(id_msg):

	# On recupère le message par leur id
	message = Message.query.get(id_msg)

	doc_path = "signs_docs/static/medias/" + message.fichier

	p = open(doc_path, 'rb')
	
	pdfile = p.read()

	# s = hacherdocs(pdfile)

	if request.method == 'GET':
		return render_template("profiles/single_message.html", message=message, pdfile=pdfile)

	# Si on est en mode post, on recupère la clef publique et le message
	publickey = request.files['publickey']
	contenu = request.form['contenu']
	if publickey:
		publickey = publickey.read()
	# On test le champs de clef publique, si c'est vide on léve une exception
	else:
		flash("Tous les champs doivent être remplis! ", "danger")
		return render_template("profiles/single_message.html", message=message, pdfile=pdfile)

	# On essaie de verifier la signature
	try:

		#  On appelle la fonction importPublickey() pour importer la clef public
		# Et la focntion verifier(contenu, publickey, signature) pour verifier la signature.
		publickey = importPublicKey(publickey)
		verify = verifier(contenu, publickey, message.signature)
		
		
		if verify:
			flash("Votre signature est valide.", "success")
			return render_template("profiles/single_message.html", message=message, pdfile=pdfile)
		else:
			flash("Votre signature invalide!!!", "danger")
			return render_template("profiles/single_message.html", message=message, pdfile=pdfile)

	# Dans le cas où on arrive pas à importer la clef publique
	except : 
		flash("Veiller entrer une clef valide!", "danger")
		return render_template("profiles/single_message.html", message=message, pdfile=pdfile)

@app.route('/profile/show_keys/', methods=['GET', 'POST'])
@login_required
def show_keys():

	all_keys = GenerateKeys.query.order_by(GenerateKeys.date_create_key.desc())
	
	if request.method == "GET":
		return render_template('profiles/show_keys.html', all_keys=all_keys)
	return render_template('profiles/show_keys.html', all_keys=all_keys)

# @app.route('/profile/show_key/<int:id_key>', methods=['GET', 'POST'])
# @login_required
# def show_key(id_key):
# 	key = GenerateKeys.query.get(id_key)
# 	if request.method == "GET":
# 		return render_template('profiles/show_key.html', key=key)
# 	return render_template('profiles/show_key.html', key=key)

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        # if user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            return render_template('uploaded_file.html',filename=filename)
    return '''
    <!doctype html>
    <title>Upload new File</title>
    <h1>Upload new File</h1>

    <form method=post enctype=multipart/form-data>
      <input type=file name=file>
      <input type=submit value=Upload>
    </form>
    '''



































