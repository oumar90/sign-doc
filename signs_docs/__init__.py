from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from werkzeug.utils import secure_filename
# from flask_wtf.csrf import CSRFProtect


from flask_avatars import Avatars


UPLOAD_FOLDER = 'signs_docs/static/medias/uploads/'
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])


app = Flask(__name__)
app.config['SECRET_KEY']='b4f8d207f45b6ca20d28a8f11859b737'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqldb://admin:admin123@localhost/flaskappsign'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
db = SQLAlchemy(app)
# csrf = CSRFProtect(app)
# app.config.from_object('config.settings')
# csrf.init_app(app)

avatars = Avatars(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = "info"


def allowed_file(filename):
    return '.' in filename and \
    			filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def create_app():
    

    app.config.from_object('config.settings')

    csrf.init_app(app)

from signs_docs import routes



