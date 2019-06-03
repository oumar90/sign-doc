from flask import Flask, render_template, request, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms_sqlalchemy.fields import QuerySelectField
from io import BytesIO



app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///filestorage.db'
app.config['SECRET_KEY'] = 'secret'

db = SQLAlchemy(app)

# class FileContents(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     name = db.Column(db.String(300))
#     data = db.Column(db.LargeBinary)

class Choice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    extra = db.Column(db.String(50))

    def __repr__(self): 
        return "<Choice {} >".format(self.name)

def choice_query():
    return Choice.query

class ChoiceForm(FlaskForm):
    opts = QuerySelectField(query_factory=choice_query, allow_blank=True, get_label='id')



@app.route('/')
def index():
    form = ChoiceForm()
    return render_template('index.html', form=form)

# @app.route('/upload', methods=['POST'])
# def upload():

#     file = request.files['inputFile']

#     newFile = FileContents(name=file.filename, data=file.read())
#     db.session.add(newFile)
#     db.session.commit()



#     return 'Saved' + file.filename + 'to database.'

# @app.route('/download')
# def download():

#     file_data = FileContents.query.filter_by(id=1).first()

#     return send_file(BytesIO(file_data.data), attachment_filename="flask.pdf",as_attachment=True)

 
if __name__ == '__main__':
    app.run(debug=True)







    import os
from flask import Flask, flash, request, redirect, url_for
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = '/path/to/the/uploads'
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/', methods=['GET', 'POST'])
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
            return redirect(url_for('uploaded_file',
                                    filename=filename))
    return '''
    <!doctype html>
    <title>Upload new File</title>
    <h1>Upload new File</h1>
    <form method=post enctype=multipart/form-data>
      <input type=file name=file>
      <input type=submit value=Upload>
    </form>
    '''