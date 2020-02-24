# coding=utf-8
import os
import sys
reload(sys)
sys.setdefaultencoding('utf-8')

##### SERVER SETTINGS #####
SECRET_KEY = os.urandom(128)
SQLALCHEMY_DATABASE_URI = "mysql://root:root@localhost:3306/pan?charset=utf8"
SESSION_TYPE = "filesystem"
SESSION_FILE_DIR = "/tmp/flask_session"
SESSION_COOKIE_HTTPONLY = True
UPLOAD_FOLDER = 'static/uploads'
CERTIFICATE_FOLDER ='static/certificate'
CONFIG_FOLDER = 'static' + os.sep + 'config'
DEBUG=True
MYSQL_USER = 'root'
MYSQL_PASSWORD = 'root'
DATEBASE_NAME = 'pan'

##### SUPER USER #####
ADMINNAME = 'admin'
ADMINPASSWORD = '$bcrypt-sha256$2a,12$3VJQUi85Wp35MDJ43zbxo.$tyI./jGvFmEIJ2hhlaUgUUmPJ1Ch5iS'
