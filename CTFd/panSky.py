# coding=utf-8
from flask import current_app as app, render_template, render_template_string, request, redirect, abort, jsonify, json as json_mod, url_for, session, send_from_directory
from CTFd.utils import authed, allowed_file, sha512, judge_result, check_ip
from CTFd import initial, ukey,Transport
from CTFd.models import db, Users, Certificates,LeadMachine,Flag,LMIPAddr,LMRoute, DLeadMachineCert, Cipermachine, Terminallogs,Tree, EquipmentsStatus,UploadCertificates

from jinja2.exceptions import TemplateNotFound
from passlib.hash import bcrypt_sha256
from collections import OrderedDict
from werkzeug.utils import secure_filename
from flask import current_app as app
import base64
import logging
import os
import shutil
import re
import sys
import json
import hashlib
import os
import datetime
import time
import chardet
import socket
import struct
import MySQLdb
from generalfunction import SwitchErrorCode
authority = app.config['MYSQL_USER']
password = app.config['MYSQL_PASSWORD']
name = app.config['DATEBASE_NAME']
reload(sys)
sys.setdefaultencoding('utf-8')

def init_views(app):
    @app.route('/main', methods=['GET', 'POST'])
    def mainPage():
        return render_template('main.html')
