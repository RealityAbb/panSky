from flask import Flask, render_template, request, redirect, abort, session, jsonify, json as json_mod, url_for
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.mail import Mail, Message
from logging.handlers import RotatingFileHandler
from flask.ext.session import Session
from datetime import timedelta
import logging
import os
import sqlalchemy
def create_app():
    app = Flask("CTFd", static_folder="../static", template_folder="../templates")
    with app.app_context():
        app.config.from_object('CTFd.config')
        app.permanent_session_lifetime = timedelta(minutes=30)

        from CTFd.models import db, Users, EquipmentsStatus
        from CTFd import models
        db.init_app(app)
        db.create_all() 

        app.db = db
        # app.setup = True

        global mail
        mail = Mail(app)

        Session(app)

        from CTFd.views import init_views
        init_views(app)
        from CTFd.errors import init_errors
        init_errors(app)
        from CTFd import auth
        auth.init_auth(app)
        #from CTFd.auth import init_auth
        #init_auth(app)
        from CTFd.utils import init_utils
        init_utils(app)
        return app

