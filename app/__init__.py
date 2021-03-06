from flask import Flask
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_talisman import Talisman

from rq import Queue
from rq.job import Job
from worker import conn

# just added
#from SQLAlchemy import create_engine 
#from SQLAlchemy.orm import sessionmaker

# app instance
app = Flask(__name__)

# SSL / Content-Security-Policy
csp = {
  'default-src': [
    '\'self\'',
    '\'unsafe-inline\'',
    'https://www.fileundernda.com',
    'https://www.fileundernda.com',
    'www.fileundernda.com',
    'fileundernda.com'
    'https://ssl.gstatic.com',
    'data:',
    'gap:',
    'https://www.googletagmanager.com',
    'https://code.jquery.com',
    'https://kit.fontawesome.com',
    'https://static.filestackapi.com',
    'https://ka-f.fontawesome.com/',
    'https://www.google-analytics.com',
    'https://upload.filestackapi.com',
    'https://fonts.gstatic.com',
    'https://*.filestackapi.com',
    'https://*.amazonaws.com',
    'https://cdn.filestackcontent.com/'
  ],
  'style-src': [
    '\'self\'',
    '\'unsafe-inline\'',
    'https://www.googletagmanager.com',
    'https://code.jquery.com',
    'https://kit.fontawesome.com',
    'https://static.filestackapi.com',
    'https://ka-f.fontawesome.com/',
    'https://www.google-analytics.com',
    'https://fonts.googleapis.com'
  ],
  'media-src': '*',
  'script-src': [
    '\'self\'',
    '\'unsafe-inline\'',
    'https://fileundernda.com',
    'https://www.fileundernda.com',
    'www.fileundernda.com',
    'fileundernda.com',
    'https://www.googletagmanager.com',
    'https://code.jquery.com',
    'https://kit.fontawesome.com',
    'https://static.filestackapi.com',
    'https://ka-f.fontawesome.com/'
    'https://www.google-analytics.com',
    'https://cdnjs.cloudflare.com',
    'https://cdn.jsdelivr.net'
  ]
}

Talisman(app, content_security_policy=csp)


# app configuration
app.config.from_object(Config)

# database & migration handling
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# redis
q = Queue(connection=conn)

'''
engine = create_engine (
  app.config['SQLALCHEMY_DATABASE_URI'],
  pool_size=5,
  max_overflow=10,
  pool_timeout=1
)
'''

# must be at bottom to avoid circ refs
from app import routes, models

