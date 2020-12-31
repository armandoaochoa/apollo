from flask import Flask
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

# just added
#from SQLAlchemy import create_engine 
#from SQLAlchemy.orm import sessionmaker

# app instance
app = Flask(__name__)

# app configuration
app.config.from_object(Config)

# database & migration handling
db = SQLAlchemy(app)
migrate = Migrate(app, db)

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

