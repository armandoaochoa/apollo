from flask import Flask
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

# app instance
app = Flask(__name__)

# app configuration
app.config.from_object(Config)

# database & migration handling
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# must be at bottom to avoid circ refs
from app import routes, models