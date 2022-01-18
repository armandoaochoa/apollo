import os
basedir = os.path.abspath(os.path.dirname(__file__))

class Config(object):
  SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'
  SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///' + os.path.join(basedir, 'app.db')
  SQLALCHEMY_TRACK_MODIFICATIONS = False

  FILESTACK_API_KEY = os.environ.get('FILESTACK_API_KEY')
  FILESTACK_APP_SECRET = os.environ.get('FILESTACK_APP_SECRET')
  FILESTACK_WEBHOOK_SECRET = os.environ.get('FILESTACK_WEBHOOK_SECRET')

  SENDGRID_API_KEY = os.environ.get('SENDGRID_API_KEY')

  TEMPORARY_FILE_PATH = os.environ.get('TEMPORARY_FILE_PATH') or './temp_watermark_ops/'

  EMAIL_FROM = os.environ.get('EMAIL_FROM')

  DOMAIN = os.environ.get('DOMAIN') or 'http://127.0.0.1:5000'

  PROD = os.environ.get('PROD') or 'production' # 'development'


