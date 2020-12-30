import os
basedir = os.path.abspath(os.path.dirname(__file__))

class Config(object):
  SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'
  SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///' + os.path.join(basedir, 'app.db')
  SQLALCHEMY_TRACK_MODIFICATIONS = False

  FILESTACK_API_KEY = os.environ.get('FILESTACK_API_KEY') or 'Aav2WFMRdTlqC2x0zpLZkz'
  FILESTACK_APP_SECRET = os.environ.get('FILESTACK_APP_SECRET') or 'ISYEHH4PIFEG7I44B77ZS3ALFE'
  FILESTACK_WEBHOOK_SECRET = os.environ.get('FILESTACK_WEBHOOK_SECRET') or 'wpE5zmVSSDK72cUAQMfh'

  SENDGRID_API_KEY = os.environ.get('SENDGRID_API_KEY') or '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'

  TEMPORARY_FILE_PATH = os.environ.get('TEMPORARY_FILE_PATH') or './temp_watermark_ops/'

  EMAIL_FROM = os.environ.get('EMAIL_FROM') or 'armando.ochoa92@gmail.com'

  DOMAIN = os.environ.get('DOMAIN') or 'http://127.0.0.1:5000'

  

