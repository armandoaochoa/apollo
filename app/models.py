from datetime import datetime
from app import db

class FreeUser(db.Model):
  __tablename__ = 'freeuser'
  id = db.Column(db.Integer, primary_key=True)
  email = db.Column(db.String(120), index=True, unique=True, nullable=False)
  first_name = db.Column(db.String(40), nullable=False)
  last_name = db.Column(db.String(40), nullable=False)
  organization = db.Column(db.String(100))
  status = db.Column(db.String(12), default='unverified')
  premium_conversion = db.Column(db.Boolean, nullable=False, default=False) 
  last_file_share = db.Column(db.DateTime, index=True, nullable=False, default=datetime.utcnow)
  file_shares = db.relationship('FreeFileShare', backref='owner', lazy='dynamic')

class FreeFileShare(db.Model):
  __tablename__ = 'freefileshare'
  id = db.Column(db.Integer, primary_key=True)
  user_id = db.Column(db.Integer, db.ForeignKey('freeuser.id'))
  session_id = db.Column(db.String(120), nullable=True)
  file_type = db.Column(db.String(100), nullable=False)
  file_name = db.Column(db.String(250), nullable=False)
  dashboard_url = db.Column(db.String(250), index=True, nullable=False, unique=True)
  file_url = db.Column(db.String(250), unique=True, nullable=False)
  file_size = db.Column(db.Integer)
  file_upload_id = db.Column(db.String(70), nullable=False, index=True)
  created = db.Column(db.DateTime, index=True, default=datetime.utcnow)
  expiration = db.Column(db.DateTime, index=True) 
  ip_address = db.Column(db.String(45), index=True)
  status = db.Column(db.String(12), index=True, nullable=False, default='unverified')
  stage = db.Column(db.String(24), default='created')
  shares = db.Column(db.Integer, nullable=False, default=0)
  downloads = db.Column(db.Integer, nullable=False, default=0)
  views = db.Column(db.Integer, nullable=False, default=0)
  last_accessed = db.Column(db.DateTime)
  watermarked = db.Column(db.Boolean, default=False, nullable=False)
  paid = db.Column(db.Boolean, default=False, nullable=False)
  recipients = db.relationship('FreeRecipient', backref='file_share', lazy='dynamic')
  use_logs = db.relationship('FreeUseLog', backref='file_share', lazy='dynamic')
  ndas = db.relationship('FreeNDA', backref='file_share', lazy='dynamic')

class FreeFilestackUpload(db.Model):
  __tablename__ = 'freefilestackupload'
  id = db.Column(db.Integer, primary_key=True)
  file_name = db.Column(db.String(250), nullable=False)
  file_type = db.Column(db.String(100), nullable=False)
  file_upload_id = db.Column(db.String(70), index=True, nullable=False)
  file_url = db.Column(db.String(250), unique=True, nullable=False)
  file_size = db.Column(db.Integer, nullable=False)
  time_received = db.Column(db.DateTime, index=True, default=datetime.utcnow)


class FreeRecipient(db.Model):
  __tablename__ = 'freerecipient'
  id = db.Column(db.Integer, primary_key=True)
  file_share_id = db.Column(db.Integer, db.ForeignKey('freefileshare.id'), nullable=False)
  watermarked_file_url = db.Column(db.String(250), unique=True, nullable=True)
  file_type = db.Column(db.String(10))
  invitation_url = db.Column(db.String(250), index=True, unique=True, nullable=False)
  email = db.Column(db.String(120), index=True, nullable=False)
  first_name = db.Column(db.String(40), nullable=False)
  last_name = db.Column(db.String(40), nullable=False)
  organization = db.Column(db.String(100), nullable=True)
  status = db.Column(db.String(30), default='created')
  ip_address = db.Column(db.String(45), index=True)
  nda_required = db.Column(db.Boolean, default=True, nullable=False)
  nda_signed = db.Column(db.Boolean, default=False, nullable=False)
  clicks = db.Column(db.Integer, nullable=False, default=0)
  views = db.Column(db.Integer, nullable=False, default=0)
  downloads = db.Column(db.Integer, nullable=False, default=0)
  nda = db.relationship('FreeNDA', backref='recipient', lazy='dynamic')
  use_logs = db.relationship('FreeUseLog', backref='recipient', lazy='dynamic')
  last_accessed = db.Column(db.DateTime)

class FreeUseLog(db.Model):
  __tablename__ = 'freeuselog'
  id = db.Column(db.Integer, primary_key=True)
  file_share_id = db.Column(db.Integer, db.ForeignKey('freefileshare.id'), nullable=False)
  recipient_id = db.Column(db.Integer, db.ForeignKey('freerecipient.id'), nullable=False)
  action = db.Column(db.String(30), nullable=False)
  timestamp = db.Column(db.DateTime, default=datetime.utcnow)
  ip_address = db.Column(db.String(45), index=True)
  user_agent = db.Column(db.String(200))


class FreeNDA(db.Model):
  __tablename__ = 'freenda'
  id = db.Column(db.Integer, primary_key=True)
  file_share_id = db.Column(db.Integer, db.ForeignKey('freefileshare.id'), nullable=False)
  recipient_id = db.Column(db.Integer, db.ForeignKey('freerecipient.id'), nullable=False)
  signature = db.Column(db.Text, nullable=False)
  file_url = db.Column(db.String(250), nullable=True, unique=True)
  timestamp = db.Column(db.DateTime, default=datetime.utcnow)
  checksum = db.Column(db.String(200), nullable=True, unique=True)
  file_name = db.Column(db.String(250))
  certificate_file_name = db.Column(db.String(250))
  certificate_file_url = db.Column(db.String(250))
  copy_emailed = db.Column(db.Boolean, default=False) 


