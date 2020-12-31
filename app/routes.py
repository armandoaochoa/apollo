from flask import render_template, redirect, url_for, request, abort
from app import app, db
from app.models import FreeUser, FreeFileShare, FreeFilestackUpload, FreeRecipient, FreeUseLog, FreeNDA
import time, datetime
from filestack import Security as create_security
from filestack.helpers import verify_webhook_signature
from filestack import Client, Filelink
from pprint import pprint
import json
import hashlib
import random, math
import re, requests
import urllib.request
from reportlab.pdfgen import canvas
from reportlab.lib.colors import Color, black, blue, red
from PyPDF2 import PdfFileWriter, PdfFileReader
import os
from multiprocessing import Process
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import (Mail, Attachment, FileContent, FileName, FileType, Disposition)
import textwrap
import base64
from PIL import Image, ImageDraw
#from signapadpy import create_image, Padding
import base64


# Helper function to create Filestack credentials for landing page [public facing]
def create_filestack_creds(json_policy):
  sec = create_security(json_policy, app.config['FILESTACK_APP_SECRET'])
  print(sec.__dict__)
  creds = { 'api_key': app.config['FILESTACK_API_KEY'] } 
  creds['policy'] = sec.policy_b64
  creds['signature'] = sec.signature
  print(creds)
  return creds 

# Helper function to validate POST identification data from posters and recipients
def validate_person(first_name, last_name, organization, email):
  if len(first_name) >= 2 is False or first_name.replace(' ','').isalpha() is False:
    print('Invalid first name.')
    return False
  if len(last_name) >= 2 is False or last_name.replace(' ','').isalpha() is False:
    print('Invalid last name.')
    return False
  if len(organization) != 0 and len(organization) < 2:
    print('Invalid organization.')
    return False
  regex = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
  if re.search(regex, email) is None:
    print('Invalid email.')
    return False
  return True

# Helper function to generate unique hash for private URLs
def generate_unique_hash(raw_unique_string):
  unique_hash = hashlib.md5(raw_unique_string.encode('utf-8')).hexdigest()
  start_index = random.randint(0,5)
  substr_length = min(random.randint(17,28),len(unique_hash))
  end_index = start_index + substr_length
  unique_hash = unique_hash[start_index:end_index]
  return unique_hash

# Helper function to get location from given IP address
def get_location_from_ip(ip_address):
  ip_response = requests.get("https://geolocation-db.com/json/" + str(ip_address) + "&position=true").json()
  if ip_response['country_code'] == 'Not found' or ip_response['country_code'] is None:
    location = 'Unknown'
  else:
    location = ip_response['city'] + ', ' + ip_response['country_code']
  return location

# Helper function to upload a file to Filestack
def fs_upload(file_path):
  json_policy = { 'expiry': int(time.time()) + (5 * 60), 'call': ['pick', 'read', 'convert', 'stat', 'runWorkflow'] }
  security = create_security(json_policy, app.config['FILESTACK_APP_SECRET'])
  filestack_client = Client(app.config['FILESTACK_API_KEY'])
  filestack_response = filestack_client.upload(filepath=file_path, security=security)
  return filestack_response

# Helper function to determine if a file can be converted to PDF for watermarking
def is_convertible_to_pdf(file_name):
  # source: https://helpx.adobe.com/acrobat/kb/supported-file-formats-acrobat-reader.html (3D files excluded)
  convertible_file_extensions = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.rtf', '.ps', '.eps', '.prn', '.bmp', '.jpeg', '.gif', '.tiff', '.png', '.pcx', '.rle', '.dib', '.html', '.wpd', '.odt', '.odp', '.ods', '.odg', '.odf', '.sxw', '.sxi', '.sxc', '.sxd', '.stw', '.psd', '.ai', '.indd', '.dwg', '.dwt', '.dxf', '.dwf', '.dst', '.xps', '.mpp', '.vsd']
  file_extension = os.path.splitext(file_name)[-1].lower()
  return (file_extension in convertible_file_extensions)

@app.route('/')
@app.route('/index')
def index():
  expiry = int(time.time()) + (5 * 60)
  json_policy = { 
    'call': ['pick', 'runWorkflow'], 
    'expiry': expiry
  } 
  creds = create_filestack_creds(json_policy)
  print('TESTING...')
  return render_template('landing.html', **creds)

@app.route('/favicon.ico')
def favicon():
  return os.path.join(app.root_path, 'static') + 'favicon.ico' #, mimetype='image/vnd.microsoft.icon'


# receives webhook payload from Filestack post upload 
@app.route('/f_2k20a7sub', methods=['POST'])
def free_fs_upload():
  print('We made it here at all...')
  if request.method == 'POST':
    print('We made it this far...')

    # resp returns true or false; details returns with error message if applicable 
    # request.data contains payload with upload details -- need to convert to JSON
    # request.headers contains signature from Filestack for authentication
    resp, details = verify_webhook_signature(app.config['FILESTACK_WEBHOOK_SECRET'], request.data, dict(request.headers))
    
    # if webhook is valid and was generated by Filestack
    if resp is True:
      jsonResponse = json.loads(request.data.decode('utf-8'))
      
      fupload_id = jsonResponse['id'] # int
      fupload_name = jsonResponse['text']['filename'] # string
      fupload_size = jsonResponse['text']['size'] # int
      fupload_type = jsonResponse['text']['type'] # string
      fupload_url = jsonResponse['text']['url'] # string

      # create record in FileStackUpload table
      fupload = FreeFilestackUpload(file_upload_id = fupload_id, file_url = fupload_url, file_type = fupload_type, file_size = fupload_size, file_name = fupload_name)
      db.session.add(fupload)
      db.session.commit()

      # find FileShare record and verify that data matches to prevent client falsified records 
      existing_file_share = FreeFileShare.query.filter_by(file_name=fupload_name, file_type=fupload_type, file_url=fupload_url, file_size=fupload_size).first()
      print(existing_file_share)
      
      if existing_file_share is None:
        print('File Share does not exist...')
      else:
        # validation
        rules = [existing_file_share.file_size == fupload_size,
                existing_file_share.file_type == fupload_type,
                existing_file_share.file_url == fupload_url,
                existing_file_share.file_size == fupload_size,
                existing_file_share.file_name == fupload_name]

        if all(rules):
          print('File is valid.')
          existing_file_share.status = 'verified'
          db.session.commit()
        else:
          print('File not valid.')

      return '', 200
      
    else:
      # webhook is invalid
      raise Exception(details['error'])
      abort(400)
  else:
    abort(400)


# receives file upload info and requests submitter's info
@app.route('/id_poster', methods=['POST'])
def free_id_poster():
  if request.method == 'POST':
    file_upload_id = request.form['file_upload_id'].strip() # convert to int
    file_type = request.form['file_type'].strip()
    file_name = request.form['file_name'].strip()
    file_size = int(request.form['file_size'].strip()) # convert to int 
    file_url = request.form['file_url'].strip()

    # (1/5) Get uploader's IP address
    if request.environ.get('HTTP_X_FORWARDED_FOR') is None:
      ip_address = request.environ['REMOTE_ADDR']
    else:
      ip_address = request.environ['HTTP_X_FORWARDED_FOR']

    # (2/5) Generate a unique dashboard URL
    raw_unique_string = file_name + str(file_size) + str(time.time())
    unique_hash = hashlib.md5(raw_unique_string.encode('utf-8')).hexdigest()
    start_index = random.randint(0,5)
    substr_length = min(random.randint(17,28),len(unique_hash))
    end_index = start_index + substr_length
    unique_hash = unique_hash[start_index:end_index]

    # (3/5) Soft validate POST data and ensure file share is unique
    if len(file_url) != 53:
      print("Forged request.")
      abort(400)

    existing_file_share = FreeFileShare.query.filter_by(file_url=file_url).first()
    if existing_file_share is None:
      # (4/5) Create & store new FreeFileShare 
      expiration = datetime.datetime.utcnow() + datetime.timedelta(days=3)
      file_share = FreeFileShare(file_type=file_type, file_name=file_name, file_upload_id=file_upload_id, file_url=file_url, file_size=file_size, ip_address=ip_address, dashboard_url=unique_hash, expiration=expiration)
      db.session.add(file_share)
      db.session.commit()

    # (5/5) Render template - file_upload_id & file_handle used to generate unique link to invite page
    file_handle = file_url.replace('https://cdn.filestackcontent.com/','')
    watermarkable = is_convertible_to_pdf(file_name)

    return render_template('free_poster_id.html', file_upload_id=file_upload_id, file_handle=file_handle, watermarkable=watermarkable)

  else:
    abort(400)

# Creates new User, attaches user to relevant FreeFileShare, and renders recipient invitation form 
@app.route('/invite/<file_share_parameters>', methods=['POST'])
def free_invite(file_share_parameters):
  # (1/6) Get file_upload_id and file_handle from <file_share_parameters> in URL - conjoined by "n0ABjSyn29lM34ds"
  file_upload_id = file_share_parameters.partition('n0ABjSyn29lM34ds')[0]
  file_handle = file_share_parameters.partition('n0ABjSyn29lM34ds')[2]

  # (2/6) Get relevant FreeFileShare
  file_url = 'https://cdn.filestackcontent.com/' + file_handle
  file_share = FreeFileShare.query.filter_by(file_upload_id=file_upload_id, file_url=file_url).first()
  if file_share is None:
    print("Invalid FileShare ID or handle.")
    abort(400)

  # (3/6) Validate POST data 
  first_name = request.form['poster_first_name'].strip()
  last_name = request.form['poster_last_name'].strip()
  email = request.form['poster_email'].strip()
  organization = request.form['poster_organization'].strip()

  if request.form.get('watermarked') == 'on':
    if is_convertible_to_pdf(file_share.file_name):
      watermarked = True
    else:
      watermarked = False
  else:
    watermarked = False

  validation = validate_person(first_name, last_name, organization, email)
  if validation is False:
    abort(400)

  # (4/6) Check if user exists, then create new user or update existing user 
  user = FreeUser.query.filter_by(email=email).first()

  if user is None:
    if len(organization) == 0:
      organization = None
    user = FreeUser(first_name=first_name, last_name=last_name, email=email, organization=organization)
    db.session.add(user)
    db.session.commit()
  else:
    if user.first_name != first_name:
      user.first_name = first_name
    if user.last_name != last_name:
      user.last_name = last_name
    if user.organization is None:
      user_organization = ""
    else:
      user_organization = user.organization
    if user_organization != organization:
      user.organization = organization
    db.session.commit()

  # (5/6) Attach user as owner of FileShare & update watermarked boolean if user indicates to watermark file
  if watermarked is True:
    file_share.watermarked = True
  file_share.owner = user
  db.session.commit()

  print('Made it to the end of user creation!')

  # (6/6) Render recipient invitation template with relevant action URL
  return render_template('free_invite.html', file_upload_id=file_upload_id, file_handle=file_handle)

@app.route('/test_form2')
def test_form2():
  # Starter info
  expiry = int(time.time()) + (5 * 60) # policy valid for 5 minutes
  json_policy = { 
    'call': ['read', 'convert'], 
    'expiry': expiry
  } 
  sec = create_security(json_policy, app.config['FILESTACK_APP_SECRET'])
  api_key = app.config['FILESTACK_API_KEY']
  creds = {
    'policy': sec.policy_b64,
    'signature': sec.signature
  }
  handle = '0hYNgCQHSJWB6vgihiaN'

  embedded_url = 'https://cdn.filestackcontent.com/' + handle + '?' + 'policy' + '=' + creds['policy'] + '&' + 'signature' + '=' + creds['signature']
  print(embedded_url)




  
  #return render_template('free_sign_nda.html', invitation_url=recipient.invitation_url)
  return render_template('test_form.html')


######## TEST SPOT #######
@app.route('/test_form')
def test_form():
  return redirect(url_for('free_recip_viewer', private_invitation_url='0f50cd5bd8f3624d73e7c27a24b'))

  #return render_template('test_form.html')



@app.route('/test_submit_form', methods=['POST'])
def test_submit_form():
  first_name = request.form['first_name'].strip()
  last_name = request.form['last_name']
  email = request.form['email']
  organization = request.form['organization'].strip()
  nda_required = request.form['nda_required']

  print(len(organization))
  print(len(first_name))
  print(organization)

  return redirect(url_for('rview', private_invitation_url='0f50cd5bd8f3624d73e7c27a24b'))

  '''
  if len(organization) == 0:
    organization = None

  new_recipient = FreeRecipient(first_name=first_name,
                                  last_name=last_name,
                                  organization=organization,
                                  email=email,
                                  nda_required=True,
                                  file_share_id=1,
                                  invitation_url='3892374fsasdf983')
  db.session.add(new_recipient)
  db.session.commit()


  return render_template('test_submit_form.html')
  '''
####### TEST SPOT ########


@app.route('/submit/<file_share_parameters>', methods=['POST'])
def free_send(file_share_parameters):
  print('We are here...')
  # creator must verify their email address before anything is sent... 
  # (1/8) Get file_upload_id and file_handle from <file_share_parameters> in URL - conjoined by "n0ABjSyn29lM34ds"
  file_upload_id = file_share_parameters.partition('Xt3iU7L8jYzP03s')[0]
  file_handle = file_share_parameters.partition('Xt3iU7L8jYzP03s')[2]
  
  # (2/8) Get relevant FreeFileShare
  file_url = 'https://cdn.filestackcontent.com/' + file_handle
  file_share = FreeFileShare.query.filter_by(file_upload_id=file_upload_id, file_url=file_url).first()
  if file_share is None:
    print("Invalid FileShare ID or handle.")
    abort(400)

  # (3/8) Get and loop through recipients' POST data -- first convert list of IDs into array, then loop & validate
  recipients = {}
  x = 0
  posted_recipients_index = request.form['recipients_index'].split(',')
  for i in posted_recipients_index:
    recipients[x] = {}
    recipients[x]['first_name'] = request.form["recipients[" + i + "]['first_name']"].strip()
    recipients[x]['last_name'] = request.form["recipients[" + i + "]['last_name']"].strip()
    recipients[x]['organization'] = request.form["recipients[" + i + "]['organization']"].strip()
    recipients[x]['email'] = request.form["recipients[" + i + "]['email']"].strip()
    if request.form.get("recipients[" + i + "]['nda_required']") == 'on':
      recipients[x]['nda_required'] = True
    else:
      recipients[x]['nda_required'] = False
    
    print(recipients[x])
    x += 1
  
  #(4/8) Validate each recipient's information and store to DB
  new_recipient = {}
  for key in recipients:
    if validate_person(recipients[key]['first_name'], recipients[key]['last_name'], recipients[key]['organization'], recipients[key]['email']):
      # (4.1) Create new FreeRecipient and attach the relevant FileShare to it
      raw_unique_string = recipients[key]['email'] + file_share.file_upload_id + str(time.time())
      unique_hash = generate_unique_hash(raw_unique_string)

      if len(recipients[key]['organization']) == 0:
        recipients[key]['organization'] = None

      new_recipient[key] = FreeRecipient(first_name=recipients[key]['first_name'],
                                        last_name=recipients[key]['last_name'],
                                        organization=recipients[key]['organization'],
                                        email=recipients[key]['email'],
                                        nda_required=recipients[key]['nda_required'],
                                        file_share_id=file_share.id,
                                        invitation_url=unique_hash)
      db.session.add(new_recipient[key])
    else:
      print('Invalid user.')
      abort(400)
  
  db.session.commit()
  recipients = file_share.recipients

  # (5/8) Watermark process
  if file_share.watermarked is True:
    print('Watermark indicated by owner.')

    # (5.1) Create filestack credentials 
    expiry = int(time.time()) + (10 * 60)
    json_policy = { 
      'call': ['pick', 'read', 'convert', 'stat', 'runWorkflow'], 
      'expiry': expiry
    } 
    filestack_creds = create_filestack_creds(json_policy)
    
    # (5.2) Build filestack download URL, converting to PDF if necessary 
    file_handle = file_share.file_url.replace('https://cdn.filestackcontent.com/','')
    if file_share.file_type != 'application/pdf':
      print(file_share.file_type)
      print('Time to convert to PDF.')
      file_url = 'https://cdn.filestackcontent.com/security=p:' + filestack_creds['policy'] + ',s:' + filestack_creds['signature'] + '/output=f:pdf/' + file_handle
    else:
      print('No need to convert to PDF.')
      file_url = 'https://cdn.filestackcontent.com/security=p:' + filestack_creds['policy'] + ',s:' + filestack_creds['signature'] + '/' + file_handle

    print(file_url)

    # (5.3-5.7) Define watermark process to loop through recipients and generate custom watermarked PDFs for each
    def watermark():
      # (5.3) Download FreeFileShare file from filestack
      '''
      downloaded_file = requests.get(file_url)
      target_file_name = generate_unique_hash(file_handle + str(random.randint(100,9000)) + str(time.time()))
      target_pdf_path = app.config['TEMPORARY_FILE_PATH'] + target_file_name + '.pdf'
      with open(target_pdf_path, 'wb') as f:
        f.write(downloaded_file.content)
      '''
      target_file_name = generate_unique_hash(file_handle + str(random.randint(100,9000)) + str(time.time()))
      target_pdf_path = app.config['TEMPORARY_FILE_PATH'] + target_file_name + '.pdf'
      response = urllib.request.urlopen(file_url)  
      file = open(target_pdf_path, 'wb')
      file.write(response.read())
      file.close()    

      # (5.4) Loop through recipients and generate custom watermarked PDFs for each then upload & store response URL
      for recipient in recipients:
        # (5.5) Generate custom watermark $text, $subtext_legal, $subtext_ad for each recipient within space limitations
        name = recipient.first_name + recipient.last_name
        num_text_repetitions = math.ceil(45 / len(recipient.first_name + recipient.last_name))
        text = (recipient.first_name + ' ' + recipient.last_name + ' \u2022 ') * num_text_repetitions

        if len(recipient.organization) > 0:
          num_subtext_legal_repetitions = math.ceil(120 / len(recipient.email + recipient.organization))
          subtext_legal = (recipient.email + ' \u2022 ' + recipient.organization + ' \u2022 ') * num_subtext_legal_repetitions
        else:
          num_subtext_legal_repetitions = math.ceil(120 / len(recipient.email + 'CONFIDENTIAL'))
          subtext_legal = (recipient.email + ' \u2022 ' + 'CONFIDENTIAL' + ' \u2022 ') * num_subtext_legal_repetitions
          
        subtext_ad = 'Confidential file securely generated by www.FileUnderNDA.com on ' + str(datetime.datetime.utcnow()) + '. Do not distribute.'

        # (5.6) Generate watermark and save as a PDF
        target_watermark_path = app.config['TEMPORARY_FILE_PATH'] + target_file_name + name + str(random.randint(100,999)) + '_watermark.pdf'
        c = canvas.Canvas(target_watermark_path)
        transparent_gray = Color(.56, .56, .56, alpha=0.5)
        c.setFillColor(transparent_gray)
        c.setFont('Helvetica-Bold', 34)
        c.rotate(55)
        c.drawString(30, 0, text)
        c.setFont('Helvetica-Bold', 15)
        c.drawString(95, 50, subtext_ad)
        c.drawString(45, -35, subtext_legal)
        c.save()

        # (5.7) Open the newly created watermark PDF
        target_watermark = PdfFileReader(open(target_watermark_path, 'rb'))

        # (5.8) Merge watermark with target file
        target_pdf_watermarked = PdfFileWriter()
        target_pdf = PdfFileReader(open(target_pdf_path, 'rb'))
        page_count = target_pdf.getNumPages()

        for page_number in range(page_count):
          input_page = target_pdf.getPage(page_number)
          input_page.mergePage(target_watermark.getPage(0))
          target_pdf_watermarked.addPage(input_page)

        target_pdf_watermarked_path = app.config['TEMPORARY_FILE_PATH'] + target_file_name + name + str(random.randint(100,999)) + '_wm.pdf'
        with open(target_pdf_watermarked_path, 'wb') as outputStream:
          target_pdf_watermarked.write(outputStream)

        # (5.9) Upload to FileStack 
        try:
          filestack_response = fs_upload(target_pdf_watermarked_path)
          print(filestack_response.url)
        except Exception as e:
          print(e.message)

        # (5.10) Store Filestack URL for recipient
        recipient.watermarked_file_url = filestack_response.url
        db.session.commit()

        # (5.11) Delete watermark and watermarked file 
        os.remove(target_watermark_path)
        os.remove(target_pdf_watermarked_path)
      
      # (5.12) Delete downloaded filestack file
      os.remove(target_pdf_path)

    # (6/8) Run watermark process asynchronously 
    async_watermark_process = Process(target=watermark, daemon=True)
    async_watermark_process.start()

  # (7/8) Send confirmation email to user
  def email_confirmation():
    body = 'Hello ' + file_share.owner.first_name + ' ' + file_share.owner.last_name + ',<br><br>' + 'Click through the following <a href="' + app.config['DOMAIN'] + '/fdb/' + file_share.dashboard_url + '">private link</a> to UnderNDA to confirm your email address.<br><br>Upon verifying, invitations with private links will be sent out to the recipients you selected where they will be asked to e-sign an NDA before viewing the watermarked document.<br><br>After verifying, you can access your file share dashboard for status updates and use logs via the same URL which also acts as your password. Do not share or reveal it. <br><br>Your free file share and its copies will auto-delete from our file storage in 7 days.<br><br>For future or expanded confidential file sharing needs, check out our <a href="' + app.config['DOMAIN'] + '/premium">premium plans</a> and don\'t hesitate to reply to this email with any questions.<br><br>Best,<br>UnderNDA'
    message = Mail(
    from_email=app.config['EMAIL_FROM'],
    to_emails=file_share.owner.email,
    subject='Please verify your email address to share your file.',
    html_content=body)

    try:
      sg = SendGridAPIClient(app.config['SENDGRID_API_KEY'])
      response = sg.send(message)
    except Exception as e:
      print(e.message)
    
    async_email_confirmation_process = Process(target=email_confirmation, daemon=True)
    async_email_confirmation_process.start()

  # (8/8) Render template 
  return render_template('free_send.html')

  # to-do: error handling if email fails or is invalid 

  
# recipient dashboard - if already verified, show doc viewer template. if not, show id_recip template
@app.route('/id_recip/<private_invitation_url>')
def free_id_recipient(private_invitation_url):
  # (1/3) Verify recipient invitation_url
  recipient = FreeRecipient.query.filter_by(invitation_url=private_invitation_url).first_or_404()
  if recipient is None:
    abort(400)

  # (2/3) Get recipient IP address and user agent
  user_agent = request.headers.get('User-Agent')

  if request.environ.get('HTTP_X_FORWARDED_FOR') is None:
    ip_address = request.environ['REMOTE_ADDR']
  else:
    ip_address = request.environ['HTTP_X_FORWARDED_FOR']

  # (3/3) Render appropriate template depending on verification status and NDA execution of recipient 
  if recipient.status == 'Invitation sent' or recipient.status == 'Invitation opened':
    if recipient.status == 'Invitation sent':
      recipient.status = 'Invitation opened'
      recipient.last_accessed = datetime.datetime.utcnow()

      use_log = FreeUseLog(file_share_id=recipient.file_share.id, recipient_id=recipient.id, action='invitation clicked', ip_address=ip_address, user_agent=user_agent) 
      db.session.add(use_log)
      db.session.commit()
    
    return render_template('free_recipient_id.html', invitation_url=recipient.invitation_url)

  if recipient.status == 'Verified identity' and recipient.nda_required is True:
    recipient.last_accessed = datetime.datetime.utcnow()
    db.session.commit()
    return redirect(url_for('free_sign_nda', private_invitation_url=private_invitation_url))


  if (recipient.status == 'Verified identity' and recipient.nda_required is False) or (recipient.status == 'NDA signed'):
    recipient.last_accessed = datetime.datetime.utcnow()
    db.session.commit()
    print('Verified but no NDA required.')
    return redirect(url_for('free_recip_viewer', private_invitation_url=private_invitation_url))


@app.route('/sign_nda/<private_invitation_url>', methods=['POST', 'GET'])
def free_sign_nda(private_invitation_url):
  # (1/3) Validate recipient 
  recipient = FreeRecipient.query.filter_by(invitation_url=private_invitation_url).first_or_404()
  if recipient is None:
    print('User not found.')
    abort(400)

  if recipient.nda_required is False:
    print('User should not have access to this route.')
    abort(400)

  # (2/4) Render appropriate page based on recipient status
  render_nda = False

  # (2.1) Recipient has already verified identity
  if recipient.status == 'Verified identity':
    render_nda = True


  # (2.2) Recipient is submitting identity verification now so we are matching up submission against our record
  if recipient.status == 'Invitation opened':
    first_name = request.form['r_first_name'].strip()
    last_name = request.form['r_last_name'].strip()
    organization = request.form['r_organization'].strip()
    email = request.form['r_email'].strip()

    if request.environ.get('HTTP_X_FORWARDED_FOR') is None:
      ip_address = request.environ['REMOTE_ADDR']
    else:
      ip_address = request.environ['HTTP_X_FORWARDED_FOR']

    user_agent = request.headers.get('User-Agent')

    if first_name == recipient.first_name and last_name == recipient.last_name and email == recipient.email:
      print('Recipient verification success.')
      recipient.status = 'Verified identity'
      recipient.last_accessed = datetime.datetime.utcnow()
      recipient.ip_address = ip_address

      use_log = FreeUseLog(file_share_id=recipient.file_share.id, recipient_id=recipient.id, action='verified identity', ip_address=ip_address, user_agent=user_agent)
      db.session.add(use_log)
      db.session.commit()
      render_nda = True
    else:
      print('Recipient verification failed.')
      abort(400)
  

  # (4/4) Render template with NDA and signature pad 
  if render_nda is True:
    date = datetime.datetime.utcnow().strftime('%B %d, %Y')
    return render_template('free_sign_nda.html', invitation_url=recipient.invitation_url, recipient_first_name=recipient.first_name, recipient_last_name=recipient.last_name, recipient_organization=recipient.organization, recipient_email=recipient.email, owner_first_name=recipient.file_share.owner.first_name, owner_last_name=recipient.file_share.owner.last_name, owner_organization=recipient.file_share.owner.organization, owner_email=recipient.file_share.owner.email, date=date)
  else:
    return redirect(url_for('index'))


@app.route('/fdb/<private_dashboard_code>')
def free_dashboard(private_dashboard_code):
  '''
  unverified
  verified
  sent
  '''
  # (1/5) Validate private_dashboard_code
  file_share = FreeFileShare.query.filter_by(dashboard_url=private_dashboard_code).first_or_404()

  if file_share.status == 'deleted':
    abort(400)

  if datetime.datetime.utcnow() > file_share.expiration:
    expired = True
  else:
    expired = False
  
  # (2/5) Attempt again to validate the file share with the filestack upload record if hasn't been done already 
  if file_share.status == 'unverified':
    print('unverified')
    existing_filestack_upload = FreeFilestackUpload.query.filter_by(file_name=file_share.file_name, file_type=file_share.file_type, file_url=file_share.file_url, file_size=file_share.file_size).first()
    print(existing_filestack_upload)

    if existing_filestack_upload is None:
      print('Verification failed.')
      abort(400)
    else:
      print('Verification succeeded.')
      file_share.status = 'verified'
      db.session.commit()

  # (3/5) If the file share is verified, email invitations with private links to the indicated recipients
  if file_share.status == 'verified':
    print('verified')
    for recipient in file_share.recipients:
      body = 'Hi ' + recipient.first_name + ' ' + recipient.last_name + ',<br><br>' + 'Click through the following <a href="' + app.config['DOMAIN'] + '/id_recip/' + recipient.invitation_url + '">private invitation link</a> to UnderNDA for access the confidential document. It will auto-delete in a week.<br><br>You\'ll be asked to verify your identity and may then be required to agree to and e-sign a Non Disclosure Agreement with the sender before gaining access to the document.<br><br>For your own confidential file sharing needs, check out our <a href="#">offerings</a> and don\'t hesitate to reply to this email with any questions.<br><br>Best,<br>UnderNDA'
      subject = file_share.owner.first_name + ' ' + file_share.owner.last_name + ' has invited you to review a confidential document.'
      message = Mail(
      from_email=app.config['EMAIL_FROM'],
      to_emails=recipient.email,
      subject=subject,
      html_content=body)

      try:
        sg = SendGridAPIClient(app.config['SENDGRID_API_KEY'])
        response = sg.send(message)
      except Exception as e:
        print(e.message)

      if response.status_code == 202:
        use_log = FreeUseLog(file_share_id=file_share.id, recipient_id=recipient.id, action='invitation emailed') 
        db.session.add(use_log)
        recipient.status = 'Invitation sent'
        db.session.commit()
        print('Good to go')
      else:
        print('Email failed.')
        recipient.status = 'Invitation failed'
        db.session.commit()
    
    file_share.status = 'sent'
    db.session.commit()
  
  # (4/5) Pull down relevant file share information for template
  # get fileshare, recipient info, nda log, and send to template 
  if file_share.expiration is None:
    expiration = file_share.created + datetime.timedelta(days=7)
    days_remaining = (expiration - datetime.datetime.utcnow()).days
  else:
    expiration = file_share.expiration
    days_remaining = (file_share.expiration - datetime.datetime.utcnow()).days

  expiry = int(time.time()) + (20 * 60) 
  json_policy = { 
    'call': ['read', 'convert'], 
    'expiry': expiry
  } 
  sec = create_security(json_policy, app.config['FILESTACK_APP_SECRET'])
  api_key = app.config['FILESTACK_API_KEY']
  creds = {
    'policy': sec.policy_b64,
    'signature': sec.signature
  }


  # (5/5) Render template 
  return render_template('free_dashboard.html', days_remaining=days_remaining, file=file_share, recipients=file_share.recipients, use_logs=file_share.use_logs, dbc=private_dashboard_code, signature=creds['signature'], policy=creds['policy'], expired=expired)


# REST route to email subscriber interest
@app.route('/po39fkdls93qb3Xl_dlincr', methods=['POST'])
def subscriber():
  print('Handling subscriber')

  # (1/3) Collect POST request data 
  email = request.form['email']

    # (4/6) Retry sending email invitation
  body = 'We have some interest from: ' + email
  message = Mail(
  from_email=app.config['EMAIL_FROM'],
  to_emails='contact@fileundernda.com',
  subject='A NEW PROSPECT!!!',
  html_content=body)

  try:
    sg = SendGridAPIClient(app.config['SENDGRID_API_KEY'])
    response = sg.send(message)
  except Exception as e:
    print(e.message)

  if response.status_code == 202:
    print('Good to go')
    resp = 'success'
  else:
    print('Email failed.')
    resp = 'failure'

  return resp



@app.route('/fdb8a3jfD0X_rsrecip', methods=['POST'])
def fdb_resubmit_recipient():
  # make sure dashboard code checks out and recipient ID exists within fileshare
  print('We are here...')
  #print('Request: ' + request)
  
  #parse_request = json.loads(request.data.decode('utf-8'))
  #print(parse_request)

  # (1/6) Collect POST request data
  dashboard_url = request.form['dbc']
  print('HERE')
  recipient_id = int(request.form['resubmission_recipient_id'])
  print('HERE 2')
  first_name = request.form['recipient_first_name'].strip()
  last_name = request.form['recipient_last_name'].strip()
  organization = request.form['recipient_organization'].strip()
  email = request.form['recipient_email'].strip()

  print('We are here... 2')

  if request.form.get('recipient_nda_required') == 'on':
    nda_required = True
  else:
    nda_required = False

  print('We are here... 3')

  # (2/6) Validate FreeFileShare dashboard code & existence of recipient
  file_share = FreeFileShare.query.filter_by(dashboard_url=dashboard_url).first_or_404()
  if file_share.status != 'sent':
    print('Dashboard code is not validating...')
    abort(400)

  print('We are here... 4')

  recipient_valid = False
  for recipient in file_share.recipients:
    if recipient.id == recipient_id and recipient.status == 'Invitation failed':
      recipient_valid = True
      this_recipient = recipient
  
  if recipient_valid is False:
    print('Recipient is not validating...')
    abort(404)

  # (3/6) Validate new recipient information 
  if validate_person(first_name, last_name, organization, email) is False:
    print('Recipient information submitted is invalid.')
    resp = { 'status': 'invalid recipient information submitted.' }
    return resp

  # (4/6) Retry sending email invitation
  body = 'Hi ' + first_name + ' ' + last_name + ',<br><br>' + 'Click through the following <a href="' + app.config['DOMAIN'] + '/id_recip/' + this_recipient.invitation_url + '">private invitation link</a> to UnderNDA for access the confidential document. It will auto-delete in a week.<br><br>You\'ll be asked to verify your identity and may then be required to agree to and e-sign a Non Disclosure Agreement with the sender before gaining access to the document.<br><br>For your own confidential file sharing needs, check out our <a href="#">offerings</a> and don\'t hesitate to reply to this email with any questions.<br><br>Best,<br>UnderNDA'
  subject = file_share.owner.first_name + ' ' + file_share.owner.last_name + ' has invited you to review a confidential document.'
  message = Mail(
  from_email=app.config['EMAIL_FROM'],
  to_emails=email,
  subject=subject,
  html_content=body)

  try:
    sg = SendGridAPIClient(app.config['SENDGRID_API_KEY'])
    response = sg.send(message)
  except Exception as e:
    print(e.message)

  if response.status_code == 202:
    print('Good to go')
    this_recipient.status = 'Invitation sent'
  else:
    print('Email failed.')
    resp = { 'status': 'email failed' }
    return resp


  # (5/6) Update recipient 
  if len(organization) == 0:
    organization = None

  this_recipient.first_name = first_name
  this_recipient.last_name = last_name
  this_recipient.organization = organization
  this_recipient.email = email
  this_recipient.nda_required = nda_required
  db.session.commit()

  # (6/6) Return response with new recipient info
  resp = { 'status': 'success', 
          'recipient_status': this_recipient.status,
          'first_name': this_recipient.first_name,
          'last_name': this_recipient.last_name,
          'organization': this_recipient.organization,
          'email': this_recipient.email,
          'nda_required': this_recipient.nda_required,
          'id': this_recipient.id }

  return resp

@app.route('/p9LiX710tfx_dltfs', methods=['POST'])
def delete_free_file_share():
  # (1/4) Validate dashboard url
  dashboard_url = request.form['dbc']
  file_share = FreeFileShare.query.filter_by(dashboard_url=dashboard_url).first_or_404()

  # (2/4) Set file share status to deleted 
  if file_share.status != 'deleted':
    file_share.status = 'deleted'
  else:
    abort(400)

  # (3/4) Delete all filestack links, starting with recipient links if applicable, then original file share 
  expiry = int(time.time()) + (5 * 60) # policy valid for 5 minutes
  json_policy = { 
    'call': ['remove'], 
    'expiry': expiry
  } 
  security = create_security(json_policy, app.config['FILESTACK_APP_SECRET'])
  
  if file_share.watermarked is True:
    for recipient in file_share.recipients:
      file_handle = recipient.watermarked_file_url.replace('https://cdn.filestackcontent.com/','')
      file_link = Filelink(file_handle, security=security, apikey=app.config['FILESTACK_API_KEY'])
      try:
        file_link.delete()
      except Exception as e:
        print(e)

  file_handle = file_share.file_url.replace('https://cdn.filestackcontent.com/','')
  file_link = Filelink(file_handle, security=security, apikey=app.config['FILESTACK_API_KEY'])

  try:
    file_link.delete()
    print('File deleted')
  except Exception as e:
    print(e)
  
  db.session.commit()

  # (4/4) Return response
  resp = { 'status': 'success' }
  return resp

  # future to-do: write cron for clearing up expired filestack uploads 

@app.route('/rdb/<private_invitation_url>', methods=['POST', 'GET'])
def free_recipient_processor(private_invitation_url):
  # (1/5) Verify recipient invitation_url & current status of the file share
  recipient = FreeRecipient.query.filter_by(invitation_url=private_invitation_url).first_or_404()
  if recipient is None:
    abort(400)
  file_share = recipient.file_share

  if (datetime.datetime.utcnow() > file_share.expiration) or file_share.status == 'deleted':
    print('File share is no longer available.')
    render_doc_viewer = False
    return redirect(url_for('index'))

  recipient.last_accessed = datetime.datetime.utcnow()
  db.session.commit()

  
  # (2-4) Determine status of recipient and process accordingly 
  # (2/5) If recipient has signed NDA or the NDA is being processed (refreshed after signing), render document
  if recipient.status == 'NDA signed':
    render_doc_viewer = True
  
  if recipient.status == 'Processing NDA':
    time.sleep(8)
    render_doc_viewer = True


  # (3/5) If recipient is submitting a signed NDA now, process then generate & store a PDF of the signed NDA & cert
  if (recipient.status == 'Verified identity') and (recipient.nda_required is True): 
    if recipient.nda.count() != 1:
      if request.method == 'POST':
        # (3.0) Process and validate POST request 
        signature_b64_og = request.form.get('signature')
        agreed = request.form.get('agreement')

        if signature_b64_og[0:22] != 'data:image/png;base64,':
          print('Invalid signature.')
          abort(400)

        if agreed != 'on':
          print('Must check agreed box.')
          abort(400)
        
        user_agent = request.headers.get('User-Agent')
        if request.environ.get('HTTP_X_FORWARDED_FOR') is None:
          ip_address = request.environ['REMOTE_ADDR']
        else:
          ip_address = request.environ['HTTP_X_FORWARDED_FOR']

        recipient.status = 'Processing NDA'
        db.session.commit()

        ################################# CONTRACT AND CERTIFICATE GENERATION ############################
        def generate_contract_and_certificate(ip_address):
          ################# GENERATE & PROCESS CONTRACT (3.1-3.11) ####################
          begin_time = datetime.datetime.utcnow()
          # (3.1) Set NDA contract template file path and a unique hash to append to created temporary local files
          template_pdf_path = app.config['TEMPORARY_FILE_PATH'] + 'nda_template.pdf'
          unique_hash = generate_unique_hash(recipient.email + str(random.randint(100,9000)) + str(time.time()))


          # (3.2) Prepare info for NDA contract
          owner_name_and_email = file_share.owner.first_name + ' ' + file_share.owner.last_name + ' (' + file_share.owner.email + ')'
          if recipient.organization is not None:
            recipient_name_and_email = recipient.organization + ' (' + recipient.email + ')'
          else:
            recipient_name_and_email = recipient.first_name + ' ' + recipient.last_name + ' (' + recipient.email + ')'
          timestamp = datetime.datetime.utcnow()
          date = timestamp.strftime('%B %d, %Y')

          # (3.3) Clean and decode the submitted base64 signature and write it to a new PNG file 
          signature_b64 = signature_b64_og.replace('data:image/png;base64,', '')
          signature_file_name = 'signature_' + str(unique_hash) + '.png'
          signature_file_path = app.config['TEMPORARY_FILE_PATH'] + signature_file_name
          
          image = open(signature_file_path, "wb")
          image.write(base64.b64decode(signature_b64))
          image.close()

          # (3.4) Proportionally scale the signature PNG to given standardized size for contract
          desired_height = 60 
          image = Image.open(signature_file_path)
          scale_ratio = desired_height / image.height
          height = image.height * scale_ratio
          width = image.width * scale_ratio
          image.close()
          
          # (3.5) Generate PDF file to write NDA contract contents to
          contract_contents_file_name = 'contract_contents_' + str(unique_hash) + '.pdf' 
          contract_contents_pdf_path = app.config['TEMPORARY_FILE_PATH'] + contract_contents_file_name
          c = canvas.Canvas(contract_contents_pdf_path)
          c.setFillColor(black)
          
          # (3.6) Write contract contents onto PDF
          c.setFont('Times-Roman', 12)
          c.drawString(372, 677, date)
          c.drawString(74, 633, recipient_name_and_email)
          c.drawString(74, 604, owner_name_and_email)
          
          c.showPage()
          c.setFont('Times-Roman', 12)
          if recipient.organization is not None:
            c.drawString(76, 653, recipient.organization)
          signatory = recipient.first_name + ' ' + recipient.last_name + ', Affirmed Signatory'
          c.drawString(76, 558, signatory)
          c.drawString(106, 529, date)
          c.drawImage(signature_file_path, 76, 572, width=width, height=height, mask='auto')

          c.save()

          # (3.7) Merge the newly created NDA contract contents PDF with the pre-made NDA contract template PDF
          contract_contents_pdf = PdfFileReader(open(contract_contents_pdf_path, 'rb'))
          executed_contract = PdfFileWriter()
          template_pdf = PdfFileReader(open(template_pdf_path, 'rb'))
          page_count = template_pdf.getNumPages()

          for page_number in range(page_count):
            input_page = template_pdf.getPage(page_number)
            input_page.mergePage(contract_contents_pdf.getPage(page_number))
            executed_contract.addPage(input_page)

          executed_contract_file_name = 'executed_contract_' + str(unique_hash) + '.pdf'
          executed_contract_pdf_path = app.config['TEMPORARY_FILE_PATH'] + executed_contract_file_name
          with open(executed_contract_pdf_path, 'wb') as outputStream:
            executed_contract.write(outputStream)

          # (3.8) Generate checksum of executed NDA contract PDF to be stored for audit purposes
          with open(executed_contract_pdf_path, 'rb') as file_contents:
            data = file_contents.read()
            checksum = hashlib.md5(data).hexdigest()

          # (3.9) Upload the executed NDA contract PDF, update recipient, and generate a DB record each in FreeNDA and FreeUseLog
          try:
            filestack_response = fs_upload(executed_contract_pdf_path)
            print(filestack_response)
          except Exception as e:
            print(e.message)

          recipient.status = 'NDA signed'
          this_nda = FreeNDA(file_share_id=file_share.id, recipient_id=recipient.id, signature=signature_b64_og, file_url=filestack_response.url, checksum=checksum, file_name=executed_contract_file_name)
          execution_log = FreeUseLog(file_share_id=recipient.file_share.id, recipient_id=recipient.id, action='agreed and signed', ip_address=ip_address, user_agent=user_agent)
          db.session.add(this_nda)
          db.session.add(execution_log)
          db.session.commit()

          # (3.10) Email executed contract PDF to recipient
          #def send_contract():
          body = 'Hello ' + recipient.first_name + ' ' + recipient.last_name + ',<br><br>' + 'Attached is a PDF of the Non-disclosure Agreement you recently signed at www.FileUnderNDA.com. Please store it for your legal records. <br><br>For your own personal or business confidential file sharing needs, <a href="http://www.fileundernda.com">check us out</a> and feel free to reply to this email with any questions.<br><br>Best,<br>UnderNDA'
          message = Mail(
          from_email=app.config['EMAIL_FROM'],
          to_emails=recipient.email,
          subject='Your signed copy of the Non-disclosure Agreement',
          html_content=body)

          with open(executed_contract_pdf_path, 'rb') as f:
            data = f.read()
            f.close()
          encoded_file = base64.b64encode(data).decode()

          attached_file = Attachment(
              FileContent(encoded_file),
              FileName('attachment.pdf'),
              FileType('application/pdf'),
              Disposition('attachment')
          )
          message.attachment = attached_file

          try:
            sg = SendGridAPIClient(app.config['SENDGRID_API_KEY'])
            response = sg.send(message)
          except Exception as e:
            print(e.message)
              
          #async_email_process = Process(target=send_contract, daemon=True)
          #async_email_process.start()

          # (3.11) Generate a DB record in FreeUseLog -- 'contract emailed'
          contract_emailed_log = FreeUseLog(file_share_id=recipient.file_share.id, recipient_id=recipient.id, action='contract emailed')
          recipient.copy_emailed = True
          recipient.status = 'NDA signed'
          db.session.add(contract_emailed_log)
          db.session.commit()

          os.remove(contract_contents_pdf_path)
          os.remove(signature_file_path)
          os.remove(executed_contract_pdf_path)

          ################# END OF CONTRACT GENERATION ####################

          ################# GENERATE & PROCESS CERTIFICATE (3.12-3.25) ####################

          # (3.12) Prepare contents to be written to the first half of the certificate
          confidential_file_name = this_nda.file_share.file_name 
          confidential_file_id = file_share.file_url.replace('https://cdn.filestackcontent.com/','')
          nda_file_name = this_nda.file_name
          nda_file_id = this_nda.file_url.replace('https://cdn.filestackcontent.com/','')
          checksum = this_nda.checksum

          # (3.13) Generate new certificate contents PDF where we will write file information (first half) and use logs (second half)
          certificate_contents_file_name = 'cert_contents_' + str(unique_hash) + '.pdf'
          certificate_contents_file_path = app.config['TEMPORARY_FILE_PATH'] + certificate_contents_file_name
          c = canvas.Canvas(certificate_contents_file_path)
          c.setFillColor(black)
          
          # (3.14) Set permanent x coordinates for timestamps and logs and a starting y coordinate to begin writing logs from (second half) 
          timestamp_x = 56
          logtext_x = 177
          y = 364

          # (3.15) Write shared file and NDA file information to the top half of the certificate
          c.setFont('Times-Roman', 11.5)
          c.drawString(timestamp_x, 667, confidential_file_name)
          c.drawString(timestamp_x, 632, confidential_file_id)
          c.drawString(timestamp_x, 573, nda_file_name)
          c.drawString(timestamp_x, 535, nda_file_id)
          c.drawString(timestamp_x, 501, checksum)

          # (3.16) Grab the use logs on record for this recipient & file_share and validate them
          ######## There should be 5 logs if an NDA is required or 3 logs if an NDA is not required
          ######## (1) 'invitation emailed', (2) 'invitation clicked', (3) 'verified identity', 
          ######## (4) 'agreed and signed', (5) 'contract emailed'; (will be created below) => (6) 'certificate generated' 
          use_logs = FreeUseLog.query.filter_by(recipient=recipient).order_by(FreeUseLog.timestamp.asc()).limit(5)
          if use_logs.count() != 3 and use_logs.count() != 5:
            print('Invalid use logs.')
            abort(404)

          if use_logs[0].action == 'invitation emailed' and use_logs[1].action == 'invitation clicked' and use_logs[2].action == 'verified identity':
            if use_logs.count() == 5 and use_logs[3].action != 'agreed and signed' and recipient.nda_required is True:
              print('Invalid use logs.')
              abort(400)
          else:
            print('Invalid use logs.')
            abort(400)

          # (3.17) Set spacing variables for writing logs to the second half of the certificate
          logtext_line_spacing = 12
          logtext_item_spacing = 28
          useragent_item_spacing = 20
          useragent_line_spacing = 8
          max_logtext_characters = 92
          max_useragent_characters = 110

          # (3.18-3.24) Loop through use logs to generate certificate contents PDF 
          # (3.18) Use counter to loop through and write each log to PDF and then to generate and write a final log (+1)
          counter = 0
          ip_address = 0
          use_logs_count = use_logs.count()

          while counter < (use_logs_count + 1): 
            if counter < use_logs_count:
              # (3.19) Process IP address, location (sends a request), and user agent -- don't repeat if same as last log
              if ip_address != use_logs[counter].ip_address:
                ip_address = use_logs[counter].ip_address
                location = get_location_from_ip(ip_address)
              
              if use_logs[counter].user_agent is None:
                useragent_text = None
              else:
                useragent_text = 'User agent: ' + use_logs[counter].user_agent

              # (3.20) Process timestamp, log text, and user agent info to insert depending on current log
              timestamp = str(use_logs[counter].timestamp.strftime("%Y-%m-%d %H:%M:%S")) + ' UTC'

              if counter == 0:
                logtext = 'A private link to access the document was emailed to {} {} ({})'.format(recipient.first_name, recipient.last_name, recipient.email)

              if counter == 1:
                logtext = "{} {} ({}) accessed UnderNDA's website via the private link from {} ({})".format(recipient.first_name, recipient.last_name, recipient.email, ip_address, location) 
              
              if counter == 2:
                logtext = "{} {} ({}) entered personal information that matches UnderNDA's records for identity verification from {} ({})".format(recipient.first_name, recipient.last_name, recipient.email, ip_address, location)

              if recipient.nda_required is True:
                if counter == 3:
                  logtext = "{} {} ({}) agreed to UnderNDA’s Terms of Service, agreed to use electronic records and signatures, and agreed to and signed the Non-disclosure Agreement from {} ({})".format(recipient.first_name, recipient.last_name, recipient.email, ip_address, location)

                if counter == 4:
                  logtext = "UnderNDA emailed the executed Non-disclosure Agreement PDF to {} {} ({})".format(recipient.first_name, recipient.last_name, recipient.email) 
                  useragent_text = None

            # (3.21) Once existing logs have been written, create 'certificate generated' log and write to PDF
            if (counter == 3 and recipient.nda_required is False) or (counter == 5 and recipient.nda_required is True):
              certificate_generated_log = FreeUseLog(file_share_id=recipient.file_share.id, recipient_id=recipient.id, action='certificate generated', ip_address=ip_address, user_agent=user_agent)
              db.session.add(certificate_generated_log)
              db.session.commit()

              timestamp = str(certificate_generated_log.timestamp.strftime("%Y-%m-%d %H:%M:%S") + ' UTC')
              logtext = "UnderNDA generated this certificate"
              useragent_text = None

            # (3.22) Break up text into lines based on preset max character count per line
            logtext_lines = textwrap.wrap(logtext, max_logtext_characters, break_long_words=False)
            if useragent_text is not None:
              useragent_text_lines = textwrap.wrap(useragent_text, max_useragent_characters, break_long_words=False)
            
            # (3.23) Insert timestamp
            c.setFont('Times-Roman', 10)
            if counter > 0:
              y -= logtext_item_spacing
            c.drawString(timestamp_x, y, timestamp)

            # (3.24) Insert log text and user agent text, add spacing after each line and after each item
            length = len(logtext_lines)
            n = 0
            for text_line in logtext_lines:
              n += 1  
              c.drawString(logtext_x, y, text_line)
              if n < length:
                y -= logtext_line_spacing
            
            c.setFont('Times-Roman', 8)
            if useragent_text is not None:
              y -= useragent_item_spacing
              length = len(useragent_text_lines)
              n = 0
              for text_line in useragent_text_lines:
                n += 1
                c.drawString(logtext_x, y, text_line)
                if n < length:
                  y -= useragent_line_spacing
            
            counter += 1

          c.save()


          # (3.25) Open the newly created certificate contents PDF and merge it with the certificate template PDF
          certificate_template_file_path = app.config['TEMPORARY_FILE_PATH'] + 'certificate_template.pdf'
          certificate_contents_pdf = PdfFileReader(open(certificate_contents_file_path, 'rb'))
          certificate_template_pdf = PdfFileReader(open(certificate_template_file_path, 'rb'))
          certificate = PdfFileWriter()
          page_count = certificate_template_pdf.getNumPages()

          for page_number in range(page_count):
            input_page = certificate_template_pdf.getPage(page_number)
            input_page.mergePage(certificate_contents_pdf.getPage(0))
            certificate.addPage(input_page)

          certificate_file_name = 'certificate_' + str(unique_hash) + '.pdf'
          certificate_file_path = app.config['TEMPORARY_FILE_PATH'] + certificate_file_name
          with open(certificate_file_path, 'wb') as outputStream:
            certificate.write(outputStream)
          
          # (3.26) Upload certificate to Filestack and store certificate info in NDA record
          try:
            filestack_response = fs_upload(certificate_file_path)
            print(filestack_response)
          except Exception as e:
            print(e.message)  
          
          this_nda.certificate_file_name = certificate_file_name
          this_nda.certificate_file_url = filestack_response.url
          db.session.commit()

          os.remove(certificate_contents_file_path)
          os.remove(certificate_file_path)

          end_time = datetime.datetime.utcnow()
          time_elapsed = (end_time - begin_time).total_seconds()
          print(time_elapsed)

        async_generate_contract_and_certificate_process = Process(target=generate_contract_and_certificate, args=(ip_address,), daemon=True)
        async_generate_contract_and_certificate_process.start()
        ################################# END CONTRACT AND CERTIFICATE GENERATION ##########################

        render_doc_viewer = True
      else:
        print('Invalid request.')
        abort(400)
    else:
      print('ERROR: NDA exists but recipient status does not indicate so.')
      abort(400)
  
  # (4/5) If recipient is not required to sign NDA
  if recipient.status == 'Verified identity' and recipient.nda_required is False:
    render_doc_viewer = True

  # (5/5) Show document if recipient has completed all necessary steps 
  if render_doc_viewer is True:
    return redirect(url_for('free_recip_viewer', private_invitation_url=private_invitation_url))
  else:
    abort(400)




@app.route('/legal')
def legal():
  return render_template('legal.html')

@app.route('/terms')
def tos():
  return render_template('tos.html')


@app.route('/security')
def security():
  return 'This is where security information goes'

@app.route('/premium')
def premium():
  return render_template('premium.html')

@app.route('/login')
def login():
  return redirect(url_for('premium'))

@app.route('/subscribe')
def subscribe():
  return redirect(url_for('premium'))

@app.route('/rview/<private_invitation_url>')
def free_recip_viewer(private_invitation_url):
  # (1/4) Process request and determine if file share is still viewable 
  recipient = FreeRecipient.query.filter_by(invitation_url=private_invitation_url).first_or_404()
  if recipient is None:
    abort(400)
  file_share = recipient.file_share

  if file_share.expiration is not None: # to delete 
    if (datetime.datetime.utcnow() > file_share.expiration) or file_share.status == 'deleted':
      render_doc_viewer = False
      return redirect(url_for('index'))
    
  recipient.last_accessed = datetime.datetime.utcnow()
  db.session.commit()


  # (2/4) Determine status of recipient and process accordingly 
  # If recipient has signed NDA, NDA is not required, or the NDA is being processed, render document
  if recipient.status == 'NDA signed' or (recipient.status == 'Verified identity' and recipient.nda_required is False):
    render_doc_viewer = True
  
  if recipient.status == 'Processing NDA':
    time.sleep(8)
    render_doc_viewer = True

  if render_doc_viewer is not True:
    abort(400)

  recipient.views += 1
  db.session.commit()

  # (3/4) Fetch relevant file URL and add Filestack security policy credentials to URL to be embedded in page
  if file_share.watermarked is True:
    url = recipient.watermarked_file_url
  else:
    url = file_share.file_url
  
  expiry = int(time.time()) + (5 * 60) # policy valid for 5 minutes
  json_policy = { 
    'call': ['read', 'convert'], 
    'expiry': expiry
  } 
  sec = create_security(json_policy, app.config['FILESTACK_APP_SECRET'])
  api_key = app.config['FILESTACK_API_KEY']
  creds = {
    'policy': sec.policy_b64,
    'signature': sec.signature
  }
  handle = url.replace('https://cdn.filestackcontent.com/', '')

  #embedded_url = 'https://cdn.filestackcontent.com/' + handle + '?' + 'policy' + '=' + creds['policy'] + '&' + 'signature' + '=' + creds['signature']

  # (4/4) Render document viewer
  return render_template('viewer.html', api_key=api_key, policy=creds['policy'], signature=creds['signature'], handle=handle, recipient=recipient) # file_url=embedded_url,


@app.errorhandler(404)
def not_found(e):
  return redirect(url_for('index'))
'''
@app.errorhandler(500)
def server_error(e):
  return render_template('error.html')
'''
