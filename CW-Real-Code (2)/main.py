import hashlib
import cryptography
import glob
import atexit
import logging
import random
import sys
import datetime
import os  #various modules required for the program to function
import secrets
import re
from cryptography.fernet import Fernet
from flask import Flask, render_template, request, redirect, url_for
from flask import session as f_session
from flask_session import Session as Flask_session
import base64
import uuid
from sqlalchemy import Column, ForeignKey, Integer, String, create_engine, select, update, Boolean, or_
from sqlalchemy.orm import declarative_base, query, sessionmaker
from sqlalchemy.sql.sqltypes import Float
from babel.numbers import format_currency

# OTP Modules
import pyotp
from flask_wtf import FlaskForm
from wtforms import EmailField, PasswordField
from wtforms.validators import DataRequired, Email, EqualTo, Length
from security.mfa import get_b64encoded_qr_image, is_otp_valid

#Create Encryption Key Files and encrypt logs
def encrypt_logs():
  #When program ends, loop through all log files and generate keys for them. Then encrypt the log files themselves.
  pattern = '*.log'
  log_files = glob.glob(pattern)
  print(log_files)

  #   Iterate over each log file and perform actions
  for file_path in log_files:
    username = file_path.split(".")[0]
    key = Fernet.generate_key()
    with open(f'{username}.filekey', 'wb') as filekey:
      filekey.write(key)

    #use the key files  to encrypt the log files
    #opening the key
    with open(f'{username}.filekey', 'rb') as filekey:
      key = filekey.read()

    #using the generatd key
    fernet = Fernet(key)

    #opening original log file to encrypt
    with open(f'{username}.log', 'rb') as file:
      original = file.read()

    #encrypting the  log files
    encrypted = fernet.encrypt(original)

    #opneing file in write mode and writing the encrypted data
    with open(f'{username}.log', 'wb') as encrypted_file:
      encrypted_file.write(encrypted)


#decrypt log files
pattern = '*.log'
log_files = glob.glob(pattern)
print(log_files)

for file_path in log_files:
  username = file_path.split('.')[0]
  with open(f'{username}.filekey', 'rb') as key_file:
    key = key_file.read()

  #making the fernet key from the key file
  fernet = Fernet(key)

  #opening encrypted file
  with open(f'{username}.log', 'rb') as enc_file:
    encrypted = enc_file.read()

  #decrypting the  log file
  decrypted = fernet.decrypt(encrypted)

  #opneing file in write mode and writing the unencrypted data
  with open(f'{username}.log', 'wb') as decrypted_file:
      decrypted_file.write(decrypted)

formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')


def set_logger(name, level=logging.INFO):
  handler = logging.FileHandler(
      f'{name}.log')  #creates a log file for every user within a database
  handler.setFormatter(formatter)  #defines how logs are set for all users

  logger = logging.getLogger(name)
  logger.setLevel(level)  #logs are for info messages
  logger.addHandler(handler)
  logger.propogate = False

  return logger  #return the log file name to be used


log_files = {}

app = Flask(__name__)

app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
Flask_session(app)  #a
loggedin = None

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename=
    'system.log',  #creating the base system log for all logs to be sent into
    filemode='w')
logger = logging.getLogger('system')
logger.info("System loaded at: IP=%s")

#at exit call encrypt function. Add this back in once code is finished.

atexit.register(encrypt_logs)


def sanitise_input(input_string):
  return re.sub('[../+\\n+\\r"\\\']*', '', input_string) #remove specific characters from input string


#santisation of inputs to protect against malicious inputs and to prevent SQL injection
def sanitise_float(input_string):
  try:
    input_string = float(input_string)
    return float("%.2f" % input_string)
  except ValueError:
    new = re.sub('[^\d.]', '', input_string) #If conversion fails due to a non number input, remove all non number characters
    try:
      new = float(new) #create a new float value if the input is valid
      return new
    except ValueError:
      return None


def generate_salt(length=16):
  return secrets.token_hex(
      length
  )  #generates a random salt for the user to use when creating a password


def usr_log(usr, msg):
  if os.path.exists(f"{usr}.log"):
    usr_log = set_logger(usr)
  else:
    f = open(f"{usr}.log", "w")  #create a user log for each user
    f.close()
    usr_log = set_logger(usr)
  usr_log.info(
      msg)  #then make the message in the log file for the specific user


#user log is created
def create_log(chosen_username):
  if os.path.exists(
      f"{chosen_username}.log"
  ):  #create a users log with config information based on the username it is being created for, this will be performed when a new user is registered
    with open(f"{chosen_username}.log", "w"):
      logging.basicConfig(level=logging.INFO,
                          format='%(asctime)s - %(levelname)s - %(message)s',
                          filename=f'{chosen_username}.log',
                          filemode='w')
      hummus = logging.getLogger(f'{chosen_username}')


def log_time(chosen_username):
  if os.path.exists(f"{chosen_username}.log"):
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        filename=
        f'{chosen_username}.log',  #logging once the log has been created, filemode is now append instead of write so log files dont get rewritten each tume
        filemode='a')
    hummus = logging.getLogger(f'{chosen_username}')
    return hummus
  else:
    print("somethings wrong lmao")


def log_syntax_error(exctype, value, traceback):
  logger.error(
      "Internal system error: %s", value
  )  #logic for what happpens if something goes wrong that is unexpected


sys.excepthook = log_syntax_error

#aaron -- start
engine = create_engine(
    'sqlite:///flaskdat.sqlite3', echo=True
)  #creating a sql engine, flaskdat.sqlite3 to store data within #echo=True for logging sql database
Session = sessionmaker(bind=engine)
session = Session()  #creating a session for the database to run in
connection = engine.connect().begin()
Base = declarative_base()


class User(Base):
  __tablename__ = 'users'
  id = Column(Integer, primary_key=True)
  username = Column(String)
  customer_name = Column(String)
  hpasswd = Column(String)
  salt = Column(String)
  recovery_code = Column(
      Integer)  #- this only gets generated when customer registers.
  bank_bal = Column(Float)
  sort_code = Column(String)
  account_number = Column(String)
  role = Column(String)
  isLocked = Column(Boolean, default=False)
  secret_token = Column(String)

  # 2FA variables -  i am commenting this out to test the reste of the code for our report


'''
 is_two_factor_authentication_enabled = Column(db.Boolean, default=False)
  secret_token = db.Column(db.String, unique=True)

  def get_authentication_setup_uri(self):
    return pyotp.totp.TOTP(self.secret_token).provisioning_uri(
        name=self.username, issuer_name=Config.APP_NAME)

  def is_otp_valid(self, user_otp):
    totp = pyotp.parse_uri(self.get_authentication_setup_uri())
    return totp.verify(user_otp)
'''


#database tables for each user within the database contains the important information used throughout the program
class Transactions(Base):
  __tablename__ = 'transactions'
  id = Column(Integer, primary_key=True,
              autoincrement=True)  #may need to adjust the database to fix
  username = Column(String, ForeignKey('users.username'))
  sender = Column(String)
  receiver = Column(String)
  amount = Column(Float)
  date = Column(String)
  time = Column(String)
  status = Column(String)


#database tables for each transaction made within the database contains the important information used throughout the program
Base.metadata.create_all(engine)
#initialise the tables within the engine

get_usernames = session.query(
    User.username)  #list all usernames in the database
usr_list = []
for each in get_usernames:
  usr_list.append(each.username)
global login_attempts
login_attempts = dict.fromkeys(
    usr_list, 0)  #intialise login attempts for all users in the user list at 0

#Below shows the data stored in the database --- START
for row in session.execute(select(User)):
  for entry in row:
    print(f'''
    ID: {entry.id},
    Username: {entry.username}, 
    Customer Name: {entry.customer_name}, 
    Hashed password: {entry.hpasswd},   
    Salt {entry.salt}, 
    Recovery code: {entry.recovery_code}, 
    Bank bal: {entry.bank_bal}, 
    Sort code: {entry.sort_code}, 
    Account No: {entry.account_number}, 
    Role {entry.role}
    isLocked {entry.isLocked}
    secretToken {entry.secret_token}
    ''')
for row in session.execute(select(Transactions)):
  for entry in row:
    print(f'''
    ID: {entry.id}
    Username: {entry.username}, 
    Sender: {entry.sender}, 
    Receiver: {entry.receiver}, 
    Amount: {entry.amount}, 
    Date: {entry.date},
    Time: {entry.time}, 
    Status: {entry.status}
    ''')

#Below shows the data stored in the database --- END
### admin password is 'test123' with sha256 hash 'ecd71870d1963316a97e3ac3408c9835ad8cf0f3c1bc703527c30265534f75ae'

#when user registers, we salt the password and store the SALT in the database. Then when the user logs in, we read the salt from the database and prepend it on to the password. Then hash that as one thing.

#When the user is generated. We randomly generate a unique salt for that user. Then we add the salt to their plaintext password and hash it. THen we add that hashed password to the database. We also add the salt to the database. Then when we authorise the user we will read the salt and add that to the plaintext password the user entered and hash all of it to then compare it to the hashed password in the database.


def hash_password(chosen_password, salt):

  t_sha = hashlib.sha512()  #call sha512 hashing function
  encoded = bytes(chosen_password + str(salt),
                  'utf-8')  #add the password with the randomly generated salt
  t_sha.update(encoded)
  hashed_password = base64.urlsafe_b64encode(
      t_sha.digest())  #encode the password in a sha value to be stored
  return hashed_password


def auth_user(username, password):
  logger.info(f"Database being accessed for {username}.")
  query = select(User).where(
      User.username == username)  # if the username exists
  query2 = session.query(User).filter_by(username=username).first()
  if not query2:  # if the username exists
    logger.error(f"User {username} not found in database.")
    return False, False
  else:
    # Execute the query and retrieve the user
    entry = session.execute(query).scalar_one_or_none()

    if entry:
      dbUsername = entry.username
      dbPassword = entry.hpasswd
      dbSalt = entry.salt

      #grab the values for the entrys row if the user exists

      t_sha = hashlib.sha512(
      )  #encode the entered password to be compared to the hashed password in the database
      encoded = bytes(password + str(dbSalt), 'utf-8')
      t_sha.update(encoded)
      hashed_password = base64.urlsafe_b64encode(
          t_sha.digest()).decode('utf-8')

      if username == dbUsername:
        if dbPassword == hashed_password:
          logger.info(f"User '{username}' authenticated.")
          return True, True  #return true on both values to affirm user is authenticated
        else:
          logger.error(f"User '{username}' password incorrect.")
          return True, False  #user exists but wrong second input for password value
      else:
        logger.error(f"User '{username}' not found.")
        return False, False


@app.route('/')
def home():  #exit and return home to the login page
  return render_template('loginpage.html', login_message='')


@app.route('/userlookup', methods=['POST', 'GET'])
def userlookup():
  if f_session['username'] == None:
    return redirect(url_for('home'))
  lookup_username = sanitise_input(request.form.get('lookupname'))
  f_session[
      'lookup_username'] = lookup_username  #get the username being queried in the afmin dash
  logged_in_user = f_session['username']
  lookup_query = session.query(User).filter_by(
      username=lookup_username).first()
  with open(f"{lookup_username}.log",
            "r") as file:  #find the users log file via database query
    contents = file.read()

  return render_template(
      'admincontrols.html',
      logged_in_user=logged_in_user,
      lookup_query=lookup_query,
      logs=contents
  )  #present all user information that is queried to the admin dashboard


@app.route('/admindashboard', methods=['POST', 'GET'])
def admindashboard():
  if f_session['username'] == None:
    return redirect(url_for('home'))
  try:
    display_message = f_session[
        'admin_display_message']  #set default display message for the admin dashboard page
  except KeyError:
    display_message = ''  #blank as no processes have been run yet
  f_session['admin_display_message'] = ''
  logger.debug(f"Key Error has occured on admin dashboard")
  return render_template(
      'admin.html',
      display_message=display_message)  #bring about the admin dashboard


#oscar here
@app.route('/registerpage', methods=['POST'])  #render register page
def registerpage():
  return render_template('registration.html')


'''
def registerpage():
  try:
    inc_true, msg = f_session['incorrect_pass']
    if inc_true:
      return render_template('registration.html', incorrect_pass=msg)
  except KeyError:
    return render_template('registration.html', incorrect_pass='')
'''


@app.route('/registration', methods=['POST'])
def register():
  chosen_name = sanitise_input(request.form.get('fullname'))
  chosen_username = sanitise_input(request.form.get(
      'username'))  #acquire the details about the user to be used
  chosen_password = sanitise_input(request.form.get('password'))

  if chosen_username in [
      'withdrawal', 'deposit'
  ]:  # Username cannot be this as it used in transactions
    return render_template('registration.html',
                           register_message='Username is invalid')

  check_query = session.query(User).filter_by(username=chosen_username).first()
  try:  # checks if username is already taken
    check_query_username = check_query.username
    if check_query_username == chosen_username:
      return render_template('registration.html',
                             register_message='Username is invalid')
  except AttributeError:
    check_query_username = None  #  username is valid as it returns no response

  salt = generate_salt()  #create the salt for the new user
  default_assignment = "customer"
  check_pass = str(chosen_password)
  salt2 = str(salt)  #ensure the salt and check pass are string values
  hashed_password = hash_password(check_pass, salt2)
  hashy = hashed_password.decode('utf-8')
  logger.info(f"Hash generated for user '{chosen_username}'")
  generated_code = random.randint(100000000000, 999999999999)
  account_no = random.randint(
      100000000000, 999999999999
  )  #create randmised sort, account and recovery codes for the user


  while True:
    check_rec_query = session.query(User).filter_by(
        recovery_code=generated_code).first()
    try:
      rc = check_rec_query.recovery_code
      generated_code = random.randint(100000000000, 999999999999)
    except AttributeError:  # this means that the recovery code does not exists in the database
      break

  while True:
    check_ac_query = session.query(User).filter_by(
        account_number=account_no).first()
    try:
      ac = check_ac_query.account_number
      account_no = random.randint(100000000000, 999999999999)
    except AttributeError:  # this means that the recovery code does not exists in the database
      break

  random_sort_code = "{}-{}-{}".format(
      str(random.randint(0, 99)).zfill(
          2
      ),  ## added this so sortcode is always 2 digits with zfill(2) if not then it pads with zeros
      str(random.randint(0, 99)).zfill(2),
      str(random.randint(0, 99)).zfill(2))
  if len(check_pass) > 10:  # ensures password is of a valid length to be used
    # creator = log_time(chosen_username)  #generate a log file for the user
    secret_token = pyotp.random_base32()
    print(f"Secret token: {secret_token}")
    new_user = User(username=chosen_username,
                    hpasswd=hashy,
                    recovery_code=generated_code,
                    customer_name=chosen_name,
                    bank_bal=0,
                    sort_code=random_sort_code,
                    account_number=account_no,
                    role=default_assignment,
                    salt=salt,
                    secret_token=secret_token)
    session.add(new_user)
    session.commit()  #add a new user to the user table of the database
    login_attempts[chosen_username] = 0
    logger.info(f"User '{chosen_username}' registered.")
    usr_log(chosen_username,f"User '{chosen_username}' registered and file generated.")
    f_session['username'] = chosen_username
    return redirect('/setup_2fa')
    #return redirect(url_for('dashboard'))
    #f_session['incorrect_pass'] = (False, None)
  else:
    #f_session['incorrect_pass'] = (True, "Password does not meet minimum secure length, enter a new one")
    logger.info(
        "Password does not meet minimum secure length, enter a new one")
    return render_template(
        'registration.html',
        register_message=
        'Password does not meet minimum secure length, enter a new one'
    )  #sends a message back to the user informing the person


@app.route('/logout', methods=['POST', 'GET'])
def logout():
  usr_log(f_session['username'], "User has logged out")
  logger.critical(f"User '{f_session['username']}' has logged out.")
  f_session['username'] = None  #close the session for the user
  session.close()
  return redirect(url_for('home'))  #go to the login page again


@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():

  try:
    user_display_message = f_session['user_display_message']
    f_session[
        'user_display_message'] = ''  #set default user display message, blank as no processes have been run yet when page loaded
  except KeyError:
    logger.debug(f"Key Error occured on user dashboard")
    user_display_message = ''

  username = f_session['username']
  if username == None:
    return redirect(url_for('home'))
  #Note to self (Husaam) - need to pass in data for user from database
  try:  #exception handling
    transaction_query = session.query(Transactions).filter(
        or_(Transactions.username == username, Transactions.receiver ==
            username)).all()  #look for username in transactions
    for row in transaction_query:
      print(row.username, row.sender, row.receiver, row.amount, row.date,
            row.time, row.status)
  except:
    transaction_query = None
  user_query = session.query(User).filter_by(username=username).first()
  bank_bal = format_currency(
      user_query.bank_bal, 'GBP',
      locale='en_GB')  #load the users balance to the screen from the database
  try:
    if f_session['user_rec_code'] == None:
      show_hide_rec = 'Show'
      user_rec_code = ''
    else:  #is the view recovery code requested, if not or if so one of these if statements will run depending on whether or not its pressed
      show_hide_rec = 'Hide'
      user_rec_code = f"Recovery code for {username} is {f_session['user_rec_code']}"
  except KeyError:
    user_rec_code = ''
    show_hide_rec = 'Show'
    logger.debug(f"Key Error occured when trying to display recovery code")
  return render_template(
      'userdashboard.html',
      username=username,
      user_query=user_query,
      tr_query=transaction_query,
      user_recovery_code=user_rec_code,
      bank_bal=bank_bal,
      show_hide_rec=show_hide_rec,
      user_display_message=user_display_message
  )  #return user dashboard with various information about the user needed for jinja and for the user to see


@app.route('/login', methods=['GET', 'POST'])
def login():
  username = sanitise_input(request.form.get('username'))  #validate the inputs are not malicious for this function
  password = sanitise_input(request.form.get('password'))
  user_valid, password_valid = auth_user(username, password)
  if user_valid:
    isUserLocked = session.query(User).filter_by(username=username).first().isLocked
    if isUserLocked:  #checks if the user has been locked for security reasons by an admin
      logger.info(f"User '{username}' is locked and tried to login.")
      usr_log(username, f"User '{username}' is locked and tried to login.")  #logs for the function
    else:
      if password_valid:
        if login_attempts[username] >= 10:  #check if login attempts are less than 10 for the username in order to prevent bruteforce or dictionary attacks
          logger.critical(f"Too many login attempts on user, possible attack present on: '{username}'")
          usr_log(username, f"Too many login attempts on user, possible attack present on: '{username}'")  #more logs
          return render_template(
              'loginpage.html', login_message='Username or password incorrect')
        else:
            if session.query(User).filter_by(username=username).first().secret_token != "":
                f_session['try_username'] = username
                return redirect(url_for('verify_2fa'))
            else:
              logger.info(f"Login acquired on user: '{username}'")
              f_session['username'] = username  # session is now set for the user that has been logged in
              if check_role(username) == 'admin':
                login_attempts[username] == 0  # if the user is an admin redirect to the admin dash
                usr_log(username, f'{username} has logged in')
                return redirect(url_for('admindashboard'))
              else:
                login_attempts[username] == 0
                usr_log(username, f'{username} has logged in')
                return redirect(url_for('dashboard'))  #if the users not an admin go to dashboard
      else:
        
        login_attempts[username] += 1  #if there is not a valid login add a login attempt against the user
        logger.info(f"Incorrect password entered for user: {username}")
        usr_log(username, f"Incorrect password entered for user: {username}")
        return render_template('loginpage.html',
                               login_message='Username or password incorrect')
  else:
    logger.info(f"User '{username}' not found in database.")
    return render_template('loginpage.html',login_message='Username or password incorrect')


#when user clicks on the forgot password button, user needs to answer secuirty question, if successful a recovery code gets generated and added to database. Recovery code appears on user's screen.



@app.route('/recoverypage', methods=['POST', 'GET'])
def recovery():
  return render_template('recovery.html')


@app.route('/resetpassword', methods=['POST'])
def resetpassword():
  input_username = sanitise_input(
      request.form.get('username'))  #user enters username and recovery code so
  input_recovery_code = sanitise_input(request.form.get('recovery_code'))
  input_newpassword = sanitise_input(request.form.get('new_password'))

  #extract salt from the database, then prepend salt to the input_newpassword.  Then hash the whole thing

  salt = session.query(User.salt).filter_by(username=input_username).first()[0]
  #find the salt for the specific user that is stored

  hashednewpassword = hash_password(input_newpassword, salt)

  username_query = session.query(User).filter_by(username=input_username)

  password_query = session.query(User).filter_by(hpasswd=hashednewpassword)

  recovery_query = session.query(User).filter_by(
      recovery_code=input_recovery_code)

  #ensure there is a valid recovery code and hashed password within the database
  if username_query and recovery_query:
    logger.info(f"Recovery code for user '{input_username}' is valid.")

    #update password with hashed password
    generated_code = random.randint(100000000000, 999999999999)
    # Logic for making sure you do not get duplicate recovery codes in the table

    recovery_dupe_test = session.query(User).filter_by(
        recovery_code=generated_code).first()
    #Loops until it finds a unique recovery code
    while recovery_dupe_test != None:
      generated_code = random.randint(100000000000, 999999999999)
      recovery_dupe_test = session.query(User).filter_by(
          recovery_code=generated_code).first()

#decode the hashed password from the salt
    hashednewpassword = hashednewpassword.decode('utf-8')
    print(type(hashednewpassword), hashednewpassword)

    #commit updated recovery code to database
    session.query(User).filter(User.username == input_username).update(
        {'hpasswd': hashednewpassword})

    #commit updated recovery code to database
    session.query(User).filter(User.username == input_username).update(
        {'recovery_code': generated_code})
    session.commit()

    recoverymessage = 'Your new Recovery code is ' + str(
        generated_code)  #inform the user of the code for them to use
    print(recoverymessage)
    session.commit()  #commit the new recovery code to database
    logger.info(f'New recovery code generated for user:  {input_username}')
    usr_log(username, f"New recovery code generated for user: {input_username}"
            )  #logs for this section
    return redirect(url_for('home'))
  else:
    logger.info('Invalid username or recovery code')


#CAM END --------------------------------------------


#oscar tinkering here
class TaskManagementSystem:

  def __init__():

    # Initialise roles and their associated permissions
    roles = {
        'admin': [
            'lock_account', 'delete_account', 'view_user_transactions',
            'view_user_logs', 'change_permissons', 'create_account',
            'search_user'
        ],
        'employee': [
            'make_transaction',
            'view_user_transactions',
            'lock_account',
        ],
        'customer': [
            'view_own_transactions',
            'make_transaction',
            'delete_account',
        ]
    }


@app.route('/lock_account', methods=['POST', 'GET'])
def lock_account():
  if f_session['username'] == None:
    return redirect(url_for('home'))
  username = f_session['lookup_username']  #get the user being queried

  isLocked = session.query(User).filter_by(
      username=username).first().isLocked  #is the account locked
  if isLocked == True:
    print("User account already locked")
    logger.info(
        f"{f_session['username']} tried to lock {username} but is locked already"
    )
    f_session[
        'admin_display_message'] = f"{username} is already locked"  #screen output and logs for this function
    return redirect(url_for('admindashboard'))
  else:
    session.query(User).filter(User.username == username).update(
        {'isLocked': True})
    session.commit(
    )  #commit the lock of the account if its not locked already, update this value in the database
    print("Account locked")
    logger.info(f"{f_session['username']} locked {username}")
    usr_log(username, f"User account locked by {f_session['username']}"
            )  #log and screen output for this function.
    f_session['admin_display_message'] = f"{username} has been locked"
    return redirect(url_for('admindashboard'))


@app.route('/unlock_account', methods=['POST', 'GET'])
def unlock_account():
  if f_session['username'] == None:
    return redirect(url_for('home'))
  username = f_session['lookup_username']  #grab the user being querued

  isLocked = session.query(User).filter_by(username=username).first().isLocked
  if isLocked == True:  #if the account is locked
    session.query(User).filter(User.username == username).update(
        {'isLocked': False})
    session.commit()  #update the value to false, account unlocked
    f_session['admin_display_message'] = f"{username} has been unlocked"
    usr_log(username, f"User account unlocked by {f_session['username']}"
            )  #logs for if the account is unlocked
    logger.info(f"{f_session['username']} unlocked by {username}")
    return redirect(url_for('admindashboard'))
  else:
    f_session['admin_display_message'] = f"{username} is not locked"
    print("Account is not locked")  #if not locked display this to screen
    return redirect(url_for('admindashboard'))


@app.route('/delete_account', methods=['POST', 'GET'])
def delete_account():
  if f_session['username'] == None:
    return redirect(url_for('home'))
  username = f_session[
      'lookup_username']  #check what user is currently logged in currently

  user = session.query(User).filter_by(username=username).first().username
  if user == username:
    session.query(User).filter(User.username == username).delete()
    session.commit()
    logger.info(f"User '{username}' has been removed.")
    #log file kept for purposes of storage and archiving, lol - indeed
    f_session['admin_display_message'] = f"{username} has been deleted"
    usr_log(username,
            f"User '{username}' has been deleted by {f_session['username']}"
            )  #logging that the user has been deleted and by what admin
    return redirect(url_for('admindashboard'))
  else:
    f_session[
        'admin_display_message'] = f"Failed to delete {username}"  #error checking, just incase something unexpected happens
    return redirect(url_for('admindashboard'))


@app.route('/change_permissons', methods=['POST', 'GET'])
def change_permissions():
  if f_session['username'] == None:
    return redirect(url_for('home'))  #if a user isnt queried return home
  roles = {
      'admin': [
          'lock_account', 'delete_account', 'view_user_transactions',
          'view_user_logs', 'change_permissons', 'create_account',
          'search_user'
      ],
      'employee': [
          'make_transaction',
          'view_user_transactions',
          'lock_account',
      ],
      'customer': [
          'view_own_transactions',
          'make_transaction',
          'delete_account',
      ]
  }  #role based permissions for the site
  username = f_session['lookup_username']
  user = session.query(User).filter_by(username=username).first()
  desired_role = sanitise_input(
      request.form.get('role')
  )  #ensure the input is sanitised and valid, not doing anything malicious
  if desired_role in list(roles.keys()):
    session.query(User).filter(User.username == username).update(
        {'role': desired_role})
    session.commit()  #check if there is a role in the database

    usr_log(username,
            f"{username} permissions have been changed to {desired_role}")
    logger.info(f"{username} permissions have been changed to {desired_role}")
    f_session[
        'admin_display_message'] = f"{username} permissions have been changed to {desired_role}"  #screen output to inform admin role has been changed
    return redirect(url_for('admindashboard'))
  else:
    f_session[
        'admin_display_message'] = f"{username} permissions has not been changed to {desired_role} as it is not a valid role"
    logger.info(
        f"{username} permissions failed to be changed to {desired_role}"
    )  #likewise log and screen output for this function
    return redirect(url_for('admindashboard'))


#TO FINISH - PLEASE GOD DO COMMENTS
@app.route('/maketransaction', methods=['POST', 'GET'])
def make_transaction():
  username = f_session['username']
  rec_account_number = sanitise_input(request.form.get('account_number'))
  rec_sort_code = sanitise_input(request.form.get('sort_code'))
  transaction_amount = sanitise_float(request.form.get('transaction_amount'))

  if transaction_amount == None:
    f_session['user_display_message'] = 'Error! Invalid transaction amount'
    return redirect(url_for('dashboard'))
  if transaction_amount < 0:
    f_session['user_display_message'] = 'Error! Invalid transaction amount'
    return redirect(url_for('dashboard'))

  if re.match(
      '^[0-9]{2}-[0-9]{2}-[0-9]{2}$',
      rec_sort_code) == False:  #if sortcode does not adhere to this format
    f_session['user_display_message'] = 'Error! Invalid Sort Code'
    return redirect(url_for('dashboard'))

  current_user = session.query(User).filter_by(username=username).first()
  if current_user.username == username:  # Checks if username in the session is a valid username in the database
    recipient_query = session.query(User).filter_by(
        account_number=rec_account_number).first()
    try:
      recipient_username = recipient_query.username  # Checks if the provided account number is valid in the database
    except AttributeError:
      f_session[
          'user_display_message'] = 'Error! Invalid recipient account number'
      return redirect(url_for('dashboard'))
    if recipient_query.account_number == rec_account_number and recipient_query.sort_code == rec_sort_code:
      if current_user.bank_bal >= transaction_amount:
        current_user_bank_bal = current_user.bank_bal
        recipient_bank_bal = recipient_query.bank_bal

        current_user_bank_bal -= transaction_amount
        recipient_bank_bal += transaction_amount

        current_datetime = datetime.datetime.now()
        thedate = current_datetime.date().strftime(
            '%d/%m/%Y')  #grab and apply the date and time
        thetime = current_datetime.time().strftime('%H:%M:%S')

        session.query(User).filter(User.username == username).update(
            {'bank_bal':
             current_user_bank_bal})  # updates the users bank balance
        session.query(User).filter(User.username == recipient_username).update(
            {'bank_bal': recipient_bank_bal})
        session.add(
            Transactions(
                username=username,
                sender=username,
                amount=transaction_amount,
                receiver=recipient_username,
                date=thedate,
                time=thetime,
                status="complete"))  # transaction for the current user
        session.add(
            Transactions(
                username=recipient_username,
                sender=username,
                amount=transaction_amount,
                receiver=recipient_username,
                date=thedate,
                time=thetime,
                status="complete"))  # transaction for the recipient user
        session.commit()
        usr_log(
            username,
            f'This user has sent {format_currency(transaction_amount, "GBP", locale="en_GB")} to {recipient_username}'
        )  # Logs the transaction
        usr_log(
            recipient_username,
            f'This user has received {format_currency(transaction_amount, "GBP", locale="en_GB")} from {username}'
        )
        logger.info(
            f'A transaction has been committed between {username} and {recipient_username}'
        )
        f_session[
            'user_display_message'] = f'You have successfully sent {format_currency(transaction_amount, "GBP", locale="en_GB")} to {recipient_username}'
        return redirect(url_for('dashboard'))
      else:
        f_session['user_display_message'] = 'Error! Insufficient funds'
        return redirect(url_for('dashboard'))
    else:
      f_session[
          'user_display_message'] = 'Error! Account Number or Sort Code does not match the recipient'
      return redirect(url_for('dashboard'))


@app.route('/deposit', methods=['POST', 'GET'])
def deposit():
  username = f_session['username']  #check who is currently logged in
  d_amount = sanitise_float(request.form.get('amount'))
  cvv = int(sanitise_float(request.form.get('cvv')))  #check that the values are valid and do not attempt anything malicious
  exp_date = request.form.get('expiry_date')
  try:
    exp_date = datetime.datetime.strptime(
        exp_date, '%m/%y')  #used for checks to insert into the account
    date_now = datetime.datetime.now()  #acquire the date and time
    if exp_date < date_now:  #if the check isnt valid
      f_session['user_display_message'] = 'Error! Invalid expiry date'
      return redirect(url_for('dashboard'))
  except ValueError:  #for if you recieve like a word instead of a number
    f_session['user_display_message'] = 'Error! Invalid expiry date'
    logger.debug(
        f"Invalid input has been inserted when trying to cash this check")
    return redirect(url_for('dashboard'))

  if d_amount == None:  # if the input is sanitised and is not a valid float value then it will be set to none so it will not complete this transaction
    f_session['user_display_message'] = 'Error! Incorrect number format'
    return redirect(url_for('dashboard'))
  if len(str(cvv)) != 3:
    f_session['user_display_message'] = 'Error! Incorrect CVV format'
    return redirect(url_for('dashboard'))

  user = session.query(User).filter_by(username=username).first()
  if user.username == username:
    orig_bal = user.bank_bal
    orig_bal += d_amount  #adding the amount specified to the users bankbalance
    current_datetime = datetime.datetime.now()
    thedate = current_datetime.date().strftime(
        '%d/%m/%Y')  #grab and apply the date and time
    thetime = current_datetime.time().strftime('%H:%M:%S')
    session.add(
        Transactions(username=username,
                     sender='deposit',
                     amount=d_amount,
                     receiver=username,
                     date=thedate,
                     time=thetime,
                     status="complete"))
    session.query(User).filter(User.username == username).update(
        {'bank_bal':
         orig_bal})  #update the bank balance value with the orig_bal variable
    session.commit()
    logger.info(
        f'{username} has depsoited {d_amount} dollars into their account'
    )  #log the information
    f_session[
        'user_display_message'] = f'Successfully deposited {format_currency(d_amount, "GBP", locale="en_GB")} into your account'
    usr_log(
        username,
        f'{user} has deposited {format_currency(d_amount, "GBP", locale="en_GB")} into their account'
    )
    return redirect(
        url_for('dashboard'
                ))  #output messages to the user indicating the deposit occured
  else:
    f_session[
        'user_display_message'] = "Error with username in this transaction"
    return redirect(url_for('dashboard'))


@app.route('/withdraw', methods=['POST', 'GET'])
def withdraw():
  username = f_session['username']
  user = session.query(User).filter_by(
      username=username).first()  #does user exist

  #retrieve the amount to be withdrawn in correct form
  w_amount = float("{:.2f}".format(float(request.form.get('amount'))))
  if w_amount <= 0:
    f_session['user_display_message'] = 'Error! Invalid amount'
    return redirect(url_for('dashboard'))

  orig_bal = user.bank_bal

  if user.username == username:
    if orig_bal >= w_amount:
      orig_bal -= w_amount  #subtract the amount from the users bank balance
      current_datetime = datetime.datetime.now()
      thedate = current_datetime.date().strftime('%d/%m/%Y')
      thetime = current_datetime.time().strftime(
          '%H:%M:%S')  #generate the date and time for the transaction
      session.add(
          Transactions(username=username,
                       sender='withdrawal',
                       amount=w_amount,
                       receiver=username,
                       date=thedate,
                       time=thetime,
                       status="complete"))
      session.query(User).filter(User.username == username).update(
          {'bank_bal': orig_bal})
      session.commit(
      )  #update the users bank balance and apply a new instance of a transaction occuring
      logger.info(f'{username} has withdrew {w_amount} from their account')
      #logging evidence of
      f_session[
          'user_display_message'] = f'Successfully withdrawed {format_currency(w_amount, "GBP", locale="en_GB")} from your account'
      usr_log(
          username,
          f'{user} has withdrawed {format_currency(w_amount, "GBP", locale="en_GB")} from their account'
      )
      return redirect(url_for('dashboard'))  #output messages for the user
    else:
      f_session[
          'user_display_message'] = 'Insufficent funds to withdraw funds from the account'  #covers whether the user tries to withdraw a value beyond the balance within the bank
      usr_log(
          username,
          f'{username} has failed to withdraw {w_amount} dollars from their account'
      )
      logger.info(
          f'{username} failed to withdraw {w_amount} from their account')
      return redirect(url_for('dashboard'))

  else:
    f_session[
        'user_display_message'] = "Error with username in this transaction"
    return redirect(url_for('dashboard'))


@app.route('/securitydashboard', methods=['POST', 'GET'])
def check_role(username):
  #user = User.query.filterby(username=username).first() #can aaron correct this so it grabs the username from the html file,
  user = session.query(User).filter_by(username=username).first()
  if user.role == "admin":  #looking to see if the user is an admin
    checkedrole = "admin"
    logger.info(f"User '{username}' has entered the admin dashboard.")
    usr_log(username, f'{username} has accessed the admin page')
    return checkedrole  #will return and allow access to the admin dashboard
  else:
    checkedrole = "notAdmin"  #if user isnt admin, inform the other method of this so return false and then it will load the admin page
    return checkedrole


@app.route('/view_balance', methods=[
    'POST', 'GET'
])  # i dont think this is used so it can be deleted/ignored
def check_balance(account_number):
  user = session.query(User).filter_by(
      account_number=account_number).first()  #checks for username in database
  if user:
    return user.bank_bal  #returns user bank balance back to the function its called from
  else:
    print("User not found")


@app.route('/check_code', methods=['POST', 'GET'])
def code_check():
  if f_session['username'] == None:
    return redirect(url_for('home'))
  username = f_session['username']
  user_query = session.query(User).filter_by(username=username).first(
  )  # Makes a query to the database to check if the username is in the database
  if username == user_query.username:
    try:
      if f_session['user_rec_code'] == user_query.recovery_code:
        f_session['user_rec_code'] = None
        return redirect(url_for('dashboard'))
      else:
        f_session[
            'user_rec_code'] = user_query.recovery_code  #set the current user code to the specific users recovery code
        return redirect(url_for('dashboard'))
    except KeyError:
      f_session['user_rec_code'] = user_query.recovery_code
      logger.debug(f"Key Error occured on user recovery code")
      return redirect(url_for('dashboard'))

  else:
    f_session['user_rec_code'] = 'Error fetching recovery code'
    return redirect(url_for('dashboard'))


@app.route('/add_funds', methods=['POST', 'GET'])
def add_funds():
  if f_session[
      'username'] == None:  #is there a user logged in if not send back to home screen
    return redirect(url_for('home'))
  username = f_session['lookup_username']
  user = session.query(User).filter_by(username=username).first()
  funds = float(request.form.get('amount'))  #retrieve the amount to be added
  orig_bal = user.bank_bal
  orig_bal += funds  #add the funds amount to the bank bal
  if user:
    current_datetime = datetime.datetime.now()
    thedate = current_datetime.date().strftime('%d/%m/%Y')
    thetime = current_datetime.time().strftime('%H:%M:%S')  #acquire date and time for transaction log
    account_number = user.account_number
    session.add(
        Transactions(
            username=f_session['username'],
            sender='admin',
            receiver=username,
            amount=funds,
            date=thedate,
            time=thetime,
            status="complete"))  #apply a new instance of a transaction
    session.query(User).filter(User.username == username).update(
        {'bank_bal': orig_bal})
    session.commit()  #commit the transaction after updating the value in sql
    f_session[
        'admin_display_message'] = f"Successfully added {format_currency(funds, 'GBP', locale='en_GB')} to {username} account"
    usr_log(
        username,
        f"{f_session['username']} has added funds of {format_currency(funds, 'GBP', locale='en_GB')} to {username} account"
    )
    logger.info(
        f"{format_currency(funds, 'GBP', locale='en_GB')} has been added to {username}'s account"
    )  #messages on log files and to the screen if adding funds successful
    return redirect(url_for('admindashboard'))
  else:
    f_session[
        'admin_display_message'] = f"Failed to add {format_currency(funds, 'GBP', locale='en_GB')} to {username} account"
    logger.info(
        f"Failed to add {format_currency(funds, 'GBP', locale='en_GB')} to {username} account"
    )
    usr_log(
        username,
        f"{f_session['username']} failed to add funds {format_currency(funds, 'GBP', locale='en_GB')} to {username} account"
    )  #messages on log files and to the screen if adding funds fails
    return redirect(url_for('admindashboard'))


@app.route("/setup_2fa")  #code to intialise 2fa
def setup_2fa():
  username = f_session['try_username']

  secret = session.query(User).filter_by(
      username=username).first().secret_token

  uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username,
                                                 issuer_name="NEXTSAFE")

  base64_qr_image = get_b64encoded_qr_image(uri)
  return render_template("mfa/setup_2fa.html",secret=secret,qr_image=base64_qr_image)


@app.route("/verify_2fa", methods=["GET", "POST"])
def verify_2fa():
    if request.method == 'GET':
        # Error message handling
        try:
            error_message = f_session['error_message']
            f_session['error_message'] = None
        except KeyError:
            error_message = ''

        return render_template('mfa/verify_2fa.html', error_message=error_message)
    else:  # Only two functions so else should be fine here
        otp = request.form.get('otp')
        username = f_session['try_username']
        secret = session.query(User).filter_by(username=username).first().secret_token
        # Imported function from security/mfa.py
        if is_otp_valid(username, secret, otp):
            print("2FA verification successful!!")
            f_session['username'] = username
            return redirect('/dashboard')
        else:
            print("Invalid OTP. Please try again.")
            return render_template('mfa/verify_2fa.html', error_message='Invalid OTP. Please try again.')


if __name__ == '__main__':
  app.run(debug=True)

#Then when program begins, decrypt the encrypted log files.
