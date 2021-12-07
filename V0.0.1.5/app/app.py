from flask import Flask, render_template, flash,redirect, url_for, session, request, logging
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, IntegerField, validators,  DecimalField, ValidationError
from passlib.hash import sha256_crypt
from functools import wraps
import datetime

app = Flask(__name__)

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'ghtbank'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

mysql = MySQL(app)


@app.route('/')
def hello_world():
    return render_template('homeBank.html')


@app.route('/about')
def about():
    return render_template('bankAbout.html')

class RegisterForm(Form):
    id_number = StringField('id_number', [validators.Length(min=1, max=50)])
    name = StringField('Name', [validators.Length(min=5, max=25, message='אורך השם צרך להיות בין חמישה לעשרים וחמישה תווים')])
    username = StringField('Username', [validators.Length(min=4, max=25, message='אורך שם המשתמש צרך להיות בין ארבעה לעשרים וחמישה תווים')])
    email = StringField('Email', [validators.Email(message='כתובת אימייל לא תקינה')])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')
    
    def __init__(self, *args, **kwargs):  # accept the object
        super(RegisterForm, self).__init__(*args, **kwargs)
    
    def validate_id_number(self, id_number):
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM allowedids WHERE id = %s", [id_number.data])
        if result > 0:
            result = cur.execute("SELECT * FROM user WHERE id = %s", [id_number.data])
            if result > 0:
                raise ValidationError('מספר הזהות כבר בשימוש')
        else:
            raise ValidationError('מספר הזהות לא רשאי לפתיחת חשבון')
    
    def validate_password(self, password):
        flag = True
        if len(password.data) < 8:
            flag = False
        elif sum(1 for c in password.data if c.isupper()) < 1:
            flag = False
        elif sum(1 for c in password.data if c.islower()) < 1:
            flag = False
        elif sum(1 for c in password.data if c.isdigit()) < 1:
            flag = False
        flag = True  # DELETE
        if flag is False:
            raise ValidationError('הסיסמא צריכה להיות באורך של 8 תווים לפחות, להכיל לפחות אות גדולה אחת, אות קטנה אחת, וסיפרה אחת.')
    
    def validate_username(self, username):
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM user WHERE username = %s", [username.data])
        print(result)
        if result > 0:
            raise ValidationError('שם המשתמש כבר בשימוש')

        
    

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        id_number = form.id_number.data
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))
        
        #create cursor
        cur = mysql.connection.cursor()
        
        #exexute query
        cur.execute("INSERT INTO user(id, name, username, password) VALUES(%s, %s, %s, %s)", (id_number, name, username, password))
        
        #commit to DB
        mysql.connection.commit()
        
        #Close the connection
        cur.close()
        
        flash('You are now register and log in', 'seccess')
        
        return redirect(url_for('login'))
    return render_template('register.html', form = form)

class LoginForm(Form):
    username = StringField('username')
    password = PasswordField('password')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    if request.method == 'POST':
        #get from fields
        username = form.username.data
        password_candidate = form.password.data
        
        #create cursor
        cur = mysql.connection.cursor()
        
        #get user by user name
        result = cur.execute("SELECT * FROM user WHERE username = %s", [username])
        
        if result > 0:
            #get stopred hash
            data = cur.fetchone()
            password = data['password']
            
            # compere the passwords
            if sha256_crypt.verify(password_candidate, password):
                #passed
                #get user by user name
                result = cur.execute("SELECT id FROM user WHERE username = %s", [username])
                
                session['id'] = cur.fetchone()['id']
                session['logged_in'] = True
                session['username'] = username
                
                flash('You are now logged in', 'success')
                return redirect(url_for('dashboard'))
            else:
                error = 'Invalid login'
                return render_template('login.html', error=error)
            #Close the connection
            cur.close()
        else:
            error = 'Username not found'
            return render_template('login.html', error=error)
    return render_template('login.html')

def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, please login', 'danger')
            return redirect(url_for('login'))
    return wrap

@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('ההתנתקות הצליחה', 'seccess')
    return redirect(url_for('login'))

@app.route('/dashboard')
@is_logged_in
def dashboard():
    cur = mysql.connection.cursor()
    
    result = cur.execute("SELECT amountOfTokens, amountOfAllocatedTokens FROM user WHERE username = %s", [session['username']])
    
    amount_of_tokens, amount_of_allocated_tokens_in_account = cur.fetchone().values()
    print(amount_of_tokens)
    return render_template('dashboard.html', amount_of_tokens = amount_of_tokens, amount_of_allocated_tokens_in_account =amount_of_allocated_tokens_in_account)

class NewTransactionForm(Form):
    to_username = StringField('to_username')
    amount_of_tokens_to_transact = DecimalField('amount_of_tokens_to_transact')
    title = StringField('title')
    
    def validate_amount_of_tokens_to_transact(self, amount_of_tokens_to_transact):
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT amountOfTokens FROM user WHERE username = %s", [session['username']])
        amount_of_tokens_in_account = cur.fetchone()['amountOfTokens']
        cur.close()
        if amount_of_tokens_to_transact.data > amount_of_tokens_in_account:
            raise ValidationError('אי אפשר להעביר יותר כסף משיש בחשבון')
        if amount_of_tokens_to_transact.data <= 0:
            raise ValidationError('סכום העברה צריך להיות גדול מאפס')
        if amount_of_tokens_to_transact.data != int(amount_of_tokens_to_transact.data):
            raise ValidationError('סכום העברה צריך להיות מספר שלם')
        
    def validate_to_username(self, to_username):
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT username FROM user WHERE username = %s", [to_username.data])
        if result == 0:
            raise ValidationError('שם משתמש אינו קיים')
        if to_username.data == session['username']:
            raise ValidationError('אי אפשר להעביר מטבעות לעצמך')
        cur.close()

@app.route('/newTransaction', methods=['GET', 'POST'])
@is_logged_in
def new_transaction():
    form = NewTransactionForm(request.form)
    if request.method == 'POST' and form.validate():
        from_username = session['username']
        to_username = form.to_username.data
        amount_of_tokens_to_transact = form.amount_of_tokens_to_transact.data
        title = form.title.data
        cur = mysql.connection.cursor()
        user_data = cur.execute("SELECT amountOfTokens, amountOfAllocatedTokens FROM user WHERE id = %s", ([session['id']]))
        amount_of_tokens_in_account, amount_of_allocated_tokens_in_account = cur.fetchone().values()
        cur.execute("INSERT INTO transaction(fromUsername, toUsername, amountOfTokens, transactionTitle) VALUES(%s, %s, %s, %s)", (from_username, to_username, amount_of_tokens_to_transact, title))
        cur.execute("UPDATE user SET amountOfTokens = %s, amountOfAllocatedTokens = %s WHERE id = %s", ((amount_of_tokens_in_account - amount_of_tokens_to_transact), (amount_of_allocated_tokens_in_account + amount_of_tokens_to_transact), [session['id']]))
        
        mysql.connection.commit()
        
        #Close the connection
        cur.close()
        flash('העברה בוצעה', 'success')
        return redirect(url_for('dashboard'))
        
    return render_template('newTransaction.html', form = form)

@app.route('/unApprovedTransactions')
@is_logged_in
def un_approved_transactions():
    cur = mysql.connection.cursor()
    outgoing_transaction = cur.execute("SELECT `transactionId`,`toUsername`,`amountOfTokens`,`transactionTitle`,`transactionDate` FROM transaction WHERE fromUsername = %s and transactionApproved = 0", [session['username']])
    outgoing_transaction = cur.fetchall()
    ingoing_transaction = cur.execute("SELECT `transactionId`,`fromUsername`,`amountOfTokens`,`transactionTitle`,`transactionDate` FROM transaction WHERE toUsername = %s and transactionApproved = 0", [session['username']])
    ingoing_transaction = cur.fetchall()
    return render_template('unApprovedTransactions.html', outgoing_transaction = outgoing_transaction, ingoing_transaction = ingoing_transaction)
    cur.close()


@app.route('/transactionHistory')
@is_logged_in
def transactions_history():
    cur = mysql.connection.cursor()
    outgoing_transaction = cur.execute("SELECT `transactionId`,`toUsername`,`amountOfTokens`,`transactionTitle`,`transactionDate` FROM transaction WHERE fromUsername = %s and transactionApproved = 1", [session['username']])
    outgoing_transaction = cur.fetchall()
    ingoing_transaction = cur.execute("SELECT `transactionId`,`fromUsername`,`amountOfTokens`,`transactionTitle`,`transactionDate` FROM transaction WHERE toUsername = %s and transactionApproved = 1", [session['username']])
    ingoing_transaction = cur.fetchall()
    return render_template('transactionHistory.html', outgoing_transaction = outgoing_transaction, ingoing_transaction = ingoing_transaction)


@app.route('/approveTransaction/<string:transactionId>/')
@is_logged_in
def approve_transaction(transactionId):
    cur = mysql.connection.cursor()
    result = cur.execute("SELECT fromUsername, amountOfTokens FROM transaction WHERE transactionId = %s", [transactionId])
    outgoing_username, amount_of_tokens_to_transact = cur.fetchone().values()
    cur.execute("UPDATE transaction SET transactionApproved = %s, approvelDate = %s WHERE transactionId = %s", (1, datetime.datetime.now(), [transactionId]))
    
    outgoing_user_data = cur.execute("SELECT amountOfAllocatedTokens FROM user WHERE username = %s", ([outgoing_username]))
    amount_of_allocated_tokens_in_account = cur.fetchone()['amountOfAllocatedTokens']
    cur.execute("UPDATE user SET amountOfAllocatedTokens = %s WHERE username = %s", ((amount_of_allocated_tokens_in_account - amount_of_tokens_to_transact), ([outgoing_username])))
    ingoing_user_data = cur.execute("SELECT amountOfTokens FROM user WHERE id = %s", ([session['id']]))
    amount_of_tokens_in_account = cur.fetchone()['amountOfTokens']
    cur.execute("UPDATE user SET amountOfTokens = %s WHERE id = %s", ((amount_of_tokens_in_account + amount_of_tokens_to_transact), [session['id']]))
    mysql.connection.commit()
    cur.close()
    flash('העברה התקבלה', 'success')
    return redirect(url_for('un_approved_transactions'))

@app.route('/declineTransaction/<string:transactionId>/')
@is_logged_in
def decline_transaction(transactionId):
    cur = mysql.connection.cursor()
    result = cur.execute("SELECT fromUsername, amountOfTokens FROM transaction WHERE transactionId = %s", [transactionId])
    outgoing_username, amount_of_tokens_to_transact = cur.fetchone().values()
    cur.execute("DELETE FROM transaction WHERE transactionId = %s", ([transactionId]))
    outgoing_user_data = cur.execute("SELECT amountOfTokens, amountOfAllocatedTokens FROM user WHERE username = %s", ([outgoing_username]))
    amount_of_tokens_in_account, amount_of_allocated_tokens_in_account = cur.fetchone().values()
    cur.execute("UPDATE user SET amountOfTokens = %s, amountOfAllocatedTokens = %s WHERE username = %s", ((amount_of_tokens_in_account + amount_of_tokens_to_transact), (amount_of_allocated_tokens_in_account - amount_of_tokens_to_transact), ([outgoing_username])))
    
    mysql.connection.commit()
    cur.close()
    flash('העברה התקבלה', 'success')
    return redirect(url_for('un_approved_transactions'))

@app.route('/cancelTransaction/<string:transactionId>/')
@is_logged_in
def cancel_transaction(transactionId):
    cur = mysql.connection.cursor()
    result = cur.execute("SELECT amountOfTokens FROM transaction WHERE transactionId = %s", [transactionId])
    amount_of_tokens_to_transact = cur.fetchone()['amountOfTokens']
    cur.execute("DELETE FROM transaction WHERE transactionId = %s", ([transactionId]))
    outgoing_user_data = cur.execute("SELECT amountOfTokens, amountOfAllocatedTokens FROM user WHERE username = %s", ([session['username']]))
    amount_of_tokens_in_account, amount_of_allocated_tokens_in_account = cur.fetchone().values()
    cur.execute("UPDATE user SET amountOfTokens = %s, amountOfAllocatedTokens = %s WHERE username = %s", ((amount_of_tokens_in_account + amount_of_tokens_to_transact), (amount_of_allocated_tokens_in_account - amount_of_tokens_to_transact), ([session['username']])))
    
    mysql.connection.commit()
    cur.close()
    flash('העברה התקבלה', 'success')
    return redirect(url_for('un_approved_transactions'))




if __name__ == "__main__":
    app.secret_key='secret123'
    app.run(host = "0.0.0.0", debug=True)
