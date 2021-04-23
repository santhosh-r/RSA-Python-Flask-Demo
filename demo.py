from flask import Flask, render_template
from flask_bootstrap import Bootstrap
from flask_moment import Moment
from datetime import datetime
from flask_wtf import FlaskForm
from wtforms import TextAreaField, SubmitField
from wtforms.validators import DataRequired
from rsa_cryptosystem import RSACryptosystem
from sys import getsizeof
from time import time

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ualbany-cs521_project-demo_UFSHJ^&%K#@W'
bootstrap = Bootstrap(app)
moment = Moment(app)

class MessageForm(FlaskForm):
    message = TextAreaField('Enter your message:', validators=[DataRequired()])
    submit = SubmitField('Submit')

# create RSACryptosystem object with randomly generated keys
decrypter = RSACryptosystem()
# create encrypter object which only knows public keys
encrypter = RSACryptosystem(decrypter.e, decrypter.n)

def hexa(n): return hex(n)[2:].upper()

def exec_time(f, args):
    t = time()
    ret = f(args)
    t = time() - t
    return ret, t 

@app.route('/', methods=['GET', 'POST'])
def index():
    emsg, dmsg = None, None
    emsg_size, dmsg_size = 0, 0
    msg_len = 0
    etime, dtime = 0.0, 0.0
    form = MessageForm()
    if form.validate_on_submit():
        # encrypt and decrypt and time the execution
        emsg, etime = exec_time(encrypter.encrypt, (form.message.data))
        dmsg, dtime = exec_time(decrypter.decrypt, (emsg))
        # find number of characters in original message
        msg_len = len(dmsg)
        # find actual size of the original message
        dmsg_size = getsizeof(dmsg)
        # find actual size of the encrypted message
        emsg_size = sum([getsizeof(p) for p in emsg])
    # public key pair (e, n)
    publickp = '({}, {})'.format(hexa(encrypter.e), hexa(encrypter.n))
    # encrypted message
    emsg = emsg if emsg is None else '{}'.format('\n'.join([hexa(p) for p in emsg]))
    # send all the information to template rendered
    return render_template('index.html', current_time=datetime.utcnow(),
        form=form, publickp=publickp, emsg=emsg, dmsg=dmsg,
        emsg_size=emsg_size, dmsg_size=dmsg_size, msg_len=msg_len,
        etime=etime, dtime=dtime)

@app.route('/secret')
def secret():
    # display secret key (d)
    return '<p style="font-family:monospace; word-wrap:break-word;">{}</p>'.format(hexa(decrypter.d))

app.run(debug=True)
