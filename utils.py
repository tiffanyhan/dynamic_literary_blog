from google.appengine.ext import db
from string import letters

import jinja2
import os

import re
import hashlib
import hmac
import random
import string

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

SECRET = 'imsosecret'


# MODEL CLASSES
def users_key(name='default'):
    '''
    returns a key to be used as the parent for each
    user instance created
    '''
    return db.Key.from_path('/', name)


def blog_key(name='default'):
    '''
    returns a key to be used as the parent for each
    submission instance created
    '''
    return db.Key.from_path('/', name)


def render_str(template, **params):
    '''
    a global version of render_str that is available
    to functions that don't inherit from Handler
    '''
    t = jinja_env.get_template(template)
    return t.render(params)


# FORM VALIDATION
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")


def valid_username(username):
    '''
    checks that a valid username was entered
    '''
    return username and USER_RE.match(username)


def valid_password(password):
    '''
    checks that a valid password was entered
    '''
    return password and PASSWORD_RE.match(password)


def valid_email(email):
    '''
    checks that either an email was not entered or
    if it was, that a valid one was entered
    '''
    return not email or EMAIL_RE.match(email)


# PASSWORD HASHING
def make_salt():
    '''
    makes a salt to be used for hashing passwords
    '''
    return ''.join(random.choice(string.letters) for x in xrange(5))


def make_pw_hash(name, pw, salt=''):
    '''
    hashes a password, either with a new salt or
    with an already existing one
    '''
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s|%s' % (salt, h)


def valid_pw(name, password, h):
    '''
    takes the salt from the user's hashed pw in the db,
    and ensures that hashing the entered pw with that salt
    gives the hashed pw in the db
    '''
    salt = h.split('|')[0]
    return h == make_pw_hash(name, password, salt)


# COOKIES
def hash_str(s):
    '''
    given some input, creates a hashed output.
    used for making secure cookie values
    '''
    return hmac.new(SECRET, s).hexdigest()


def make_secure_val(s):
    '''
    makes a secure cookie value
    '''
    return "%s|%s" % (s, hash_str(s))


def check_secure_val(h):
    '''
    takes the unhashed part of the cookie.  if hashing it
    matches the entire cookie value, then the unhashed
    part of the cookie is returned
    '''
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val
