import hashlib
import random
import string


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
