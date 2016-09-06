from google.appengine.ext import db
from utils.models import users_key
from utils.pw_hashing import make_pw_hash, valid_pw


class User(db.Model):
    '''
    class used to create the user instances to be
    inserted into and retrieved from the db
    '''
    username = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        '''
        retrieves a user instance from the db using the
        cookie's user-id value
        '''
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        '''
        retrieves a user instance from the db using the
        username that was entered
        '''
        u = User.all().filter('username =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        '''
        takes all user information, makes a pw hash, then
        creates a new user instance with the hashed pw
        '''
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    username=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        '''
        if this user exists in the db, and their pw
        is a valid one, then return that user instance
        '''
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u
