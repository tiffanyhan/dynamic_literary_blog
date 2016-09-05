from google.appengine.ext import db
from utils import users_key, blog_key, render_str, \
                  make_pw_hash, valid_pw


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


class Submission(db.Model):
    '''
    class used to create the submission instances to be
    inserted into and retrieved from the db
    '''
    user = db.ReferenceProperty(User, collection_name='submissions')
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    def render(self):
        '''
        method that renders the submission using the submission.html
        template, correctly rendering line breaks in html
        '''
        self._render_text = self.content.replace('\n', '<br>')
        return render_str('submission.html', submission=self)

    @classmethod
    def by_id(cls, submission_id):
        '''
        retrieves a submission instance from the db using a
        given submission key identifier
        '''
        key = db.Key.from_path('Submission',
                               int(submission_id),
                               parent=blog_key())
        submission = db.get(key)
        return submission


class Comment(db.Model):
    '''
    class used to create the comment instances to be inserted
    into and retrieved from the db
    '''
    submission = db.ReferenceProperty(Submission, collection_name='comments')
    user = db.ReferenceProperty(User, collection_name='comments')
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    @classmethod
    def by_id(cls, comment_id):
        '''
        retrieves a comment instance from the db using a
        given comment key identifier
        '''
        key = db.Key.from_path('Comment', int(comment_id))
        comment = db.get(key)
        return comment


class Like(db.Model):
    '''
    class used to create the like instances to be inserted
    into and retrieved from the db
    '''
    submission = db.ReferenceProperty(Submission, collection_name='likes')
    user = db.ReferenceProperty(User, collection_name='likes')
    created = db.DateTimeProperty(auto_now_add=True)
