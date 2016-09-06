from google.appengine.ext import db
from submission import Submission
from user import User


class Like(db.Model):
    '''
    class used to create the like instances to be inserted
    into and retrieved from the db
    '''
    submission = db.ReferenceProperty(Submission, collection_name='likes')
    user = db.ReferenceProperty(User, collection_name='likes')
    created = db.DateTimeProperty(auto_now_add=True)
