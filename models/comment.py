from google.appengine.ext import db
from submission import Submission
from user import User


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
