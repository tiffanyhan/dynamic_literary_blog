from google.appengine.ext import db
from user import User
from utils.models import blog_key, render_str


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
