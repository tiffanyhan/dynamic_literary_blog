from google.appengine.ext import db
from handlers.handler import Handler
from utils.models import blog_key
from models.submission import Submission
from models.comment import Comment
from models.like import Like
from decorators.authentication import login_required_redirect_login
from decorators.check_existence import submission_required
from decorators.authorization import owner_submission_required

import time


class SubmissionHandler(Handler):
    @submission_required
    def get(self, submission_id, **kwargs):
        '''
        using the submission_id passed in as a parameter in the URL,
        gets the associated submission instance in the db and renders
        the permalink page with it

        if the associated submission instance in the db DNE,
        returns a 404 error
        '''
        submission = kwargs['submission']

        self.render("submissions/permalink.html", submission=submission)


class NewHandler(Handler):
    @login_required_redirect_login
    def get(self):
        '''
        renders the form to submit a new blog entry
        '''
        self.render("submissions/new.html")

    @login_required_redirect_login
    def post(self):
        '''
        creates a new submission instance and inserts it into the db.
        then redirects the user to the blog entry permalink page.
        both subject and content are required to make a blog entry.
        '''
        subject = self.request.get("subject")
        content = self.request.get("content")

        if subject and content:
            submission = Submission(parent=blog_key(),
                                    user=self.user,
                                    subject=subject,
                                    content=content)
            submission.put()
            time.sleep(0.1)

            self.redirect('/%s' % str(submission.key().id()))

        else:
            error = "You must enter both a subject and content"
            self.render("submissions/new.html",
                        subject=subject,
                        content=content,
                        error=error)


class EditPostHandler(Handler):
    @login_required_redirect_login
    @submission_required
    @owner_submission_required
    def get(self, submission_id, **kwargs):
        '''
        render the form to edit a post
        '''
        self.render('submissions/edit.html', **kwargs)

    @login_required_redirect_login
    @submission_required
    @owner_submission_required
    def post(self, submission_id, **kwargs):
        '''
        gets all the submitted info and updates the appropriate
        submission instance in the db.  then redirects the user
        to the blog entry permalink page.  both subject and content
        are required to update the submission instance
        '''
        submission = kwargs['submission']
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            submission.subject = subject
            submission.content = content
            submission.put()
            time.sleep(0.1)

            self.redirect('/%s' % submission_id)
        else:
            error = "You must enter both a subject and content"
            self.render("submissions/edit.html", error=error, **kwargs)


class DeletePostHandler(Handler):
    @login_required_redirect_login
    @submission_required
    @owner_submission_required
    def get(self, submission_id, **kwargs):
        '''
        render the form to delete a post
        '''
        self.render('submissions/delete.html', **kwargs)

    @login_required_redirect_login
    @submission_required
    @owner_submission_required
    def post(self, submission_id, **kwargs):
        '''
        delete the appropriate submission instance in the db, and
        also delete all of its associated comments and likes in the db
        '''
        submission = kwargs['submission']
        comments = Comment.all().filter('submission =', submission)
        likes = Like.all().filter('submission =', submission)

        db.delete(submission)
        db.delete(comments)
        db.delete(likes)
        time.sleep(0.1)

        self.redirect('/')