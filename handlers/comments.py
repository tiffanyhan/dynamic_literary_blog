from google.appengine.ext import db
from handlers.handler import Handler
from models.comment import Comment
from decorators.authentication import login_required_redirect_login
from decorators.check_existence import submission_required, \
    comment_required
from decorators.authorization import owner_comment_required

import time


class NewCommentHandler(Handler):
    @login_required_redirect_login
    @submission_required
    def get(self, submission_id, **kwargs):
        '''
        render the form to make a new comment
        '''
        submission = kwargs['submission']
        self.render('comments/new_comment.html', submission=submission)

    @login_required_redirect_login
    @submission_required
    def post(self, submission_id, **kwargs):
        '''
        creates a new comment instance and inserts it into the db.
        content is required to make a new comment
        '''
        content = self.request.get('content')

        if content:
            comment = Comment(user=self.user, content=content, **kwargs)
            comment.put()
            time.sleep(0.1)

            self.redirect('/%s' % submission_id)
        else:
            error = 'You must enter content'
            self.render('comments/new_comment.html', error=error, **kwargs)


class EditCommentHandler(Handler):
    @login_required_redirect_login
    @submission_required
    @comment_required
    @owner_comment_required
    def get(self, submission_id, comment_id, **kwargs):
        '''
        renders the form to edit a comment
        '''
        self.render('comments/edit_comment.html', **kwargs)

    @login_required_redirect_login
    @submission_required
    @comment_required
    @owner_comment_required
    def post(self, submission_id, comment_id, **kwargs):
        '''
        updates the appropriate comment instance in the db.
        then redirects the user to the blog entry permalink
        page.  content is required to update the comment.s
        '''
        comment = kwargs['comment']
        content = self.request.get('content')

        if content:
            comment.content = content
            comment.put()
            time.sleep(0.1)

            self.redirect('/%s' % submission_id)
        else:
            error = 'You must enter content'
            self.render('comments/edit_comment.html', error=error, **kwargrs)


class DeleteCommentHandler(Handler):
    @login_required_redirect_login
    @submission_required
    @comment_required
    @owner_comment_required
    def get(self, submission_id, comment_id, **kwargs):
        '''
        renders the form to delete a comment
        '''
        self.render('comments/delete_comment.html', **kwargs)

    @login_required_redirect_login
    @submission_required
    @comment_required
    @owner_comment_required
    def post(self, submission_id, comment_id, **kwargs):
        '''
        deletes the appropriate comment instance from the db.
        then redirects the user to the blog entry permalink page
        '''
        comment = kwargs['comment']
        db.delete(comment)
        time.sleep(0.1)

        self.redirect('/%s' % submission_id)
