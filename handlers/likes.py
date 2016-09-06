from handlers.handler import Handler
from models.like import Like
from decorators.authentication import login_required_redirect_login
from decorators.check_existence import submission_required
from decorators.authorization import not_owner_submission_required

import time


class LikePostHandler(Handler):
    @login_required_redirect_login
    @submission_required
    @not_owner_submission_required
    def post(self, submission_id, **kwargs):
        '''
        allows the user to add a like to a blog entry.
        the user is only allowed to like a post once
        '''
        submission = kwargs['submission']

        for like in submission.likes:
            if self.user.key().id() == like.user.key().id():
                self.redirect('/%s' % submission_id)
                return

        like = Like(submission=submission, user=self.user)
        like.put()
        time.sleep(0.1)

        self.redirect('/%s' % submission_id)
