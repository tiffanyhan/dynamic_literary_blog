from functools import wraps


def owner_submission_required(f):
    '''
    the user must be the owner of the requested submission
    in order to continue.  if not, the user is redirected
    to the blog entry permalink page
    '''
    @wraps(f)
    def decorated_function(self, *args, **kwargs):
        submission = kwargs['submission']

        if self.user.key().id() == submission.user.key().id():
            return f(self, *args, **kwargs)
        else:
            submission_id = args[0]
            self.redirect('/%s' % submission_id)
    return decorated_function


def not_owner_submission_required(f):
    '''
    the user must not be the owner of the request submission
    in order to continue.  if the user is the owner, she
    is redirected to the blog entry permalink page
    '''
    @wraps(f)
    def decorated_function(self, *args, **kwargs):
        submission = kwargs['submission']

        if self.user.key().id() != submission.user.key().id():
            return f(self, *args, **kwargs)
        else:
            submission_id = args[0]
            self.redirect('/%s' % submission_id)
    return decorated_function


def owner_comment_required(f):
    '''
    the user must be the owner of the requested comment
    in order to continue.  if not, the user is redirected
    to the blog entry permalink page
    '''
    @wraps(f)
    def decorated_function(self, *args, **kwargs):
        comment = kwargs['comment']

        if self.user.key().id() == comment.user.key().id():
            return f(self, *args, **kwargs)
        else:
            submission_id = args[0]
            self.redirect('/%s' % submission_id)
    return decorated_function
