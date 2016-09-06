from functools import wraps
from models.submission import Submission
from models.comment import Comment


def submission_required(f):
    '''
    the requested submission must exist in order
    to continue.  if not, a 404 error is returned
    '''
    @wraps(f)
    def decorated_function(self, *args, **kwargs):
        submission_id = args[0]
        submission = Submission.by_id(submission_id)

        if submission:
            kwargs['submission'] = submission
            return f(self, *args, **kwargs)
        else:
            self.error(404)
            return
    return decorated_function


def comment_required(f):
    '''
    the request comment must exist in order to continue.
    if not, a 404 error is returned
    '''
    @wraps(f)
    def decorated_function(self, *args, **kwargs):
        comment_id = args[1]
        comment = Comment.by_id(comment_id)

        if comment:
            kwargs['comment'] = comment
            return f(self, *args, **kwargs)
        else:
            self.error(404)
            return
    return decorated_function
