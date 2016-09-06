from functools import wraps


def logout_required(f):
    '''
    the user must the logged out to continue.
    if the user is logged in, she is redirected
    to the home page
    '''
    @wraps(f)
    def decorated_function(self, *args, **kwargs):
        if not self.user:
            return f(self, *args, **kwargs)
        else:
            self.redirect('/')
    return decorated_function


def login_required_redirect_home(f):
    '''
    the user must be logged in to continue.
    if not, the user is redirected to the
    home page
    '''
    @wraps(f)
    def decorated_function(self, *args, **kwargs):
        if self.user:
            return f(self, *args, **kwargs)
        else:
            self.redirect('/')
    return decorated_function


def login_required_redirect_login(f):
    '''
    the user must be logged in to continue.
    if not the user is redirected to the login page
    '''
    @wraps(f)
    def decorated_function(self, *args, **kwargs):
        if self.user:
            return f(self, *args, **kwargs)
        else:
            self.redirect('/login')
    return decorated_function
