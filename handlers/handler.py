from utils.templates import template_dir, jinja_env
from utils.cookies import make_secure_val, check_secure_val
from models.user import User

import webapp2


class Handler(webapp2.RequestHandler):
    '''
    class that all our handlers will inherit from.
    contains convenience functions that all handlers
    will have access to.
    '''

    def write(self, *a, **kw):
        '''
        a convenience function for rendering templates
        '''
        self.response.write(*a, **kw)

    def render_str(self, template, **params):
        '''
        a convenience function for rendering templates
        '''
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        '''
        renders a given template with the provided parameters
        '''
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        '''
        makes a secure cookie value, adds the cookie
        to the response headers
        '''
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        '''
        if a value exists for a given cookie, check if the
        value is valid.  if it is, return that value.
        '''
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        '''
        given a user instance, get its key identifier and
        use this to set a secure cookie value
        '''
        self.set_secure_cookie('user-id', str(user.key().id()))

    def logout(self):
        '''
        clears the cookie from the response headers
        '''
        self.response.headers.add_header('Set-Cookie', 'user-id=; Path=/')

    def initialize(self, *a, **kw):
        '''
        this function is automatically invoked whenever a user
        visits any page.

        if a secure value exists for the user-id cookie, and
        the associated user instance in the db exists, then
        self.user is set to that user instance

        '''
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user-id')
        self.user = uid and User.by_id(int(uid))
