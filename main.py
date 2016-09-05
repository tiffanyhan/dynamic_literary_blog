#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from google.appengine.ext import db
from utils import template_dir, jinja_env, \
                  valid_username, valid_password, valid_email, \
                  make_secure_val, check_secure_val, \
                  blog_key, users_key
from models import User, Submission, Comment, Like

from functools import wraps

import webapp2
import time


# DECORATOR FUNCTIONS
# TODO: include custom error messages when the user is
# redirected for a more user-friendly experience
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


# ALL HANDLERS
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


class MainHandler(Handler):
    def get(self):
        '''
        show all submissions on the main page
        '''
        submissions = db.GqlQuery('''
            SELECT * from Submission ORDER BY created DESC limit 10
        ''')

        self.render("main.html", submissions=submissions)


class NewHandler(Handler):
    @login_required_redirect_login
    def get(self):
        '''
        renders the form to submit a new blog entry
        '''
        self.render("new.html")

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
            time.sleep(1)

            self.redirect('/%s' % str(submission.key().id()))

        else:
            error = "You must enter both a subject and content"
            self.render("new.html",
                        subject=subject,
                        content=content,
                        error=error)


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

        self.render("permalink.html", submission=submission)


class SignUpHandler(Handler):
    @logout_required
    def get(self):
        '''
        renders the form to register
        '''
        self.render("signup.html")

    @logout_required
    def post(self):
        '''
        creates a new user instance and inserts it into the db.
        logs the user in, then redirects the user to the welcome page.

        if there are any errors, render the signup form again with
        the appropriate saved data and error messages
        '''
        have_error = False

        self.username = self.request.get("username").encode("latin-1")
        self.password = self.request.get("password").encode("latin-1")
        self.verify = self.request.get("verify").encode("latin-1")
        self.email = self.request.get("email").encode("latin-1")

        params = dict(username=self.username,
                      email=self.email)

        # check for any errors
        if not valid_username(self.username):
            params['username_error'] = "That's not a valid username"
            have_error = True
        elif User.by_name(self.username):
                params['username_error'] = 'That user already exists'
                have_error = True

        if not valid_password(self.password):
            params['password_error'] = "That's not a valid password"
            have_error = True
        elif self.password != self.verify:
            params['verify_error'] = "Your passwords don't match"

        if not valid_email(self.email):
            params['email_error'] = "That's not a valid email"
            have_error = True

        # there's some error(s)
        if have_error:
            self.render("signup.html", **params)
        # succest!!
        else:
            user = User.register(self.username, self.password, self.email)
            user.put()

            self.login(user)
            self.redirect('/welcome')


class WelcomeHandler(Handler):
    @login_required_redirect_login
    def get(self):
        '''
        renders the welcome page
        '''
        self.render("welcome.html", user=self.user)


class LogInHandler(Handler):
    @logout_required
    def get(self):
        '''
        render the form to login
        '''
        self.render('login.html')

    @logout_required
    def post(self):
        '''
        check the information entered against information stored
        in the db.  if all is well, log the user in and redirect
        them to the welcome page.

        if not, render the login form again with an error message
        '''
        have_error = False

        username = self.request.get("username").encode("latin-1")
        password = self.request.get("password").encode("latin-1")

        user = User.login(username, password)

        if user:
            self.login(user)
            self.redirect('/welcome')
        else:
            error = 'Invalid login'
            self.render('login.html', error=error)


class LogOutHandler(Handler):
    @login_required_redirect_home
    def get(self):
        '''
        renders the logout page
        '''
        self.render('logout.html', username=self.user.username)

    @login_required_redirect_home
    def post(self):
        '''
        log the user out and redirect them to the signup page
        '''
        self.logout()
        self.redirect('/')


class EditPostHandler(Handler):
    @login_required_redirect_login
    @submission_required
    @owner_submission_required
    def get(self, submission_id, **kwargs):
        '''
        render the form to edit a post
        '''
        self.render('edit.html', **kwargs)

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
            time.sleep(1)

            self.redirect('/%s' % submission_id)
        else:
            error = "You must enter both a subject and content"
            self.render("edit.html", error=error, **kwargs)


class DeletePostHandler(Handler):
    @login_required_redirect_login
    @submission_required
    @owner_submission_required
    def get(self, submission_id, **kwargs):
        '''
        render the form to delete a post
        '''
        self.render('delete.html', **kwargs)

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
        time.sleep(1)

        self.redirect('/')


class NewCommentHandler(Handler):
    @login_required_redirect_login
    @submission_required
    def get(self, submission_id, **kwargs):
        '''
        render the form to make a new comment
        '''
        submission = kwargs['submission']
        self.render('new_comment.html', submission=submission)

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
            time.sleep(1)

            self.redirect('/%s' % submission_id)
        else:
            error = 'You must enter content'
            self.render('new_comment.html', error=error, **kwargs)


class EditCommentHandler(Handler):
    @login_required_redirect_login
    @submission_required
    @comment_required
    @owner_comment_required
    def get(self, submission_id, comment_id, **kwargs):
        '''
        renders the form to edit a comment
        '''
        self.render('edit_comment.html', **kwargs)

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
            time.sleep(1)

            self.redirect('/%s' % submission_id)
        else:
            error = 'You must enter content'
            self.render('edit_comment.html', error=error, **kwargrs)


class DeleteCommentHandler(Handler):
    @login_required_redirect_login
    @submission_required
    @comment_required
    @owner_comment_required
    def get(self, submission_id, comment_id, **kwargs):
        '''
        renders the form to delete a comment
        '''
        self.render('delete_comment.html', **kwargs)

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
        time.sleep(1)

        self.redirect('/%s' % submission_id)


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
        time.sleep(1)

        self.redirect('/%s' % submission_id)

# ALL ROUTES
app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/newpost', NewHandler),
    ('/([0-9]+)', SubmissionHandler),
    ('/signup', SignUpHandler),
    ('/welcome', WelcomeHandler),
    ('/login', LogInHandler),
    ('/logout', LogOutHandler),
    ('/([0-9]+)/edit', EditPostHandler),
    ('/([0-9]+)/delete', DeletePostHandler),
    ('/([0-9]+)/newcomment', NewCommentHandler),
    ('/([0-9]+)/comment/([0-9]+)/edit', EditCommentHandler),
    ('/([0-9]+)/comment/([0-9]+)/delete', DeleteCommentHandler),
    ('/([0-9]+)/like', LikePostHandler)
], debug=True)
