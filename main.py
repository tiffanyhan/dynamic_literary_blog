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
import os
from string import letters
from functools import wraps
import re

import webapp2
import jinja2
import time
import hashlib
import hmac

import random
import string

SECRET = 'imsosecret'

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
								autoescape = True)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
	'''
	checks that a valid username was entered
	'''
	return username and USER_RE.match(username)


PASSWORD_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
	'''
	checks that a valid password was entered
	'''
	return password and PASSWORD_RE.match(password)


EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
def valid_email(email):
	'''
	checks that either an email was not entered or
	if it was, that a valid one was entered
	'''
	return not email or EMAIL_RE.match(email)


# PASSWORD HASHING
def make_salt():
	'''
	makes a salt to be used for hashing passwords
	'''
	return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt=''):
	'''
	hashes a password, either with a new salt or
	with an already existing one
	'''
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return '%s|%s' % (salt, h)

def valid_pw(name, password, h):
	'''
	takes the salt from the user's hashed pw in the db,
	and ensures that hashing the entered pw with that salt
	gives the hashed pw in the db
	'''
	salt = h.split('|')[0]
	return h == make_pw_hash(name, password, salt)


def users_key(name = 'default'):
	'''
	returns a key to be used as the parent for each
	user instance created
	'''
	return db.Key.from_path('/', name)


class User(db.Model):
	'''
	class used to create the user instances to be
	inserted into and retrieved from the db
	'''
	username = db.StringProperty(required = True)
	pw_hash = db.StringProperty(required = True)
	email = db.StringProperty()

	@classmethod
	def by_id(cls, uid):
		'''
		retrieves a user instance from the db using the
		cookie's user-id value
		'''
		return User.get_by_id(uid, parent=users_key())

	@classmethod
	def by_name(cls, name):
		'''
		retrieves a user instance from the db using the
		username that was entered
		'''
		u = User.all().filter('username =', name).get()
		return u

	@classmethod
	def register(cls, name, pw, email = None):
		'''
		takes all user information, makes a pw hash, then
		creates a new user instance with the hashed pw
		'''
		pw_hash = make_pw_hash(name, pw)
		return User(parent = users_key(),
					username = name,
					pw_hash = pw_hash,
					email = email)

	@classmethod
	def login(cls, name, pw):
		'''
		if this user exists in the db, and their pw
		is a valid one, then return that user instance
		'''
		u = cls.by_name(name)
		if u and valid_pw(name, pw, u.pw_hash):
			return u


def blog_key(name = 'default'):
	'''
	returns a key to be used as the parent for each
	submission instance created
	'''
	return db.Key.from_path('/', name)


class Submission(db.Model):
	'''
	class used to create the submission instances to be
	inserted into and retrieved from the db
	'''
	user = db.ReferenceProperty(User, collection_name='submissions')
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)

	def render(self):
		'''
		method that renders the submission using the submission.html
		template, correctly rendering line breaks in html
		'''
		self._render_text = self.content.replace('\n', '<br>')
		return render_str('submission.html', submission=self)

	@classmethod
	def by_id(cls, submission_id):
		key = db.Key.from_path('Submission', int(submission_id), parent=blog_key())
		submission = db.get(key)
		#TODO: self is not available for class methods, so we
		# need to find another method for error handlings
		if not submission:
			self.error(404)
			return

		return submission


class Comment(db.Model):
	submission = db.ReferenceProperty(Submission, collection_name='comments')
	user = db.ReferenceProperty(User, collection_name='comments')
	content = db.TextProperty(required=True)
	created = db.DateTimeProperty(auto_now_add=True)

	@classmethod
	def by_id(cls, comment_id):
		key = db.Key.from_path('Comment', int(comment_id))
		comment = db.get(key)
		#TODO: self is not available for class methods, so we
		# need to find another method for error handlings
		if not comment:
			self.error(404)
			return

		return comment


class Like(db.Model):
	submission = db.ReferenceProperty(Submission, collection_name='likes')
	user = db.ReferenceProperty(User, collection_name='likes')
	created = db.DateTimeProperty(auto_now_add=True)


# COOKIES
def hash_str(s):
	'''
	given some input, creates a hashed output.
	used for making secure cookie values
	'''
	return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
	'''
	makes a secure cookie value
	'''
	return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
	'''
	takes the unhashed part of the cookie.  if hashing it
	matches the entire cookie value, then the unhashed
	part of the cookie is returned
	'''
	val = h.split('|')[0]
	if h == make_secure_val(val):
		return val


#DECORATOR FUNCTIONS
#TODO: include custom error messages when the user is
#redirected for a more user-friendly experience
def logout_required(f):
	@wraps(f)
	def decorated_function(self, *args, **kwargs):
		if not self.user:
			return f(self, *args, **kwargs)
		else:
			self.redirect('/')
	return decorated_function


def login_required_redirect_home(f):
	@wraps(f)
	def decorated_function(self, *args, **kwargs):
		if self.user:
			return f(self, *args, **kwargs)
		else:
			self.redirect('/')
	return decorated_function


def login_required_redirect_login(f):
	@wraps(f)
	def decorated_function(self, *args, **kwargs):
		if self.user:
			return f(self, *args, **kwargs)
		else:
			self.redirect('/login')
	return decorated_function


def owner_submission_required(f):
	@wraps(f)
	def decorated_function(self, *args, **kwargs):
		submission_id = args[0]
		submission = Submission.by_id(submission_id)

		if self.user.key().id() == submission.user.key().id():
			args += (submission, )
			return f(self, *args, **kwargs)
		else:
			self.redirect('/%s' % submission_id)
	return decorated_function


def not_owner_submission_required(f):
	@wraps(f)
	def decorated_function(self, *args, **kwargs):
		submission_id = args[0]
		submission = Submission.by_id(submission_id)
		print(self.user, submission.user)

		if self.user.key().id() != submission.user.key().id():
			args += (submission, )
			return f(self, *args, **kwargs)
		else:
			self.redirect('/%s' % submission_id)
	return decorated_function


def owner_comment_required(f):
	@wraps(f)
	def decorated_function(self, *args, **kwargs):
		submission_id = args[0]
		comment_id = args[1]
		comment = Comment.by_id(comment_id)

		if self.user.key().id() == comment.user.key().id():
			args += (comment, )
			return f(self, *args, **kwargs)
		else:
			self.redirect('/%s' % submission_id)
	return decorated_function


def render_str(template, **params):
	'''
	a global version of render_str that is available
	to functions that don't inherit from Handler
	'''
	print('render string called')
	t = jinja_env.get_template(template)
	return t.render(params)


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
		submissions = db.GqlQuery("SELECT * from Submission ORDER BY created DESC limit 10")

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
		creates a new submission instance and inserts it into the db.  then redirects
		the user to the blog entry permalink page.  both subject and content are required
		to make a blog entry.
		'''
		subject = self.request.get("subject")
		content = self.request.get("content")

		if subject and content:
			submission = Submission(parent=blog_key(), user=self.user, subject=subject, content=content)
			submission.put()
			time.sleep(1)

			self.redirect('/%s' % str(submission.key().id()))

		else:
			error = "You must enter both a subject and content"
			self.render("new.html", subject=subject, content=content, error=error)

class SubmissionHandler(Handler):
	def get(self, submission_id):
		'''
		using the submission_id passed in as a parameter in the URL, gets the
		associated submission instance in the db and renders the permalink page
		with it

		if the associated submission instance in the db DNE, returns a 404 error
		'''
		submission = Submission.by_id(submission_id)

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

		params = dict(username = self.username,
					  email = self.email)

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
	@owner_submission_required
	def get(self, submission_id, submission):
		self.render('edit.html', submission=submission)

	@login_required_redirect_login
	@owner_submission_required
	def post(self, submission_id, submission):
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
			self.render("edit.html", submission=submission, error=error)


class DeletePostHandler(Handler):
	@login_required_redirect_login
	@owner_submission_required
	def get(self, submission_id, submission):
		self.render('delete.html', submission=submission)

	@login_required_redirect_login
	@owner_submission_required
	def post(self, submission_id, submission):
		comments = Comment.all().filter('submission =', submission)
		likes = Like.all().filter('submission =', submission)

		db.delete(submission)
		db.delete(comments)
		db.delete(likes)
		time.sleep(1)

		self.redirect('/')


class NewCommentHandler(Handler):
	@login_required_redirect_login
	def get(self, submission_id):
		submission = Submission.by_id(submission_id)
		self.render('new_comment.html', submission=submission)

	@login_required_redirect_login
	def post(self, submission_id):
		submission = Submission.by_id(submission_id)
		content = self.request.get('content')

		if content:
			comment = Comment(submission=submission, user=self.user, content=content)
			comment.put()
			time.sleep(1)

			self.redirect('/%s' % submission_id)
		else:
			error = 'You must enter content'
			self.render('new_comment.html', submission=submission, error=error)


class EditCommentHandler(Handler):
	@login_required_redirect_login
	@owner_comment_required
	def get(self, submission_id, comment_id, comment):
		submission = Submission.by_id(submission_id)
		self.render('edit_comment.html', submission=submission, comment=comment)

	@login_required_redirect_login
	@owner_comment_required
	def post(self, submission_id, comment_id, comment):
		content = self.request.get('content')

		if content:
			comment.content = content
			comment.put()
			time.sleep(1)

			self.redirect('/%s' % submission_id)
		else:
			submission = Submission.by_id(submission_id)
			error = 'You must enter content'
			self.render('edit_comment.html', submission=submission, comment=comment, error=error)


class DeleteCommentHandler(Handler):
	@login_required_redirect_login
	@owner_comment_required
	def get(self, submission_id, comment_id, comment):
		submission = Submission.by_id(submission_id)
		self.render('delete_comment.html', submission=submission)

	@login_required_redirect_login
	@owner_comment_required
	def post(self, submission_id, comment_id, comment):
		db.delete(comment)
		time.sleep(1)

		self.redirect('/%s' % submission_id)


class LikePostHandler(Handler):
	@login_required_redirect_login
	@not_owner_submission_required
	def post(self, submission_id, submission):
		for like in submission.likes:
			if self.user.key().id() == like.user.key().id():
				self.redirect('/%s' % submission_id)
				return
		like = Like(submission=submission, user=self.user)
		like.put()
		time.sleep(1)

		self.redirect('/%s' % submission_id)

# ALL ROUTES AND ASSOCIATED HANDLERS
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
