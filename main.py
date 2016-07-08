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

def render_str(template, **params):
	print('render string called')
	t = jinja_env.get_template(template)
	return t.render(params)

class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

	def set_secure_cookie(self, name, val):
		cookie_val = make_secure_val(val)
		self.response.headers.add_header(
			'Set-Cookie',
			'%s=%s; Path=/' % (name, cookie_val))

	def read_secure_cookie(self, name):
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_secure_val(cookie_val)

	def login(self, user):
		self.set_secure_cookie('user-id', str(user.key().id()))

	def logout(self):
		self.response.headers.add_header('Set-Cookie', 'user-id=; Path=/')

	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.read_secure_cookie('user-id')
		self.user = uid and User.by_id(int(uid))

def blog_key(name = 'default'):
	return db.Key.from_path('/', name)

class Submission(db.Model):
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)

	def render(self):
		print('render called')
		self._render_text = self.content.replace('\n', '<br>')
		return render_str('submission.html', submission=self)

class MainHandler(Handler):
	def get(self):
		submissions = db.GqlQuery("SELECT * from Submission ORDER BY created DESC limit 10")
		self.render("main.html", submissions=submissions)

class NewHandler(Handler):
	def get(self):
		self.render("new.html")

	def post(self):
		subject = self.request.get("subject")
		content = self.request.get("content")

		if subject and content:
			submission = Submission(parent=blog_key(), subject=subject, content=content)
			submission.put()
			time.sleep(1)

			self.redirect('/%s' % str(submission.key().id()))

		else:
			error = "You must enter both a subject and content"
			self.render("new.html", subject=subject, content=content, error=error)

class SubmissionHandler(Handler):
	def get(self, submission_id):
		key = db.Key.from_path('Submission', int(submission_id), parent=blog_key())
		submission = db.get(key)

		if not submission:
			self.error(404)
			return

		self.render("permalink.html", submission=submission)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
	return username and USER_RE.match(username)

PASSWORD_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
	return password and PASSWORD_RE.match(password)

EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
def valid_email(email):
	return not email or EMAIL_RE.match(email)

# password stuff
def make_salt():
	return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt=''):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return '%s|%s' % (salt, h)

def valid_pw(name, password, h):
	salt = h.split('|')[0]
	return h == make_pw_hash(name, password, salt)

# cookie stuff
def hash_str(s):
	return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
	return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
	val = h.split('|')[0]
	if h == make_secure_val(val):
		return val

# user class for database
def users_key(name = 'default'):
	return db.Key.from_path('/', name)

class User(db.Model):
	username = db.StringProperty(required = True)
	pw_hash = db.StringProperty(required = True)
	email = db.StringProperty()

	@classmethod
	def by_id(cls, uid):
		return User.get_by_id(uid, parent=users_key())

	@classmethod
	def by_name(cls, name):
		u = User.all().filter('username =', name).get()
		return u

	@classmethod
	def register(cls, name, pw, email = None):
		pw_hash = make_pw_hash(name, pw)
		return User(parent = users_key(),
					username = name,
					pw_hash = pw_hash,
					email = email)

	@classmethod
	def login(cls, name, pw):
		u = cls.by_name(name)
		if u and valid_pw(name, pw, u.pw_hash):
			return u

class SignUpHandler(Handler):
	def get(self):
		self.render("signup.html")

	def post(self):
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
	def get(self):
		if self.user:
			self.render("welcome.html", user=self.user)
		else:
			self.redirect("/signup")

class LogInHandler(Handler):
	def get(self):
		self.render('login.html')

	def post(self):
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
	def get(self):
		self.logout()
		self.redirect('/signup')

app = webapp2.WSGIApplication([
	('/', MainHandler),
	('/newpost', NewHandler),
	('/([0-9]+)', SubmissionHandler),
	('/signup', SignUpHandler),
	('/welcome', WelcomeHandler),
	('/login', LogInHandler),
	('/logout', LogOutHandler)
], debug=True)
