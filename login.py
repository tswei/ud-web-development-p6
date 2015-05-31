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

import os, webapp2, jinja2, hashlib, hmac, string, random, re
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
								autoescape = True)

SECRET = "imsosecret"								
								
def hash_str(s):
	return hmac.new(SECRET, s).hexdigest()
	
def check_secure_val(h):
	val = h.split("|")[0]
	if h == make_secure_val(val):
		return val

def make_secure_val(s):
	return "%s|%s" % (s, hmac.new(SECRET, s).hexdigest())
		
def salted_hash(s, salt=None):
	if salt == None:
		salt = ''.join(random.choice(string.letters) for _ in range(5))
	return "%s|%s" % (salt, hash_str(s + salt))

def blog_key(name = 'default'):
	return db.Key.from_path('blogs', name)	
	
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def verify_username(username):
	if not (username and USER_RE.match(username)):
		return "That is not a vaild username"
	elif UserList.gql("WHERE user_id = :1", username).get():
		return "That username is already taken"	

PASS_RE = re.compile(r"^.{3,20}$")
def verify_password(password):
	return not (password and PASS_RE.match(password))

EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
def verify_email(email):
	return not((not email) or EMAIL_RE.match(email))		
		
def verify_login(username, password):
	user = UserList.gql("WHERE user_id = :1", username).get()
	if user:
		if user.user_id == username and user.pass_id == salted_hash(password, user.pass_id.split("|")[0]):
			return user
		
class UserList(db.Model):
	user_id = db.StringProperty(required = True)
	pass_id = db.StringProperty(required = True)
	email_id = db.StringProperty
	created = db.DateTimeProperty(auto_now_add = True)
	last_logon = db.DateTimeProperty(auto_now = True)
		
class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)
		
	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)
		
	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

	def render_unwritten(self):
		self.render("unwritten.html")
		
	def get_cookie(self, value):
		return self.request.cookies.get(value)
	
	def check_secure_login(self):
		username = self.get_cookie('user_id')
		return str(check_secure_val(username))
		if username:
			user_id = check_secure_val(username)
			return user_id
			if user_id:
				# params = dict(login_newpost = "new post", signup_logout = "logout",
				              # login_link = "/blog/newpost", signup_link = "/blog/logout")
				return user_id, # params
			else:
				self.response.delete_cookie('user_id')
	
	def login(self, user_id):
		self.response.headers.add_header('Set-Cookie', "user_id=%s;path=/" % str(make_secure_val(user_id)))
		self.redirect('/blog/welcome')

class WelcomePage(Handler):
	def get(self):
		user_id = self.check_secure_login()
		if user_id:
			# params["username"] = user_id
			self.render('welcome.html', username=user_id)
		else:
			self.redirect('/blog/signup')
			
class LogoutPage(Handler):
	def get(self):
		self.response.delete_cookie('user_id')
		self.redirect('/blog/signup')
		
class LoginPage(Handler):
	def render_login(self, **params):
		self.render('login_page.html', **params)
	
	def get(self):
		self.render_login()
				
	def post(self, **params):
		username = self.request.get("username")
		password = self.request.get("password")
		
		params = dict(username = username)
		user = verify_login(username, password)
		if user:
			self.login(user.user_id)
		else:
			params['error_username'] = "Invalid Login"
			self.render_login(**params)
	
class SignupPage(Handler):
	def render_signup(self, **params):
		self.render('signup_page.html', **params)
		
	def get(self):
		self.render_signup()
	
	def post(self):
		error_list = ['error_username', 'error_password', 'error_verify', 'error_email']
		username = self.request.get("username")
		password = self.request.get("password")
		verify = self.request.get("verify")
		email = self.request.get("email")
		
		params = dict(username = username, email = email)
		error_username = verify_username(username)
		if error_username:
			params['error_username'] = error_username
		
		if verify_password(password):
			params['error_password'] = "That is not a valid password"
			
		elif verify != password:
			params['error_verify'] = "Passwords do not match"
			
		if verify_email(email):
			params['error_email'] = "That is not a valid email"
			
		if any(key in error_list for key in params.keys()):
			self.render_signup(**params)
		else:
			u = UserList(parent = blog_key(), user_id = username, pass_id = salted_hash(password), email_id = email)
			u.put()
			user = db.get(u.key())
			self.login(user.user_id)
