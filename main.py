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

import os, webapp2, jinja2, hashlib, hmac, string, random, re, json, urllib2, logging

from datetime import datetime
from xml.dom import minidom
from google.appengine.ext import db
from webapp2_extras import routes
from google.appengine.api import memcache

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
								autoescape = True)

SECRET = "imsosecret"								

##################
#GLOBAL FUNCTIONS#		
						
def hash_str(s):
	return hmac.new(SECRET, str(s)).hexdigest()
	
def check_secure_val(h):
	val = h.split("|")[0]
	if h == make_secure_val(val):
		return val

def make_secure_val(s):
	return "%s|%s" % (s, hmac.new(SECRET, str(s)).hexdigest())
		
def salted_hash(s, salt=None):
	if salt == None:
		salt = ''.join(random.choice(string.letters) for _ in range(5))
	return "%s|%s" % (salt, hash_str(s + salt))

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

def render_str(template, **params):
	t = jinja_env.get_template(template)
	return t.render(params)

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)
	
def blog_key(name = 'default'):
	return db.Key.from_path('blogs', name)

def memcache_posts(memcache_key, update = False):
	client = memcache.Client()
	if client.gets(memcache_key) is None:
		if memcache_key == 'top':
			posts = list(db.GqlQuery("SELECT * FROM Post ORDER BY created DESC LIMIT 10"))
		else:
			db_key = db.Key.from_path('Post', int(memcache_key), parent=blog_key())
			posts = [db.get(db_key)]
		memcache.set(memcache_key, (posts, datetime.utcnow()))
	(posts, set_time) = memcache.get(memcache_key)
	if update:
		while True:
			(posts, set_time) = client.gets(memcache_key)
			posts = [update] + posts
			if client.cas(memcache_key, (posts, set_time)):
				break
	posts = posts[:10]
	age = (datetime.utcnow() - set_time).total_seconds()
	return posts, age

############
#DB OBJECTS#	

class UserList(db.Model):
	user_id = db.StringProperty(required = True)
	pass_id = db.StringProperty(required = True)
	email_id = db.StringProperty
	created = db.DateTimeProperty(auto_now_add = True)
	last_logon = db.DateTimeProperty(auto_now = True)
	
class Post(db.Model):
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

	def render(self):
		self._render_text = self.content.replace('\n', '<br>')
		return render_str("post.html", p = self)
		
	def render_json(self):
		obj = dict({'subject' : self.subject,
					'content' : self.content,
					'created' : self.created.strftime('%c'),
					'last_modified' : self.last_modified.strftime('%c'),
					})
		return obj
	
##########
#HANDLERS#

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
		if username:
			if check_secure_val(username):
				return username.split("|")[0]
			else:
				del self.request.cookie['user_id']
	
	def login(self, user):
		self.response.headers.add_header('Set-Cookie', "user_id=%s" % str(make_secure_val(user.key().id())))
		self.redirect('/blog/welcome')
		
	def write_json(self, posts):
		self.response.headers['Content-Type'] = 'application/json'
		obj = [post.render_json() for post in posts]
		self.write(json.dumps(obj))
		
class BlogFront(Handler):
	def get(self):
		posts, age = memcache_posts('top')
		if re.search(r'\.json$', self.request.url):
			self.write_json(posts)
		else:
			self.render("front.html", posts=posts, age=age)

class PostPage(Handler):
	def get(self, post_id, json):
		json = (json == ".json")
		
		# key = db.Key.from_path('Post', int(post_id), parent=blog_key())
		# post = db.get(key)
		post, age = memcache_posts(post_id)
		post = post[0]
		if not post:
			self.error(404)
			return
		
		if json:
			self.write_json([post])
		else:
			self.render("permalink.html", post = post, age = age)
	
class NewPost(Handler):
	def get(self):
		if self.check_secure_login():
			self.render("newpost.html")
		else:
			self.redirect("/blog/login")
	
	def post(self):
		subject = self.request.get("subject")
		content = self.request.get("content")
		
		if subject and content:
			p = Post(parent = blog_key(), subject = subject, content = content)
			p.put()
			memcache_posts('top', p)
			memcache_posts(str(p.key().id()))
			self.redirect("/blog/%s" % str(p.key().id()))
		else:
			error = "subject and content please!"
			self.render("newpost.html", subject=subject, content=content, error=error)
			
class WelcomePage(Handler):
	def get(self):
		id = self.check_secure_login()
		if id:
			key = db.Key.from_path("UserList", int(id), parent=blog_key())
			user = db.get(key)
			self.render('welcome.html', username=user.user_id)
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
			self.login(user)
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
			self.login(user)
			
class FlushPage(Handler):
	def get(self):
		memcache.flush_all()
		self.redirect('/blog')
			
app = webapp2.WSGIApplication([
webapp2.SimpleRoute(r'/blog/?(?:\.json$)?', handler=BlogFront, name='blogfront'),
routes.PathPrefixRoute(r'/blog', [
	webapp2.Route(r'/login', handler=LoginPage, name='login'),
	webapp2.Route(r'/signup', handler=SignupPage, name='signup'),
	webapp2.Route(r'/logout', handler=LogoutPage, name='logout'),
	webapp2.Route(r'/welcome', handler=WelcomePage, name='welcome'),
	webapp2.Route(r'/newpost', handler=NewPost, name='newpost'),
	webapp2.Route(r'/<post_id:\d+><json:(\.json$)?>', handler=PostPage, name='postpage'),
	webapp2.Route(r'/flush', handler=FlushPage, name='flushmemcache'),
	])],
debug=True)
