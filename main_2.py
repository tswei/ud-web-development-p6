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
from login import SignupPage, LoginPage

SECRET = "imsosecret"

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
								autoescape = True)

# def hash_str(s):
	# return hmac.new(SECRET, s).hexdigest()
	
# def make_secure_val(s):
	# return "%s|%s" % (s, hash_str(s))
	
def check_secure_val(h):
	val = h.split("|")[0]
	if h == salted_hash():
		return val
		
def salted_hash(s, salt=None):
	if salt == None:
		salt = ''.join(random.choice(string.letter) for _ in range(5))
	return "%s|%s" % (hmac.new(s, salt).hexdigest(), salt)

def render_str(template, **params):
	t = jinja_env.get_template(template)
	return t.render(params)

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)
	
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
		
def blog_key(name = 'default'):
	return db.Key.from_path('blogs', name)
		
class Post(db.Model):
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

	def render(self):
		self._render_text = self.content.replace('\n', '<br>')
		return render_str("post.html", p = self)
	
class BlogFront(Handler):
	def get(self):
		posts = db.GqlQuery("select * from Post order by created desc limit 10")
		self.render("front.html", posts=posts)

class PostPage(Handler):
	def get(self, post_id):
		key = db.Key.from_path('Post', int(post_id), parent=blog_key())
		post = db.get(key)
		
		if not post:
			self.error(404)
			return
			
		self.render("permalink.html", post = post)
			
		# self.response.headers['Content-Type'] = 'text/plain'
		# visits = 0
		# visit_cookie_val = self.request.cookies.get('visits')
		# if visit_cookie_val:
			# cookie_val = check_secure_val(visit_cookie_val)
			# if cookie_val:
				
				# visits = int(cookie_val)
		# visits += 1
		
		# new_cookie_val = make_secure_val(str(visits))
		# self.response.headers.add_header('Set-Cookie', 'visits=%s' % new_cookie_val)
		
		# if visits > 10000:
			# self.write("You are the best ever!")
		# else:
			# self.write("You've been here %s times!" % visits)
		

class NewPost(Handler):
	def get(self):
		self.render("newpost.html")
	
	def post(self):
		subject = self.request.get("subject")
		content = self.request.get("content")
		
		if subject and content:
			p = Post(parent = blog_key(), subject = subject, content = content)
			p.put()
			self.redirect("/blog/%s" % str(p.key().id()))
		else:
			error = "subject and content please!"
			self.render("newpost.html", subject=subject, content=content, error=error)
			
app = webapp2.WSGIApplication([
    ('/blog/?', BlogFront),
	('/login', LoginPage),
	('/blog/newpost', NewPost),
	('/signup', SignupPage),
	('/blog/(\d+)', PostPage)
], debug=True)
