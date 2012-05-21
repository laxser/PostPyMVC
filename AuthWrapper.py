#!/usr/bin/python

import logging
import re
import time

import webob
from paste.request import parse_formvars, get_cookies

from SecurePack import securePack, secureUnpack, UnpackException

log = logging.getLogger(__name__)

STORED_KEYS = [
	"REMOTE_USER_ID", 
]
COOKIE_DOMAIN = "192.168.1.2"
COOKIE_NAME = "ultrascriber"
COOKIE_SECRET = "i won't tell you"

class AuthWrapper(object):
	def __init__(self, app, login):
		self.wrappedApp = app
		self.login = login
		self.public_url = []
		assert COOKIE_DOMAIN
		assert COOKIE_NAME
		assert COOKIE_SECRET
	
	def register_public_url(self, url_pattern):
		if isinstance(url_pattern, basestring):
			url_pattern = re.compile(url_pattern)
		self.public_url.append(url_pattern)

	def is_public(self, path):
		for p in self.public_url:
			if p.match(path):
				return True
		return False

	def cookie_okay(self, req):
		jar = get_cookies(req.environ)
		if COOKIE_NAME not in jar:
			return False
		try:
			data = secureUnpack(jar[COOKIE_NAME].value, COOKIE_SECRET)
		except UnpackException:
			# cookie is currupted
			return False
		for k, v in data.iteritems():
			req.environ[k] = v
		log.debug(STORED_KEYS[0] + " is " + str(req.environ[STORED_KEYS[0]]))
		return (STORED_KEYS[0] in req.environ and 
				bool(req.environ[STORED_KEYS[0]]))

	def __call__(self, environ, start_response):
		req = webob.Request(environ)
		log.debug("%s: %s" % (req.method, req.path_info))

		if self.is_public(req.path_info):
			log.debug("this is a public url")
			return self.wrappedApp(environ, start_response)

		start_response = CookieResponder(environ, 
				start_response).start_response

		if re.match("/login$", req.path_info):
			return self.wrappedApp(environ, start_response)

		if re.match("/logout$", req.path_info):
			return self.wrappedApp(environ, start_response)

		log.debug("this is a private url")

		if self.cookie_okay(req):
			return self.wrappedApp(environ, start_response)

		return self.login(self.wrappedApp, environ, start_response)

class CookieResponder:
	def __init__(self, environ, start_response):
		self.environ = environ
		self.appResponse = (start_response,)
		self.timeout = 12 * 60 * 60	# 12 hours

	def start_response(self, status, response_headers, exc_info=None):
		"""
		Look for values in environ, create cookie
		"""
		log.debug("adding cookies now ...")
		content = dict( (k, self.environ.get(k)) for k in STORED_KEYS)
		log.debug("keys to save:\n" + repr(content))

		content = securePack(content, COOKIE_SECRET, time.time() + self.timeout)
		cookie = "%s=%s; Path=/;" % (COOKIE_NAME, content)
		if "https" == self.environ["wsgi.url_scheme"]:
			cookie += " secure;"
		if COOKIE_DOMAIN:
			cookie += " domain=%s" % COOKIE_DOMAIN
		log.debug("\n%s\n" % cookie)
		response_headers.append(("Set-Cookie", cookie))
		return self.appResponse[0](status, response_headers, exc_info)

