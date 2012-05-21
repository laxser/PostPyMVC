#!/usr/bin/python

import logging
import re

import webob

from AuthWrapper import AuthWrapper
from framework import controller

log = logging.getLogger(__name__)

class FakeApp(object):
	def __call__(self, environ, start_response):
		req = webob.Request(environ)
		if re.match("/login$", req.path_info):
			return self.login(environ, start_response)
		if re.match("/logout$", req.path_info):
			return self.logout(environ, start_response)

		return self.other(environ, start_response)

	@controller
	def other(self, cursor, req):
		return "you are requesting " + req.path_info

	@controller
	def logout(self, cursor, req):
		try:
			del req.environ["REMOTE_USER_ID"]
		except KeyError, e:
			pass
		return "bye.html", dict()

	@controller
	def login(self, cursor, req):
		log.debug("%s: %s" % (req.method, req.path_info))

		if req.method not in ("GET", "POST"):
			return HTTPMethodNotAllowed()

		if req.method == "GET":
			redirect = "/" if req.path_info == "/login" else req.path_info
			log.debug("show login form")
			return "login.html", dict(action="/login", redirect=redirect, error="")

		elif req.method == "POST":
			user = req.params.get("login", None)
			passwd = req.params.get("password", None)
			redirect = req.params.get("redirect", "/")
			log.debug("user=%s, passwd=%s, redirect=%s" % (user, passwd, redirect))
			if user == "user" and passwd == "passwd":
				req.environ["REMOTE_USER_ID"] = "100"
				return "postlogin.html", dict(user=user, redirect=redirect)
			else:
				return "login.html", dict(action="/login", redirect=redirect, 
						error="invalid username/password") 

fa = FakeApp()
wa = AuthWrapper(fa, login=FakeApp.login)

application = wa

