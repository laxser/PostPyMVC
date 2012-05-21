#!/usr/bin/python

import time
import cStringIO
import traceback
import cgi
import re

import webob
import webob.exc
import genshi.template

from database import get_cursor

LOADER = genshi.template.TemplateLoader("templates", auto_reload=True, 
		variable_lookup="strict")

def controller(fn):
	def wrapped_handler(*args):
		environ, start_response = args[-2:]
		req = webob.Request(environ)
		cursor = get_cursor()
		extra = (cursor, req)

		try:
			isAjax = re.search("application/json", 
					req.environ["HTTP_ACCEPT"]) >= 0
		except KeyError:
			isAjax = False

		try:
			fnArgs = args[:-2] + extra
			resp = fn(*fnArgs, **req.urlvars)
			# commit on sucess
			#cursor.connection.commit()

			if isinstance(resp, tuple):
				template, context = resp
				resp = webob.Response(
						content_type="text/html", 
						expires=time.time() + 5, 
						body=LOADER.load(template).generate(
							**context).render("xhtml"))
			elif isinstance(resp, basestring):
				resp = webob.Response(body=resp)

		except webob.exc.HTTPException, e:
			resp = e

		except Exception, e:
			if isAjax:
				# to be caught in decorator ajax
				# error msg will be rendered differently
				raise

			out = cStringIO.StringIO()
			traceback.print_exc(file=out)
			tb = out.getvalue()
			error = cgi.escape(tb).replace("\n", "<br/>")
			resp = webob.Response(
					content_type="text/html", 
					expires=time.time() + 5, 
					body=LOADER.load("error.html").generate(
						req=req, error=error).render("xhtml"))

		assert isinstance(resp, webob.Response)

		return resp(environ, start_response)

	return wrapped_handler

