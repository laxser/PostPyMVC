#!/usr/bin/python

import logging
from application import application

if __name__ == "__main__":
	import paste.httpserver
	HOST = "192.168.1.2"
	PORT = int("5555")
	logging.basicConfig(level=logging.DEBUG)
	paste.httpserver.serve(application, host=HOST, port=PORT)

