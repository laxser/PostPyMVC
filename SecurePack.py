#!/usr/bin/python

import logging
import hashlib
import time
import cPickle
import base64
import zlib

from Crypto.Cipher import AES

URANDOM=None
def randomBytes(n):
	global URANDOM
	if URANDOM is None:
		URANDOM = open('/dev/urandom', 'rb')
	return URANDOM.read(n)

COOKIE='Cookie'

class UnpackException(Exception):pass
class DataCorruption(UnpackException):pass
class Expired(UnpackException):pass

def pad(s, blockSize):
	extra = len(s) % blockSize
	if extra:
		padding = blockSize - extra
		return s + 'X' * padding
	else:
		return s

def securePack(data, secret, timeout=0):
	"""
	Given pickle'able data, secret key, and optional timeout, return opaque URL-able string.
	"""
	dataWithTimeout = (data, timeout)
	pickled = cPickle.dumps(dataWithTimeout)
	compressed = zlib.compress(COOKIE + pickled)
	initialisationVector = randomBytes(AES.block_size)

	key = hashlib.md5(secret).digest()
	encryptor = AES.new(key, AES.MODE_CBC, initialisationVector)
	cipherText = encryptor.encrypt(
		pad(compressed, AES.block_size)
	)
	encoded = base64.urlsafe_b64encode(initialisationVector + cipherText)
	return encoded

def secureUnpack(packedData, secret):
	"""
	Given packed data (ostensibly) returned from securePack, return original data (or None)
	"""
	try:
		# Cipher text and Initialisation vector
		ctav = base64.urlsafe_b64decode(packedData)
	except:
		logging.debug("%r not valid base64" % (packedData,))
		raise DataCorruption("invalid base64")

	if len(ctav) < AES.block_size:
		raise DataCorruption("too small")

	initialisationVector, cipherText = ctav[:AES.block_size], ctav[AES.block_size:]
	if len(cipherText) % AES.block_size:
		raise DataCorruption("corrupt cipherText")
	key = hashlib.md5(secret).digest()
	decryptor = AES.new(key, AES.MODE_CBC, initialisationVector)
	compressed = decryptor.decrypt(cipherText)
	try:
		decompressed = zlib.decompress(compressed)
	except zlib.error:
		raise DataCorruption("decrypts to invalid .gz")
	if not decompressed.startswith(COOKIE):
		logging.debug("bad cookie")
		raise DataCorruption("bad cookie")
	pickled = decompressed[len(COOKIE):]
	(data, timeout) = cPickle.loads(pickled)
	if timeout and timeout < time.time():
		raise Expired(timeout)
	return data
