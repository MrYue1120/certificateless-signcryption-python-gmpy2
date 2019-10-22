#! usr/bin/env python3
# -*- coding: utf-8 -*-

import time

#	time-counting function
#	reference : github/paillier-gmpy2
def timing(f, c = 0):
	def wrap(*args):
		time1 = time.time()
		return_value = f(*args)
		time2 = time.time()
		clock_time = time2 - time1
		if c == 0:
			return return_value
		else :
			return return_value, clock_time
	return wrap