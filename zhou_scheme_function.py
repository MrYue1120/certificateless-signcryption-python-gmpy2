#! usr/bin/env python3
# -*- coding: utf-8 -*-

from gmpy2 import mpz, is_prime, random_state, mpz_urandomb, div, mpz_random, powmod, bit_length, mul, invert, t_mod
from data_trans import *
import random
import sys
import time
import hashlib

rand = random_state(random.randrange(sys.maxsize))

# generate 2 large prime that fulfill the condition q | p - 1
def p_q_gen(bits):
	while True :
		p = mpz(2)**(bits - 1) + mpz_urandomb(rand, bits - 1)
		q = div((p - 1), 2)
		if (is_prime(q) & is_prime(p)) :
			return p, q

#	define the time-counting function		
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

# generate the 'g' generator
def g_gen(p, q):
	while True :
		g = mpz_random(rand, p)
		temp = powmod(g, q, p)
		if temp == 1 :
			return g

# compute X_u = g**x_u mod p
def secret_compute(p, q, g):
	x_u = mpz_random(rand, q)
	X_u = powmod(g, x_u, p)
	return x_u, X_u

# define the hashfunction that return 2048 bits hashvalue
def hash_func(x):
	temp1 = hashlib.sha512()
	temp2 = hashlib.sha512()
	temp3 = hashlib.sha512()
	temp4 = hashlib.sha512()
	temp1.update(x + b"1")
	temp2.update(x + b"2")
	temp3.update(x + b"3")
	temp4.update(x + b"4")
	ret_str = temp1.hexdigest() + temp2.hexdigest() + temp3.hexdigest() + temp4.hexdigest()
	return ret_str

# define the H1 hashfunction	
def H1_hash(uid, x, y, bits):
	temp = hash_func(uid.encode('utf-8') + str(x).encode('utf-8') + str(y).encode('utf-8'))
	H1_hash_value = mpz(temp[ : bits - 2], 16)
	return H1_hash_value

# define the H2 hashfunction
def H2_hash(uid, x, y, bits):
	temp = hash_func(uid.encode('utf-8') + str(x).encode('utf-8') + str(y).encode('utf-8'))
	H2_hash_value = mpz(temp[ : bits - 2], 16)
	return H2_hash_value

# define the H3 hashfunction
def H3_hash(x, bits):
	temp = hash_func(str(x).encode('utf-8'))
	H3_hash_value = mpz(temp[ : bits - 2], 16)
	return H3_hash_value

# define the H4 hashfunction
def H4_hash(uid, x, y, z, bits):
	temp = hash_func(uid.encode('utf-8') + str(x).encode('utf-8') + str(y).encode('utf-8') + str(z).encode('utf-8'))
	H4_hash_value = mpz(temp[ : bits - 2], 16)
	return H4_hash_value


# V_value compute
def V_compute(x, y, p_pub, h1_b, w, p):
	V_temp = t_mod(x * y * powmod(p_pub, h1_b, p), p)
	V_value = powmod(V_temp, w, p)
	return V_value

# define the x || y binding function, and return mpz(x || y)
def data_bind(x, y):
	x_bin = bin(x)
	x_bin_str = str(x_bin)
	y_bin = bin(y)
	y_bin_str = str(y_bin)
	x_y_bind_str = x_bin_str[2:] + y_bin_str[2 :]
	x_y_bind = mpz(x_y_bind_str, 2)
	return x_y_bind

# define the x || y binding function, after binding, bit_length(y) = bits,and return mpz(x || y)
def data_format_bind(x, y, bits):
	len_y = bit_length(y)
	x_bin = bin(x << (bits - len_y))
	x_bin_str = str(x_bin)
	y_bin = bin(y)
	y_bin_str = str(y_bin)
	x_y_bind_str = x_bin_str[2:] + y_bin_str[2 :]
	x_y_bind = mpz(x_y_bind_str, 2)
	return x_y_bind


# user key generate
class user_key(object):
	def __init__(self, uid, params):
		self.uid = uid
		self.x_u, self.X_u = secret_compute(params.p, params.q, params.g)
		self.r_u, self.Y_u = secret_compute(params.p, params.q, params.g)
		self.y_u = t_mod((self.r_u + t_mod(params.s * H1_hash(uid, self.X_u, self.Y_u, bit_length(params.q)), params.q)), params.q)	#y_u = r_u + s * H1(ID_u, X_u, Y_u)
		self.public_key = (self.uid, self.X_u, self.Y_u)
		self.private_key = (self.x_u, self.y_u)

# system params generate			
class system_params(object):
	def __init__(self, bits):
		self.p, self.q = p_q_gen(bits)
		self.g = g_gen(self.p, self.q)
		self.s, self.p_pub = secret_compute(self.p, self.q, self.g)

#	define the signcrypt function
def signcrypt(Alice, Bob, params, m):
	#	R = g ** w mod p, w <-- Zq
	w, R_value = secret_compute(params.p, params.q, params.g)
	#	h1_b = H1(ID_b, X_b, Y_b) <-- Zq
	h1_b = H1_hash(Bob.uid, Bob.X_u, Bob.Y_u, bit_length(params.q))
	#	V = (X_b * Y_b * (p_pub**h1_b)) ** w mod p
	V_value = V_compute(Bob.X_u, Bob.Y_u, params.p_pub, h1_b, w, params.p)
	#	h3 = H3(V) <-- Zp
	h3_value = H3_hash(V_value, bit_length(params.p))
	#	d = H4(ID_a, m, X_a, R) <-- Zq
	d_value = H4_hash(Alice.uid, m, Alice.X_u, R_value, bit_length(params.q))
	#	f = H4(ID_a, m, Y_a, R) <-- Zq
	f_value = H4_hash(Alice.uid, m, Alice.Y_u, R_value, bit_length(params.q))
	#	U = d * (x_a + y_a) + w * f mod q
	U_value = t_mod((d_value * (Alice.x_u + Alice.y_u) + w * f_value), params.q)
	#	m || U
	m_u_value = data_format_bind(m, U_value, bit_length(params.q))
	#	C = H3(V) (+) m || U
	C_value = h3_value ^ m_u_value
	#	h2 = H2(ID_a, R, C) <-- Zq
	h2_value =  H2_hash(Alice.uid, R_value, C_value, bit_length(params.q))
	#	S = w * ((x_a + y_a +h2) ** -1) mod q
	x_y_h_invert = invert(Alice.x_u + Alice.y_u + h2_value, params.q)
	S_value = t_mod(w * x_y_h_invert, params.q)
	#	signcryption_text = (h2, S, C)
	Signcryption_text = (h2_value, S_value, C_value)
	return Signcryption_text

#	define the unsigncrypt function
def unsigncrypt(Alice, Bob, params, Signcryption_text):
	#	get h2, S, C
	h2_value = Signcryption_text[0]
	S_value = Signcryption_text[1]
	C_value = Signcryption_text[2]
	#	h1_a = H1(ID_a, X_a, Y_a) <-- Zq
	h1_a = H1_hash(Alice.uid, Alice.X_u, Alice.Y_u, bit_length(params.q))
	#	R' = (X_a * Y_a * (p_pub**h1_a) * (g ** h2)) ** w mod p
	temp = powmod(params.g, h2_value, params.p)
	temp = t_mod(temp * Alice.Y_u, params.p)
	R_value_un = V_compute(Alice.X_u, temp, params.p_pub, h1_a, S_value, params.p)
	#	V' = R' ** (x_b + y_b) mod q
	V_value_un = powmod(R_value_un, t_mod(Bob.x_u + Bob.y_u, params.q), params.p)
	#	h3 = H3(V') <-- Zp
	h3_value = H3_hash(V_value_un, bit_length(params.p))
	#	m || U = C (+) h3
	m_u_value_un = C_value ^ h3_value
	#	get m'
	m_un = m_u_value_un >> bit_length(params.q)
	#	get U'
	U_value_un = (m_un << bit_length(params.q)) ^ m_u_value_un
	#	d' = H4(ID_a, m', X_a, R) <-- Zq
	d_value_un = H4_hash(Alice.uid, m_un, Alice.X_u, R_value_un, bit_length(params.q))
	#	f' = H4(ID_a, m', Y_a, R) <-- Zq
	f_value_un = H4_hash(Alice.uid, m_un, Alice.Y_u, R_value_un, bit_length(params.q))
	#	verify g ** U' == ((X_a * Y_a * (p_pub ** h1_a)) ** d') * (R' ** f') mod p
	#	if return true, then return m'; else return None
	left_value = powmod(params.g, U_value_un, params.p)
	temp1 = V_compute(Alice.X_u, Alice.Y_u, params.p_pub, h1_a, d_value_un, params.p)
	temp2 = powmod(R_value_un, f_value_un, params.p)
	right_value = t_mod(temp1 * temp2, params.p)
	if left_value == right_value :
		return m_un

'''
params = system_params(1024)
Alice = user_key("alice", params)
Bob = user_key("bob", params)
m = mpz(2**16)
Signcryption_text = signcrypt(Alice, Bob, params, m)
m_un = unsigncrypt(Alice, Bob, params, Signcryption_text)
print(m_un)
'''
