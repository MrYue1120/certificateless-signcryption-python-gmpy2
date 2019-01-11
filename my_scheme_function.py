#! usr/bin/env python3
# -*- coding: utf-8 -*-

from gmpy2 import mpz, is_prime, random_state, mpz_urandomb, div, mpz_random, powmod, bit_length, mul, invert, t_mod
import random
import sys
import time
import hashlib

rand = random_state(random.randrange(sys.maxsize))

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

# generate 2 large prime that fulfill the condition q | p - 1
def p_q_gen(bits):
	while True :
		p = mpz(2)**(bits - 1) + mpz_urandomb(rand, bits - 1)
		q = div((p - 1), 2)
		if (is_prime(q) & is_prime(p)) :
			return p, q

# generate the 'g' generator of Zp
def g_gen(p, q):
	while True :
		g = mpz_random(rand, p)
		temp = powmod(g, q, p)
		if temp == 1 :
			return g

# generate X_u and x_u that fulfill X_u = g**x_u mod p
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
def H2_hash(uid, x, y, z, bits):
	temp = hash_func(uid.encode('utf-8') + str(x).encode('utf-8') + str(y).encode('utf-8') + str(z).encode('utf-8'))
	H2_hash_value = mpz(temp[ : bits - 2], 16)
	return H2_hash_value

# define the H3 hashfunction
def H3_hash(x, bits):
	temp = hash_func(str(x).encode('utf-8'))
	H3_hash_value = mpz(temp[ : bits - 2], 16)
	return H3_hash_value

# T_value compute, (x * y * (p_pub ** h1_b)) ** w mod p
def T_compute(x, y, p_pub, h1_b, w, p):
	V_temp = t_mod(x * y * powmod(p_pub, h1_b, p), p)
	V_value = powmod(V_temp, w, p)
	return V_value


# user key class
class user_key(object):
	def __init__(self, uid, params):
		self.uid = uid
		self.x_u, self.X_u = secret_compute(params.p, params.q, params.g)
		self.r_u, self.Y_u = secret_compute(params.p, params.q, params.g)
		self.y_u = t_mod((self.r_u + t_mod(params.s * H1_hash(uid, self.X_u, self.Y_u,  bit_length(params.q)), params.q)), params.q)	#y_u = r_u + s * H1(ID_u, X_u, Y_u)
		self.public_key = (self.uid, self.X_u, self.Y_u)
		self.private_key = (self.x_u, self.y_u)

# system params class			
class system_params(object):
	def __init__(self, bits):
		self.p, self.q = p_q_gen(bits)
		self.g = g_gen(self.p, self.q)
		self.s, self.p_pub = secret_compute(self.p, self.q, self.g)


# signcryption function
def signcrypt(Alice, Bob, params, m):
	#	R = g ** w mod p, w <-- Zq
	w, R_value = secret_compute(params.p, params.q, params.g)
	#	h1_b = H1(ID_b, X_b, Y_b) <-- Zq
	h1_b = H1_hash(Bob.uid, Bob.X_u, Bob.Y_u, bit_length(params.q))
	#	T = (X_b * Y_b * (p_pub**h1_b)) ** w mod p
	T_value = T_compute(Bob.X_u, Bob.Y_u, params.p_pub, h1_b, w, params.p)
	#	C = m * T mod p
	C_value = t_mod(m * T_value, params.p)
	#	h2 = H2(ID_a, T, m, C) <-- Zq
	h2_value = H2_hash(Alice.uid, T_value, m, C_value, bit_length(params.q))
	#	(x_a + y_a) ** -1 mod q
	x_y_invert = invert(Alice.x_u + Alice.y_u, params.q)
	#	S = h2 * w * (x_a + y_a) ** -1 mod q
	S_value = t_mod(h2_value * w * x_y_invert, params.q)
	#	signcryption_text = (R, C, S)
	Signcryption_text = (R_value, C_value, S_value)
	return Signcryption_text

# unsigncryption function
def unsigncrypt(Alice, Bob, params, Signcryption_text):
	#	get R, C, S
	R_value = Signcryption_text[0]
	C_value = Signcryption_text[1]
	S_value = Signcryption_text[2]
	#	T' = R ** (x_b + y_b) mod p	, where "un" represent the symbol '
	T_value_un = powmod(R_value, t_mod(Bob.x_u + Bob.y_u, params.q), params.p)
	#	T' ** -1 mod p
	T_value_un_invert = invert(T_value_un, params.p)
	#	m' = (T' ** -1) * C mod p
	m_un = t_mod(T_value_un_invert * C_value, params.p)
	#	h2' = H2(ID_a, T', m', C) <-- Zq
	h2_value_un = H2_hash(Alice.uid, T_value_un, m_un, C_value, bit_length(params.q))
	#	h1_a = H1(ID_a, X_a, Y_a) <-- Zq
	h1_a = H1_hash(Alice.uid, Alice.X_u, Alice.Y_u, bit_length(params.q))
	#	verify R ** h2' mod p == (X_a * Y_a * (p_pub ** h1_a)) ** S mod p
	#	if return true, then return m' as the plain-text
	left_value = powmod(R_value, h2_value_un, params.p)
	right_value = T_compute(Alice.X_u, Alice.Y_u, params.p_pub, h1_a, S_value, params.p)
	if left_value == right_value :
		return m_un


params = system_params(1024)
Alice = user_key("alice", params)
Bob = user_key("bob", params)
m = mpz(2**16)
Signcryption_text = signcrypt(Alice, Bob, params, m)
m_un = unsigncrypt(Alice, Bob, params, Signcryption_text)
print(m_un)

