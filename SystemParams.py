#! usr/bin/env python3
# -*- coding: utf-8 -*-

from gmpy2 import mpz, is_prime, random_state, mpz_urandomb, mpz_random, powmod, bit_length, mul, invert, t_mod, next_prime, f_div
import random
import sys
import hashlib

rand = random_state(random.randrange(sys.maxsize))

class KGC(object) :

	def __init__( self, bits ) :
		self.p_q_gen( bits )
		self.g_gen()
		self.p_pub_gen()


	def p_q_gen( self, bits ) :
		self.p = mpz(2)**( bits - 1 ) + mpz_urandomb( rand, bits - 1 )
		while True :
			self.p = next_prime(self.p)
			self.q = f_div(self.p - 1 , 2)
			if is_prime(self.q) :
				break

	def g_gen( self ) :
		while True :
			self.g = mpz_random( rand, self.p )
			temp = powmod( self.g, self.q, self.p)
			if temp == 1 :
				break

	def p_pub_gen( self ) :
		self.s = mpz_random( rand, self.q )
		self.p_pub = powmod( self.g, self.s, self.p )
		

	def partialkey_compute( self, User ) :
		r_u, User.Y_u = random_pick( self.p, self.q, self.g )
		User.y_u = t_mod((r_u + t_mod( self.s * H1_hash(User.uid, User.X_u, User.Y_u,  bit_length(self.q)), self.q)), self.q)

class Params(object) :
	
	def __init__( self, p, q, g, p_pub ) :
		self.p = p
		self.q = q
		self.g = g
		self.p_pub = p_pub


# user key class
class User(object) :

	def __init__(self, uid, params) :
		self.uid = uid
		self.secret_compute( params.p, params.q, params.g )
		self.Y_u = None
		self.y_u = None
	
	def secret_compute( self, p, q, g ) :
	    self.x_u = mpz_random( rand, q )
	    self.X_u = powmod( g, self.x_u, p )

	# signcryption function
	def signcrypt( self, Reciever, params, m):
		#	R = g ** w mod p, w <-- Zq
		w, R_value = random_pick(params.p, params.q, params.g)
		#	h1_R = H1(ID_R, X_R, Y_R) <-- Zq
		h1_R = H1_hash(Reciever.uid, Reciever.X_u, Reciever.Y_u, bit_length(params.q))
		#	T = (X_R * Y_R * (p_pub**h1_R)) ** w mod p
		T_value = T_compute(Reciever.X_u, Reciever.Y_u, params.p_pub, h1_R, w, params.p)
		#	C = m * T mod p
		C_value = t_mod(m * T_value, params.p)
		#	h2 = H2(ID_S, T, m, C) <-- Zq
		h2_value = H2_hash(self.uid, T_value, m, C_value, bit_length(params.q))
		#	(x_S + y_S) ** -1 mod q
		x_y_invert = invert(self.x_u + self.y_u, params.q)
		#	S = h2 * w * (x_S + y_S) ** -1 mod q
		S_value = t_mod(h2_value * w * x_y_invert, params.q)
		#	signcryption_text = (R, C, S)
		Signcryption_text = (R_value, C_value, S_value)
		return Signcryption_text

	# unsigncryption function
	def unsigncrypt( self, Sender, params, Signcryption_text):
		#	get R, C, S
		R_value = Signcryption_text[0]
		C_value = Signcryption_text[1]
		S_value = Signcryption_text[2]
		#	T' = R ** (x_R + y_R) mod p	, where "un" represent the symbol '
		T_value_un = powmod(R_value, t_mod( self.x_u + self.y_u, params.q ), params.p )
		#	T' ** -1 mod p
		T_value_un_invert = invert( T_value_un, params.p )
		#	m' = (T' ** -1) * C mod p
		m_un = t_mod( T_value_un_invert * C_value, params.p )
		#	h2' = H2(ID_S, T', m', C) <-- Zq
		h2_value_un = H2_hash( Sender.uid, T_value_un, m_un, C_value, bit_length(params.q))
		#	h1_S = H1(ID_S, X_S, Y_S) <-- Zq
		h1_S = H1_hash( Sender.uid, Sender.X_u, Sender.Y_u, bit_length(params.q))
		#	verify R ** h2' mod p == (X_S * Y_S * (p_pub ** h1_S)) ** S mod p
		#	if return true, then return m' as the plain-text
		left_value = powmod(R_value, h2_value_un, params.p)
		right_value = T_compute( Sender.X_u, Sender.Y_u, params.p_pub, h1_S, S_value, params.p)
		if left_value == right_value :
			return m_un

#	randomly pick a number x_u from Zq, and get X_u from g ^ x_u mod p
def random_pick(p, q, g):
	x_u = mpz_random(rand, q)
	X_u = powmod(g, x_u, p)
	return x_u, X_u

# 	T_value compute, (x * y * (p_pub ** h1_R)) ** w mod p
def T_compute(x, y, p_pub, h1_b, w, p):
	T_temp = t_mod(x * y * powmod(p_pub, h1_b, p), p)
	T_value = powmod(T_temp, w, p)
	return T_value

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

if __name__ == "__main__":
	kgc_1 = KGC(512)
	params = Params(kgc_1.p, kgc_1.q, kgc_1.g, kgc_1.p_pub)
	Alice = User('Alice', params)
	Bob = User('Bob', params)
	kgc_1.partialkey_compute(Alice)
	kgc_1.partialkey_compute(Bob)
	m = mpz(2 ** 16)
	Signcryption_text = Alice.signcrypt( Bob, params, m )
	m_un = Bob.unsigncrypt( Alice, params, Signcryption_text )
	print(m_un)