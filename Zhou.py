#! usr/bin/env python3
# -*- coding: utf-8 -*-

from gmpy2 import mpz, is_prime, random_state, mpz_urandomb, mpz_random, powmod, bit_length, mul, invert, t_mod, next_prime, f_div
import random
import sys
import hashlib

rand = random_state(random.randrange(sys.maxsize))

class KGC_ZHOU( object ) :

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

class Params_ZHOU( object ) :
	
	def __init__( self, p, q, g, p_pub ) :
		self.p = p
		self.q = q
		self.g = g
		self.p_pub = p_pub

# user key class
class User_ZHOU( object ) :

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
		#	V = (X_R * Y_R * (p_pub**h1_R)) ** w mod p
		V_value = V_compute(Reciever.X_u, Reciever.Y_u, params.p_pub, h1_R, w, params.p)
		#	h3 = H3(V) <-- Zq
		h3_value = H3_hash( V_value, bit_length( params.p ))
		#	d = H4(ID_S, m, X_S, R) <-- Zq
		d_value = H4_hash(self.uid, m, self.X_u, R_value, bit_length(params.q))
		#	f = H4(ID_S, m, Y_S, R) <-- Zq
		f_value = H4_hash(self.uid, m, self.Y_u, R_value, bit_length(params.q))
		#	U = d * (x_a + y_a) + w * f mod q
		U_value = t_mod((d_value * (self.x_u + self.y_u) + w * f_value), params.q)
		#	m || U
		m_u_value = data_format_bind(m, U_value, bit_length(params.q))
		#	C = H3(V) (+) m || U
		C_value = h3_value ^ m_u_value
		#	h2 = H2(ID_a, R, C) <-- Zq
		h2_value =  H2_hash(self.uid, R_value, C_value, bit_length(params.q))
		#	S = w * ((x_a + y_a +h2) ** -1) mod q
		x_y_h_invert = invert(self.x_u + self.y_u + h2_value, params.q)
		S_value = t_mod(w * x_y_h_invert, params.q)
		#	signcryption_text = (h2, S, C)
		Signcryption_text = (h2_value, S_value, C_value)
		return Signcryption_text

	# unsigncryption function
	def unsigncrypt( self, Sender, params, Signcryption_text):
		#	get h2, S, C
		h2_value = Signcryption_text[0]
		S_value = Signcryption_text[1]
		C_value = Signcryption_text[2]
		#	h1_S = H1(ID_S, X_S, Y_S) <-- Zq
		h1_S = H1_hash(Sender.uid, Sender.X_u, Sender.Y_u, bit_length(params.q))
		#	R' = (X_S * Y_S * (p_pub**h1_S) * (g ** h2)) ** w mod p, un represent '
		temp = powmod(params.g, h2_value, params.p)
		temp = t_mod(temp * Sender.Y_u, params.p)
		R_value_un = V_compute(Sender.X_u, temp, params.p_pub, h1_S, S_value, params.p)
		#	V' = R' ** (x_b + y_b) mod q
		V_value_un = powmod(R_value_un, t_mod(self.x_u + self.y_u, params.q), params.p)
		#	h3 = H3(V') <-- Zp
		h3_value = H3_hash(V_value_un, bit_length(params.p))
		#	m || U = C (+) h3
		m_u_value_un = C_value ^ h3_value
		#	get m'
		m_un = m_u_value_un >> bit_length(params.q)
		#	get U'
		U_value_un = (m_un << bit_length(params.q)) ^ m_u_value_un
		#	d' = H4(ID_a, m', X_a, R) <-- Zq
		d_value_un = H4_hash(Sender.uid, m_un, Sender.X_u, R_value_un, bit_length(params.q))
		#	f' = H4(ID_a, m', Y_a, R) <-- Zq
		f_value_un = H4_hash(Sender.uid, m_un, Sender.Y_u, R_value_un, bit_length(params.q))
		#	verify g ** U' == ((X_a * Y_a * (p_pub ** h1_a)) ** d') * (R' ** f') mod p
		#	if return true, then return m'; else return None
		left_value = powmod(params.g, U_value_un, params.p)
		temp1 = V_compute(Sender.X_u, Sender.Y_u, params.p_pub, h1_S, d_value_un, params.p)
		temp2 = powmod(R_value_un, f_value_un, params.p)
		right_value = t_mod(temp1 * temp2, params.p)
		if left_value == right_value :
			return m_un
		
#	randomly pick a number x_u from Zq, and get X_u from g ^ x_u mod p
def random_pick(p, q, g):
	x_u = mpz_random(rand, q)
	X_u = powmod(g, x_u, p)
	return x_u, X_u

# 	V_value compute, (x * y * (p_pub ** h1_b)) ** w mod p
def V_compute(x, y, p_pub, h1_b, w, p):
	V_temp = t_mod(x * y * powmod(p_pub, h1_b, p), p)
	V_value = powmod(V_temp, w, p)
	return V_value

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
def H1_hash( uid, x, y, bits ):
	temp = hash_func(uid.encode('utf-8') + str(x).encode('utf-8') + str(y).encode('utf-8'))
	H1_hash_value = mpz(temp[ : bits - 2], 16)
	return H1_hash_value

# define the H2 hashfunction	
def H2_hash( uid, x, y, bits ):
	temp = hash_func(uid.encode('utf-8') + str(x).encode('utf-8') + str(y).encode('utf-8'))
	H2_hash_value = mpz(temp[ : bits - 2], 16)
	return H2_hash_value


# define the H3 hashfunction
def H3_hash( x, bits ):
	temp = hash_func(str(x).encode('utf-8'))
	H3_hash_value = mpz(temp[ : bits - 2], 16)
	return H3_hash_value

# define the H4 hashfunction
def H4_hash( uid, x, y, z, bits ):
	temp = hash_func(uid.encode('utf-8') + str(x).encode('utf-8') + str(y).encode('utf-8') + str(z).encode('utf-8'))
	H4_hash_value = mpz(temp[ : bits - 2], 16)
	return H4_hash_value

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


if __name__ == "__main__":
	kgc_zhou_1 = KGC_ZHOU(512)
	params = Params_ZHOU(kgc_zhou_1.p, kgc_zhou_1.q, kgc_zhou_1.g, kgc_zhou_1.p_pub)
	Alice = User_ZHOU('Alice', params)
	Bob = User_ZHOU('Bob', params)
	kgc_zhou_1.partialkey_compute(Alice)
	kgc_zhou_1.partialkey_compute(Bob)
	m = mpz(2 ** 16)
	Signcryption_text = Alice.signcrypt( Bob, params, m )
	m_un = Bob.unsigncrypt( Alice, params, Signcryption_text )
	print(m_un)