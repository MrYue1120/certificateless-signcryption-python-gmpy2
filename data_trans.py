#! usr/bin/env python3
# -*- coding: utf-8 -*-

from gmpy2 import mpz, bit_length


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

# sjsjs
