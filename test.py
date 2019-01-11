#! usr/bin/env python3
# -*- coding: utf-8 -*-

import my_scheme_function as my
import zhou_scheme_function as zhou
from gmpy2 import mpz
from my_scheme_function import system_params, user_key, timing
import time

test_time1 = time.time()

def test(f, bits, times):
	t_sc = timing(f.signcrypt, 1)
	t_unsc = timing(f.unsigncrypt, 1)
	clocktime_sum = 0
	m_list = []
	sc_list = []
	unsc_list = []
	for x in range(times) :
		m_list.append(mpz(2 ** (x * 10 + 1)))
	params = system_params(bits)
	Alice = user_key("Alice", params)
	Bob = user_key("Bob", params)
	for m in m_list :
		signcryption_text, clocktime = t_sc(Alice, Bob, params, m)
		sc_list.append(signcryption_text)
		clocktime_sum += clocktime
		m_un, clocktime = t_unsc(Alice, Bob, params, signcryption_text)
		unsc_list.append(m_un)
		clocktime_sum += clocktime
	return clocktime_sum * 1000

t1 = test(my, 1024, 2)
t2 = test(zhou, 1024, 2)
test_time2 = time.time()
t3 = test_time2 - test_time1
print(t1)
print(t2)
print(t3)
