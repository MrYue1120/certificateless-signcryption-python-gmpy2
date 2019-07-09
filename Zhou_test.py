#! usr/bin/env python3
# -*- coding: utf-8 -*-

from Zhou import *
from gmpy2 import mpz
from TimeCount import timing
import time

test_time1 = time.time()

#       KGC generates params
kgc_1 = KGC_ZHOU( 128 )
params = Params_ZHOU( kgc_1.p, kgc_1.q, kgc_1.g, kgc_1.p_pub )
Alice = User_ZHOU( 'Alice', params )
Bob = User_ZHOU( 'Bob', params )
kgc_1.partialkey_compute( Alice )
kgc_1.partialkey_compute( Bob )



def test( bits, times ):
	t_sc = timing( Alice.signcrypt, 1 )
	t_unsc = timing( Bob.unsigncrypt, 1 )
	clocktime_sum = 0
	m_list = []
	sc_list = []
	unsc_list = []
	for x in range(times) :
		m_list.append( mpz_urandomb( rand, bits - 1 ) )
	for m in m_list :
		Signcryption_text, clocktime = t_sc( Bob, params, m )
		sc_list.append( Signcryption_text )
		clocktime_sum += clocktime
		m_un, clocktime = t_unsc(Alice, params, Signcryption_text)
		unsc_list.append( m_un )
		clocktime_sum += clocktime
	return clocktime_sum * 1000

if __name__ == "__main__":
	t1 = test( 4096, 1000 )
	test_time2 = time.time()
	t2 = test_time2 - test_time1
	print( t1 )
	print( t2 * 1000 )
