# Question #1
# Consider the following situation.
# You have obtained the following information from a password distribution centre that
# has just sent out a password in the form of a number made up of eight two digit ASCII 
# representation of uppercase letters. 
# The password was sent to three recipients
# Each recipient is using unpadded RSA with public key values of 3 but different n values
# The three (ciphertext, n) pairs are,
# (1338853906351615603845328037909, 4963703553974661181865803149931)
# (742171294423584777417515756208, 2112487534646562115950045691561)
# (1364412949550017047575133658763, 3655661175938877172141578380053)
# Recover the password without factoring any of the n values.

# Solution
# This exercise represents the problem where a small group of clients are sharing
# the same small public key but different n values, and they are transmitting the same 
# message (the password)
# See http://cacr.uwaterloo.ca/hac/ 
# Page 7: http://cacr.uwaterloo.ca/hac/about/chap8.pdf 

#GCD
def gcd(number1, number2):
	"""Calculates the greatest common divisor of two integers.
	
	Uses the Euclidean algorithm in order to find the GCD of
	two numbers.
	
	Returns:
	    The GCD.
	"""
	if number2 == 0:
		return number1
	else:
		return gcd(number2, number1 % number2)

def egcd(number1, number2):
	"""Extended Euclidean Algorithm.
	
	Uses the Extended Euclidean Algorithm to find the GCD of two numbers
	and the the coefficients of Bézout's identity 
	(https://en.wikipedia.org/wiki/B%C3%A9zout%27s_identity)
	
	Returns:
	    A tuple with the CGD and the coefficients.
	    (gcd, coefficient_s, coefficient_t)
	"""
	s, old_s = 0, 1
	t, old_t = 1, 0
	r, old_r = number2, number1
	while r != 0:
		quotient = old_r // r
		old_r, r = r, old_r - quotient * r
		old_s, s = s, old_s - quotient * s
		old_t, t = t, old_t - quotient * t
	return (old_r, old_s, old_t)

def modular_inverse(number, modulo):
	"""Gets the inverse of number mod modulo.
	
	Uses the Extended Euclidean Algorithm to get the modular inverse
	of a number.
	
	Args:
	    number: number to find the inverse.
	    modulo: modulo in which to find the inverse
	
	Returns:
	    The modular inverse of number mod modulo.
	
	Raises:
	    Exception: If the modular inverse doesn't exists (number and modulo
	    		   are not coprime.
	"""
    gcd, x, y = egcd(number, modulo)
    if gcd != 1:
        raise Exception('Modular inverse doesn''t exists')
    else:
    	t = x % modulo
    	if (t < 0):
    		t = t + modulo
    	return t

def get_ascii_from_number(number):
	"""Gets an ascii word given a integer number.
	
	Gets the ascii representation of a number where each 
	two diggits represent an ascii letter. For example: 
	909090 represents ZZZ.
	
	Args:
	    number: Integer representation of the word.
	
	Returns:
	    The string represented by number.
	"""
	ascii_string = []
	while number > 0:
		mchar = number % 100
		ascii_string.insert(0, chr(mchar))
		number = number // 100
	return ''.join(ascii_string)

# Finds the integer k root of n
def iroot(k, n):
	"""Calculates the integer k root of n.
	
	Args:
	    k: k root that is desired.
	    n: number to calculate the k root
	"""
    u, s = n, n+1
    while u < s:
        s = u
        t = (k-1) * s + n // pow(s, k-1)
        u = t // k
    return s

def crt(a_tuple, m_tuple):
	"""Chinese Reminder Theorem to find x, given partial information about it: .

	Uses the chinese reminder theorem to find x, given that:
		x = a1 mod m1
		x = a2 mod m2
		... 
		x = an mod mn
	
	Args:
	    a_tuple: Tuple of size n representing (a1, a2, ..., an).
	    m_tuple: Tuple of size m representing (m1, m2, ..., mn).
	
	Returns:
	    The value of X.
	
	Raises:
	    Exception: If a_tuple and m_tuple are not tuples of the same size.
	    Exception: If it is not possible to find X due to numbers not being coprime
	"""
	if (not isinstance(a_tuple, tuple) or 
		not isinstance(m_tuple, tuple) or 
		len(a_tuple) != len(m_tuple)):
		raise Exception("a and m should have the same size")
	# Find M
	M = 1
	for m in m_tuple:
		M *= m
	# Find x
	x = 0
	for index, a in enumerate(a_tuple):
		M_index = M // m_tuple[index]
		N_index = modular_inverse(M_index, m_tuple[index])
		x += a * N_index * M_index
	return x % M

# Given Information:

# PK = 3
e = 3

# ciphertexts
c1 = 1338853906351615603845328037909
c2 = 742171294423584777417515756208
c3 = 1364412949550017047575133658763

# N values
n1 = 4963703553974661181865803149931
n2 = 2112487534646562115950045691561
n3 = 3655661175938877172141578380053 

# We now have: 
# c1 = m^3 mod n1
# c2 = m^3 mod n2
# c3 = m^3 mod n3

# Let x = m^3
# x = c1 mod n1
# x = c2 mod n2 
# x = c3 mod n3
# We can use the CRT to find X

a_tuple = (c1, c2, c3)
m_tuple = (n1, n2, n3)

x = crt(a_tuple, m_tuple)
print("x: ", x)

# Test if x < n1 * n2 * 3
print("x < n1 * n2 * 3: ", x < n1 * n2 * n3)

# Given that it is true, then we can say: 
# m^3 mod n1n2n3 = m^3, which means icuberoot(m^3) = m. 

m = iroot(3, x)
print("m: ", m)

# We get the password
password = get_ascii_from_number(m)
print("password: ", password)




