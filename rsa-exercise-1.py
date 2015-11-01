import cryptok
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

x = cryptok.crt(a_tuple, m_tuple)
print("x: ", x)

# Test if x < n1 * n2 * 3
print("x < n1 * n2 * 3: ", x < n1 * n2 * n3)

# Given that it is true, then we can say: 
# m^3 mod n1n2n3 = m^3, which means icuberoot(m^3) = m. 

m = cryptok.iroot(3, x)
print("m: ", m)

# We get the password
password = cryptok.get_ascii_from_number(m)
print("password: ", password)




