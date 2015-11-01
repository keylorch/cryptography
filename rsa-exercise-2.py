import cryptok
# Question #2
# Consider the following two RSA public keys 
# (n,e1) and (n,e2). They have been used to encrypt a password made up of four two digit ascii reperesentations to produce ciphertexts c1 and c2 respectively. Recover the password.

# n	77521140191618283780613386239788963215636521877030830245331440024401877894874823258255306962045408180421212221275845885954524130707050376947871888757048175649167751632069031329578526737098714531024187640689621015617255307596010654794518332048429841176596675399659563247476996366152248319716835481860843847055537749352498685794750086157653365404597261149152079186366401321119425525552101
# e1	399
# c1	7536673143565776736851252766385753521577419436650852536394344162715356115698762081228368138204072962985082961552894864333610499136686606591910432873331291668739875767220409064627576671914948912999248186261197026899521412762068663451535780909400953320044733652966295421510642941974997744159108847884810721550623459027543645248469463621430821533276914761012565639407615635164613751132239
# n	77521140191618283780613386239788963215636521877030830245331440024401877894874823258255306962045408180421212221275845885954524130707050376947871888757048175649167751632069031329578526737098714531024187640689621015617255307596010654794518332048429841176596675399659563247476996366152248319716835481860843847055537749352498685794750086157653365404597261149152079186366401321119425525552101
# e2	10007
# c2	34769528697321331665191012050496178932951805361555671066485334100903420952829004252656220997571380831700306275885784476779277824820310442607604219134233233062805173736521509115590453629007478551003956032206533499843468309249240298738580633828384585826624413025113558480363158304120635239296998267764449961976578139750273930111547703234975219887601372042727135973836220023715045262455984

#Solution 
# Information given
n = 77521140191618283780613386239788963215636521877030830245331440024401877894874823258255306962045408180421212221275845885954524130707050376947871888757048175649167751632069031329578526737098714531024187640689621015617255307596010654794518332048429841176596675399659563247476996366152248319716835481860843847055537749352498685794750086157653365404597261149152079186366401321119425525552101

e1 = 399
c1 = 7536673143565776736851252766385753521577419436650852536394344162715356115698762081228368138204072962985082961552894864333610499136686606591910432873331291668739875767220409064627576671914948912999248186261197026899521412762068663451535780909400953320044733652966295421510642941974997744159108847884810721550623459027543645248469463621430821533276914761012565639407615635164613751132239

e2 = 10007
c2 = 34769528697321331665191012050496178932951805361555671066485334100903420952829004252656220997571380831700306275885784476779277824820310442607604219134233233062805173736521509115590453629007478551003956032206533499843468309249240298738580633828384585826624413025113558480363158304120635239296998267764449961976578139750273930111547703234975219887601372042727135973836220023715045262455984

# Check if e1 and e2 are relatively prime
gcd_e1_e2 = cryptok.gcd(e1, e2)
print("gcd_e1_e2 == 1: ", gcd_e1_e2 == 1)

# Since they are, we can find h, k such that he1 + ke2 = 1
# We use the extended algorithm for that. 
gcd, h, k = cryptok.egcd(e1, e2)
print("gcd: ", gcd)
print("h: ", h)
print("k: ", k)

# Test if correct
print("h*e1+k*e2 == 1: ", h*e1+k*e2 == 1)

# We can now say that 
# m = m^1 = m^(h*e1 + k*e2) mod n
# 		= (m^e1)^h * (m^e2)^k mod n
# 		= c1^h * c2^k  mod n ...and we have that :)

# But, since k is negative: 
# c2^k mod n = (c2^-1)^|k|. Lets find the inverse
c2_inv = cryptok.modular_inverse(c2, n)
print("c2_inv: ", c2_inv)
k = abs(k) # and we can use the absolute value of k now

# So, m = c1 ** h + c2_inv ** k mod n

# Sadly, this overflows using the power operator, so we need to apply fast exponentiation
# m = c1 ** h * c2 ** k mod n
# m = ((c1 ** h) mod n) * (c2 ** k) mod n) mod n

c1_power_h_mod_n = cryptok.fast_exp(c1, h, n)
c2_power_k_mod_n = cryptok.fast_exp(c2_inv, k, n)

print("fast_exp(c1, h, n): ", c1_power_h_mod_n)
print("fast_exp(c2_inv, k, n): ", c2_power_k_mod_n)

m = (c1_power_h_mod_n * c2_power_k_mod_n) % n
print("m: ", m)

# We get the password
password = cryptok.get_ascii_from_number(m)
print("password: ", password)