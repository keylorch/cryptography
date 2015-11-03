import cryptok
import re 

# Paillier Exercise
# The Encrypted Votes of 1000 voters are given in the file data/paillier-exercise.txt
# The scheme used was a Paillier voting scheme.
# No voters selected 0, Yes voters Selected 1.
# Determine the result of the election  given the Paillier keys below.

# 	-Paillier public key is 1110875290280920009961998978166106038302156763 

# 	-Paillier private key phi(N) is 1110875290280920009961932304108708457006287400 

#Given Information
# PK
N = 1110875290280920009961998978166106038302156763

# SK
phi_N = 1110875290280920009961932304108708457006287400

# Precalculate the inverse of phy_N mod N,  for efficiency
inverse_phy_N = cryptok.modular_inverse(phi_N, N)

# Precalculate the second power of N, for efficiency
N_power_2 = N ** 2

# Auxiliary functions
def readVotes(filename):
	"""Reads the votes from a file (Specific to the exercise).
	
	Reads the ciphertexts of votes from a file where each line follows
	this format:
		Encrypted vote 999 is 583774516394803398092108966834984381238573894741794012923645838732245187126090513945406013 
	
	Args:
	    filename: Relative or full path of the input file.
	
	Returns:
	    A List of the votes in the file.
	"""
	result = []
	regex = re.compile('(\d+)(?!.*\d)')
	votes = open(filename, 'r')
	for line in votes:
		number = re.search(regex, line).group(0)
		result.append(int(number))
	return result

def votingResults(votes):
	"""Gets the results of an election.
	
	Gets the results of an election where the users selected 0 for no, and 1 for yes.
	It gets the amount of votes for no and yes by decrypting each of the votes.
	
	Args:
	    votes: List of the votes of the election.
	
	Returns:
	    A dictionary with the results of the election:
	    {
			"yes": 1000, 
			"no": 9999
		}
	
	Raises:
	    Type: Description.
	"""
	yes, no = 0, 0
	for vote in votes:
		value = cryptok.paillier_dec(vote, N, phi_N, N_power_2, inverse_phy_N)
		if value == 0:
			no+=1
		else:
			yes+=1
	return {
		"yes": yes, 
		"no": no
	}

# Read the votes from the files
votes = readVotes('data/paillier-exercise.txt')
L = len(votes)
print("Total votes(L): ", L)

# Get the election results without decrypting all the votes
aggregation = cryptok.paillier_aggregation(votes, N, N_power_2)
print("paillier_aggregation(votes): ", aggregation)
dec_aggregation = cryptok.paillier_dec(aggregation, N,phi_N, N_power_2, inverse_phy_N)
print("paillier_dec(aggregation): ", dec_aggregation)
if dec_aggregation > L / 2:
	print("The winner is YES")
elif dec_aggregation < L / 2:
	print("The winner is NO")
else: 
	print("TIE")

# Get the election results by decrypting each of the votes.
results = votingResults(votes)
print("results: ", results)


