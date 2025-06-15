from argon2 import PasswordHasher

# Define the default password and salt
password = 'Thanks123!'
salt = b'MIITUsersSalt'

# Initialize a PasswordHasher object with increased time and memory costs
ph = PasswordHasher(time_cost=4, memory_cost=65536)

# Generate the Argon2 hash with the provided salt, time cost, and memory cost
hashed_password = ph.hash(password, salt=salt)

print("Hashed Password:", hashed_password)
