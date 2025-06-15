import mysql.connector
from argon2 import PasswordHasher

def verify_password(username, password):
    try:
        # Connect to MySQL database
        connection = mysql.connector.connect(
            host="localhost",
            user="root",
            password="Hla@013",
            database="academia"
        )

        # Create cursor
        cursor = connection.cursor()

        # Retrieve the hashed password from the database based on the username
        query = "SELECT UserPasswordKey FROM MIITUsers WHERE Email = %s"
        cursor.execute(query, (username,))
        result = cursor.fetchone()

        if result:
            hashed_password = result[0]
            # Initialize a PasswordHasher object
            ph = PasswordHasher(time_cost=4, memory_cost=65536)
            # Verify the password hash
            if ph.verify(hashed_password, password):
                # Password verification successful
                return True
            else:
                # Password is incorrect
                return False
        else:
            # User not found
            return False
    except mysql.connector.Error as e:
        print("Error connecting to MySQL:", e)
        return False
    except Exception as e:
        print("Error:", e)
        return False
    finally:
        # Close database connection
        if connection.is_connected():
            cursor.close()
            connection.close()

# Example usage:
username = "2022-miit-cse-001@miit.edu.mm"  # Replace with the user's email
password = "Thanks123!"  # Replace with the user's password

if verify_password(username, password):
    print("Password is correct")
else:
    print("Password is incorrect")