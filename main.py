import sqlite3
import bcrypt
import time

# Initialize the database connection
conn = sqlite3.connect('auth_system.db')
cursor = conn.cursor()

# Create the users table
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password_hash BLOB NOT NULL,
    failed_attempts INTEGER DEFAULT 0,
    last_failed_login_time REAL DEFAULT 0
)
''')
conn.commit()

def signup():
    username = input("Enter a username: ")
    password = input("Enter a password: ")

    # Hash the password using bcrypt
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    try:
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                       (username, password_hash))
        conn.commit()
        print("User registered successfully!")
    except sqlite3.IntegrityError:
        print("Username already exists.")

def login():
    username = input("Enter your username: ")
    password = input("Enter your password: ")

    cursor.execute("SELECT password_hash, failed_attempts, last_failed_login_time FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()

    if result:
        password_hash, failed_attempts, last_failed_login_time = result

        # Rate limiting logic
        current_time = time.time()
        timeout_duration = 60  # 60 seconds timeout
        if failed_attempts >= 3 and (current_time - last_failed_login_time) < timeout_duration:
            print("Account locked due to multiple failed login attempts. Please try again later.")
            return

        if bcrypt.checkpw(password.encode('utf-8'), password_hash):
            print("Login successful!")
            # Reset failed attempts on successful login
            cursor.execute("UPDATE users SET failed_attempts = 0 WHERE username = ?", (username,))
            conn.commit()
        else:
            failed_attempts += 1
            cursor.execute("UPDATE users SET failed_attempts = ?, last_failed_login_time = ? WHERE username = ?",
                           (failed_attempts, current_time, username))
            conn.commit()
            print("Incorrect password.")
    else:
        print("Username not found.")

def main():
    while True:
        choice = input("Select an option: [1] Sign Up [2] Login [3] Exit: ")
        if choice == '1':
            signup()
        elif choice == '2':
            login()
        elif choice == '3':
            break
        else:
            print("Invalid option.")

if __name__ == "__main__":
    main()
