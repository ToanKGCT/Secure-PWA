import sqlite3 as sql
import time
import random
import html 
import bcrypt
#     # ^(?=.*[a-z]) - At least one lowercase letter

def insertUser(username, password, DoB, email):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()

    # Hash the password using bcrypt
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    cur.execute(
        "INSERT INTO users (username, password, dateOfBirth, email) VALUES (?, ?, ?, ?)",
        (username, hashed_password, DoB, email),
    )
    con.commit()
    con.close()


def retrieveUsers(username, password, email):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()

    # Retrieve the user record
    cur.execute(
        "SELECT * FROM users WHERE username = ? AND email = ?", (username, email)
    )
    user = cur.fetchone()

    if user:
        # Verify the hashed password
        stored_password = user[2]  # Assuming the password is in the second column
        if bcrypt.checkpw(password.encode('utf-8'), stored_password):
            # Log visitor count
            with open("visitor_log.txt", "r") as file:
                number = int(file.read().strip())
                number += 1
            with open("visitor_log.txt", "w") as file:
                file.write(str(number))
            # Simulate response time
            time.sleep(random.randint(80, 90) / 1000)
            con.close()
            return True

    con.close()
    return False


def insertFeedback(feedback, username):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    sanitized_feedback = html.escape(feedback)  # Escape harmful content
    cur.execute("INSERT INTO feedback (feedback, username) VALUES (?, ?)", (sanitized_feedback, username))
    con.commit()
    con.close()

def listFeedback():
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    data = cur.execute("SELECT * FROM feedback").fetchall()
    con.close()
    feedback_list = []
    for row in data:
        escaped_feedback = html.escape(row[1])  # Escape feedback content
        feedback_list.append(escaped_feedback)
    return feedback_list

def save_2fa_secret(username, secret):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    # Properly quote the column name "2fa_secret"
    cur.execute('UPDATE users SET "2fa_secret" = ? WHERE username = ?', (secret, username))
    con.commit()
    con.close()

def isUserExists(username, email):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    # Check if the username or email exists
    cur.execute("SELECT * FROM users WHERE username = ? OR email = ?", (username, email))
    user = cur.fetchone()
    con.close()
    return user is not None

def save_2fa_secret(username, secret):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    # Properly quote the column name "2fa_secret"
    cur.execute('UPDATE users SET "2fa_secret" = ? WHERE username = ?', (secret, username))
    con.commit()
    con.close()

def get_2fa_secret(username):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    # Properly quote the column name "2fa_secret"
    cur.execute('SELECT "2fa_secret" FROM users WHERE username = ?', (username,))
    result = cur.fetchone()
    con.close()
    return result[0] if result else None

