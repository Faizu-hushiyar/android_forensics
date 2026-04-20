import sqlite3

conn = sqlite3.connect("secops.sqlite3")
cursor = conn.cursor()

cursor.execute("SELECT * FROM users")
print(cursor.fetchall())

conn.close()
