import os
import random
import string
import sqlite3

DB_FILE = "combinations.db"

def create_database():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS combinations (combination TEXT PRIMARY KEY)''')
    conn.commit()
    conn.close()

def get_existing_combinations():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''SELECT combination FROM combinations''')
    existing_combinations = set([row[0] for row in c.fetchall()])
    conn.close()
    return existing_combinations

def insert_combinations(combination_list):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.executemany("INSERT INTO combinations (combination) VALUES (?)", [(c,) for c in combination_list])
    conn.commit()
    conn.close()

def generate_combinations(chunk_size, existing_combinations):
    characters = "abcdef0123456789"
    dashes = [8, 13, 18, 23]

    while True:
        combinations = []
        while len(combinations) < chunk_size:
            combination = ''.join(random.choices(characters, k=32))
            for pos in dashes:
                combination = combination[:pos] + '-' + combination[pos:]

            if combination not in existing_combinations:
                combinations.append(combination)

        yield combinations

def write_to_files(combinations_per_file, chunk_size):
    create_database()
    existing_combinations = get_existing_combinations()

    if not os.path.exists('output_files'):
        os.makedirs('output_files')

    file_number = 1
    for combinations in generate_combinations(chunk_size, existing_combinations):
        if not combinations:
            break

        filename = f"output_files/output_{file_number}.txt"
        with open(filename, 'w') as file:
            for combination in combinations:
                file.write(combination + '\n')

        insert_combinations(combinations)
        file_number += 1

if __name__ == "__main__":
    combinations_per_file = 750000
    chunk_size = 750000  # Adjust this value based on your system's memory capacity
    write_to_files(combinations_per_file, chunk_size)