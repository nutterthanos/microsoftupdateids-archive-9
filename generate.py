import os
import random
import string

def generate_combinations(chunk_size):
    characters = string.ascii_lowercase + string.digits
    dashes = [8, 13, 18, 23]

    while True:
        combinations = []
        for _ in range(chunk_size):
            combination = ''.join(random.choices(characters, k=32))
            for pos in dashes:
                combination = combination[:pos] + '-' + combination[pos:]
            combinations.append(combination)

        yield combinations

def write_to_files(combinations_per_file, chunk_size):
    if not os.path.exists('output_files'):
        os.makedirs('output_files')

    file_number = 1
    for combinations in generate_combinations(chunk_size):
        if not combinations:
            break

        filename = f"output_files/output_{file_number}.txt"
        with open(filename, 'w') as file:
            for combination in combinations:
                file.write(combination + '\n')

        file_number += 1

if __name__ == "__main__":
    combinations_per_file = 750000
    chunk_size = 750000  # Adjust this value based on your system's memory capacity
    write_to_files(combinations_per_file, chunk_size)