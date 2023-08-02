# increment_update.py
import re

# Read the content of the update.py file
with open('./update.py', 'r') as f:
    content = f.read()

# Use regular expression to find the line with the file path
pattern = r"with open\('\.\./output_files/output_(\d+)\.txt', 'r'\)"
match = re.search(pattern, content)

if match:
    current_number = int(match.group(1))  # Get the current number from the match
    new_number = current_number + 1
    updated_content = re.sub(pattern, f"with open('../output_files/output_{new_number}.txt', 'r')", content)

    # Write the updated content back to the file
    with open('./update.py', 'w') as f:
        f.write(updated_content)
else:
    print("Pattern not found in the file.")