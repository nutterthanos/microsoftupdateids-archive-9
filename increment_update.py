# increment_update.py

# Read the current number from the file
with open('./update.py', 'r') as f:
    content = f.read()
    current_number = int(content.strip().split('_')[-1])

# Increment the number
new_number = current_number + 1

# Update the filename in the content
updated_content = content.replace(f'output_{current_number}', f'output_{new_number}')

# Write the updated content back to the file
with open('./update.py', 'w') as f:
    f.write(updated_content)