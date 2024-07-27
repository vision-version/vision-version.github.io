import os

def contains_chinese(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
            if re.search('[\u4e00-\u9fff]', content):
                return True
    except:
        # Ignore files that can't be read
        return False
    return False

def find_files_with_chinese(directory):
    files_with_chinese = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            if contains_chinese(file_path):
                files_with_chinese.append(file_path)
    return files_with_chinese

# Specify the target directory
target_directory = os.getcwd()  # Change this to the target directory if needed

files_with_chinese = find_files_with_chinese(target_directory)
files_with_chinese