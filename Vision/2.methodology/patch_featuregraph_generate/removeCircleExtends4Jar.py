import os
import re

def find_java_files(folder_path):
    java_files = []
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if file.endswith('.java'):
                java_files.append(os.path.join(root, file))
    return java_files

# def remove_extends_from_interface(file_path):
#     with open(file_path, 'r') as file:
#         lines = file.readlines()

#     modified = False
#     for i, line in enumerate(lines):
#         match_class = re.match(r'^\s*public\s+class\s+\w+\s+extends\s+\w+(\s+implements\s+(\w+\s*,\s*)*\w+\s*)?\s*{?\s*$', line)
#         match_interface = re.match(r'^\s*public\s+interface\s+\w+\s+extends\s+\w+(\s+implements\s+(\w+\s*,\s*)*\w+\s*)?\s*{?\s*$', line)
#         if match_class:
#             lines[i] = re.sub(r'extends\s+\w+(\s+implements\s+(\w+\s*,\s*)*\w+\s*)?\s*', '', line)
#             modified = True
#         elif match_interface:
#             print(match_interface)
#             lines[i] = re.sub(r'extends\s+\w+(\s+implements\s+(\w+\s*,\s*)*\w+\s*)?\s*', '', line)
#             modified = True

#     if modified:
#         with open(file_path, 'w') as file:
#             file.writelines(lines)
#         print(f"Removed 'extends' from {file_path}")

def remove_extends_from_interface(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()

    modified = False
    for i, line in enumerate(lines):
        matched = False
        if not line.startswith("public class") and not line.startswith("public interface") and not line.startswith("public final class") and not line.startswith("public abstract class"): continue
        if ("extends" not in line and "implements" not in line) or "{" not in line: continue
        if "extends" in line:
            calss_or_interface, extends_part = line.split("extends", 1)
        else:
            calss_or_interface, extends_part = line.split("implements", 1)
        # print("extends_part:", extends_part.strip().split(" ")[0].strip(","))
        # print("calss_or_interface: ", calss_or_interface.strip().split(" ")[-1])

        if " " + calss_or_interface.strip().split(" ")[-1] + " " in extends_part or " " + calss_or_interface.strip().split(" ")[-1] + "," in extends_part:
            print(line)

            if extends_part.strip().endswith("{}"):
                matched = True
                calss_or_interface += "{}\n"
                
            elif extends_part.strip().endswith("{"):
                matched = True
                calss_or_interface += "{\n"
        

        if matched:
            modified = True
            lines[i] = calss_or_interface
            print(lines[i])
            print("---------")
        # if match_class:
        #     lines[i] = re.sub(r'extends\s+\w+(\s+implements\s+(\w+\s*,\s*)*\w+\s*)?\s*', '', line)
        #     modified = True

    if modified:
        with open(file_path, 'w') as file:
            file.writelines(lines)
        print(f"Removed 'extends' from {file_path}")
        print("------------------------------------")


def process_folder(folder_path):
    java_files = find_java_files(folder_path)
    for file_path in java_files:
        remove_extends_from_interface(file_path)

if __name__ == "__main__":

    folder_path = '4.jar/jarDecompile/org.springframework.data-spring-data-rest-webmvc'
    process_folder(folder_path)