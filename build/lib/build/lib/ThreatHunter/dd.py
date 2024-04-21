import os


def scan_directory(directory_path, exclusive, verbosity):
    # rule_dir = get_rules_folder_path()
    try:
        for root, dirs, files in os.walk(directory_path):

            for file_name in files:
                file_path = os.path.join(root, file_name)
                # if yara_log_file in file_path or rule_dir in file_path:
                # continue
                print(f'\033[1;32mScanning:\033[0m{file_path}')
                if exclusive == 'OFF':
                    print("OFF")
                    # yara_detection(file_path)
                elif exclusive != 'OFF':
                    print("ON")
                    # exclusive(file_path, exclusive)
                if not verbosity:
                    print("not v")
                    # clear_screen()
                break
    except Exception as e:
        print(e)


scan_directory("/home/", "ON", True)
