import os
import sys
import subprocess
import time
import datetime
import yara
# import pkgutil
import inspect
from .elf import is_elf, get_elf_infor
from .pe import is_pe, get_pe_infor
from .show_progress import progress_show
import logging
import logging.handlers

logging.basicConfig(level=logging.INFO, format='%(levelname)-8s %(message)s')
logger = logging.getLogger(__name__)

# Based of the system create log file
if os.name == 'posix':
    username = os.getlogin()
    if not os.path.exists(f'/home/{username}/MDART/log/'):
        subprocess.run(['mkdir', '-p', f'/home/{username}/MDART/log/'])
    yara_log_file = f'/home/{username}/MDART/log/yara.log'
elif os.name == 'nt':
    if not os.path.exists('C:\\Users\\MDART_log'):
        subprocess.run(['mkdir', '-p', 'C:\\Users\\MDART_log'])
    yara_log_file = 'C:\\Users\\MDART\\log\\yara.log'


def get_rules_folder_path():
    package_root = MDART.__dict__.get('PACKAGE_ROOT', '')
    if package_root:
        rules_folder_path = os.path.join(package_root, 'rules')
        return rules_folder_path


# Ensure that rule file is in the appropriate path
# get current date and time
current_datetime = datetime.datetime.now()


# function to extract relevant infor from the rule file that succeeds
def extract_description_sections(yara_file):
    ref = {'description', 'Description', 'author', 'fingerprint', 'category',
           'malware', 'source', 'id', 'rule', 'reference', 'malware_type',
           'samples', 'updated_date', 'tags', 'Author', 'tc_detection_type',
           'tc_detection_name', 'tc_detection_factor', 'tool', 'mitre_att'}
    with open(yara_file, 'r') as f:
        print("\033[33m__________USED RULE INFOR__________\033[0m")
        for line in f:
            for key_word in ref:
                if line.strip().startswith(key_word):
                    print(f"\033[36m{line}\033[0m")
                    with open(log_file, 'a') as log:
                        yara_log_file.write(f'\n{line}')
                else:
                    pass


# yara detection
def yara_detection(path):
    try:
        rule_dir = get_rules_folder_path()
        for root, dirs, files in os.walk(rule_dir):
            for rule_name in files:
                print(path + 'using' + rule_name)
                time.sleep(1)
                rule_path = os.path.join(root, rule_name)
                with open(rule_path, 'r') as f:
                    rule = f.read()

                    rules = yara.compile(source=rule)

                    matches = rules.match(path)
                    if matches:
                        logger.warning(f'\033[1;31mYARA detected possible\
Malware:\033[0m at\033[35m {path}\033[0m')
                        # extract_description_sections(rule_path)
                        time.sleep(2)

                        with open(yara_log_file, 'a') as log:
                            log.write(f'{current_datetime}\n\
Yara detected Malware at: {path}\n')
                            log.write('__________USED RULE DETAILS__________')
                            log.write(
                                f'{extract_description_sections(rule_path)}\n\n')
                            time.sleep(1)
                        try:
                            # extract and log elf or pe infor if the file is \
                            # any of them use sys.stdout
                            data_dumb = os.path.dirname(
                                yara_log_file) + 'dumb.xml'
                            if is_elf(path):
                                logger.info('Get elf data..')
                                progress_show()
                                with open(data_dumb) as log:
                                    log.write(
                                        '@@@@@@@@@ELF FILE INFO @@@@@@@@@')
                                    '''
                                Define a function to write to both console
                                and file
                                '''
                                    def write_and_print(obj):
                                        sys.stdout.write(obj)
                                        log.write(obj)
                                    # Redirect stdout to the custom function
                                    sys.stdout = write_and_print
                                    # Call the target function
                                    get_elf_infor(path)
                            elif is_pe(path):
                                logger.info('Get pe data..')
                                progress_show()
                                time.sleep(5)
                                with open(data_dumb) as log:
                                    log.write(
                                        '@@@@@@@@@PE FILE INFO @@@@@@@@@')

                                    def write_and_print(obj):
                                        sys.stdout.write(obj)
                                        log.write(obj)
                                    # Redirect stdout to the custom function
                                    sys.stdout = write_and_print
                                    # Call the target function
                                    get_pe_infor(path)
                        except Exception:
                            pass
        else:
            pass
            # entry_cap(path)
    except KeyboardInterrupt as e:
        print(f'{e}\nExiting')
        time.sleep(0.01)
        sys.exit(1)
    except PermissionError as e:
        logger.error(f'{e}')
        return False, None
    except yara.Error as e:
        logger.error(f'Error: {e}')
        return False, None


def scan_directory(directory_path):
    rule_dir = get_rules_folder_path()
    print(rule_dir)
    time.sleep(15)
    try:
        for root, dirs, files in os.walk(directory_path):

            for file_name in files:
                file_path = os.path.join(root, file_name)
                if yara_log_file in file_path or rule_dir in file_path:
                    continue
                print(file_path)
                time.sleep(7)
                yara_detection(file_path)

    except Exception as e:
        logger.error({e})


def yara_entry(input_file):
    try:
        if os.path.isdir(input_file):
            scan_directory(input_file)
        elif os.path.isfile(input_file):
            yara_detection(input_file)
    except Exception:
        pass


if __name__ == '__main__':
    yara_entry('/home/user/')
