import os
import sys
import subprocess
import time
import datetime
import yara
import importlib.resources as impres
from .elf import is_elf, get_elf_infor
from .pe import is_pe, get_pe_infor
from .show_progress import progress_show
from .overwrite import clear_screen
from . import date__time
import logging
import logging.handlers
from .colors import (RED, DRED, RESET, BLUE, DBLUE, YELLOW, DYELLOW, GREEN, DGREEN, BWHITE, CYAN, DCYAN, MAGENTA, DMAGENTA, FMAGENTA)

logging.basicConfig(level=logging.INFO, format='%(levelname)-8s %(message)s')
logger = logging.getLogger(__name__)

# Based of the system create log file
try:
    if os.name == 'posix':
        username = os.getlogin()
        if not os.path.exists(f'/home/{username}/.ThreatHunter/log/'):
            subprocess.run(['mkdir', '-p', f'/home/{username}/.ThreatHunter/log/'])
        yara_log_file = f'/home/{username}/.ThreatHunter/log/yara.log'
    elif os.name == 'nt':
        if not os.path.exists('C:\\Users\\ThreatHunter_log'):
            subprocess.run(['mkdir', '-p', 'C:\\Users\\ThreatHunter_log'])
        yara_log_file = 'C:\\Users\\ThreatHunter\\log\\yara.log'
except PermissionError as e:
    print(f"{RED}{e}{RESET}")


# To obtain resources ie rules
def get_rules_folder_path():
    rules_folder = impres.files('ThreatHunter').joinpath('rules')
    return str(rules_folder)


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
        print(f"{YELLOW}__________USED RULE INFOR__________{RESET}")
        for line in f:
            for key_word in ref:
                if line.strip().startswith(key_word):
                    print(f"{CYAN}{line}{RESET}")
                    with open(yara_log_file, 'a') as log:
                        log.write(f'\n{line}')
                else:
                    pass


# yara detection
def yara_detection(path, exclusive_rule=''):
    try:
        rule_dir = get_rules_folder_path()
        for root, dirs, files in os.walk(rule_dir):
            for rule_name in files:
                rule_path = os.path.join(root, rule_name)
                with open(rule_path, 'r') as f:
                    rule = f.read()

                    rules = yara.compile(source=rule)
                    matches = rules.match(path)
                    if matches:
                        logger.warning(f'{DRED}YARA detected possible\
Malware:{RESET} at{FMAGENTA} {path}{RESET}')
                        # extract_description_sections(rule_path)
                        time.sleep(2)

                        with open(yara_log_file, 'a') as log:
                            log.write(f'{date__time.get_date_time}\n\
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


def scan_directory(directory_path, verbosity=True):
    rule_dir = get_rules_folder_path()

    try:
        num_file = []
        for root, dirs, files in os.walk(directory_path):
            for fname in files:
                num_file.append(fname)
        for root, dirs, files in os.walk(directory_path):
            print(f'{BWHITE}Scan {CYAN}{len(num_file)} {RESET}files')
            for file_name in files:
                file_path = os.path.join(root, file_name)
                if yara_log_file in file_path or rule_dir in file_path:
                    continue
                print(f'{DGREEN}Scanning:{RESET}{file_path}')
                yara_detection(file_path)
                if verbosity:
                    clear_screen()

    except Exception as e:
        logger.error(e, exc_info=1, stack_info=True)


def yara_entry(input_file, verbosity=False):
    rule_dir = get_rules_folder_path()
    num_rf = []
    for root, dirs, files in os.walk(rule_dir):
        for file in files:
            num_rf.append(file)

    print(f"Rule files = {DBLUE}{len(num_rf)}{RESET}")
    try:

        if os.path.isdir(input_file):
            if verbosity:
                print(F'Verbose mode {YELLOW}ON{RESET}')
                scan_directory(input_file, False)

            else:
                print(F'Verbose mode {YELLOW}OFF{RESET}')
                scan_directory(input_file, True)

        elif os.path.isfile(input_file):
            print(f'{DGREEN}Scan:{CYAN} 1{RESET} file ->{input_file}')
            yara_detection(input_file)
    except Exception:
        pass


def evalp(path, rule, verbose=True):
    def exmatch(path, rule):
        if os.path.isfile(rule):
            print(f"{DBLUE}1{rule}{RESET} rule file to use")
            rule = rule
        elif os.path.isdir(rule):
            rule_list = walk_rule_dir(rule)
            num_rf = len(rule_list)
            print(f"{DBLUE}{num_rf}{RESET} rule files to use")
            for file in rule_list:
                rule = file
        with open(rule, 'r') as f:
            rule = f.read()
            rules = yara.compile(source=rule)
            matches = rules.match(path)
            if matches:
                print(F"\033[1;92mMAtch found{RESET}")
            else:
                print(F"\033[91mNo match found{RESET}")
                sys.exit(0)

    def walk_rule_dir(path):
        # print_once = False
        rule_list = []
        for root, dirs, files in os.walk(path):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                rule_list.append(file_path)
        return rule_list

    if os.path.isfile(path):
        exmatch(path, rule)
        print(f'{DGREEN}Scanning:{path}{RESET}')
    if os.path.isdir(path):

        # Count number of files to scan
        num_file = []
        for _root, _dirs, _files in os.walk(path):
            for _file in _files:
                num_file.append(_file)

        for root, dirs, files in os.walk(path):
            print(f'{DGREEN}Scan {CYAN}{len(num_file)} {RESET}files', end='\r')
            for file_name in files:
                file_path = os.path.join(root, file_name)
                print(f'\n{YELLOW}{path}{RESET}', end='\r')
                exmatch(file_path, rule)
                if not verbose:
                    clear_screen()
            break


if __name__ == '__main__':
    get_rules_folder_path()
    yara_entry('/home/skye/Documents/Ego and Pride.doc')
