import os
import sys
import time
import datetime
import yara
from .elf import is_elf, get_elf_infor
from .pe import is_pe, get_pe_infor
from .show_progress import progress_show
import logging
import logging.handlers

logging.basicConfig(level=logging.INFO, format='%(levelname)-8s %(message)s')
logger = logging.getLogger(__name__)

log_file = '/home/user/MDART/log/yara.log'
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
                    log_file = '/home/user/MDART/log/yara.log'
                    with open(log_file, 'a') as log:
                        log.write(f'\n{line}')
                else:
                    pass


# yara detection
def yara_detection(path):
    try:
        rule_dir = '/home/user/MDART/rules/'
        for root, dirs, files in os.walk(rule_dir):
            for rule_name in files:
                rule_path = os.path.join(root, rule_name)
                # print(f'rule {rule_path} on {path}')
                # time.sleep(0.5)
                with open(rule_path, 'r') as f:
                    rule = f.read()

                    rules = yara.compile(source=rule)

                    matches = rules.match(path)
                    if matches:
                        logger.warning(f'\033[31mYARA detected possible\
Malware:\033[0m at\033[35m {path}\033[0m')
                        # extract_description_sections(rule_path)
                        time.sleep(2)

                        with open(log_file, 'a') as log:
                            log.write(f'{current_datetime}\n\
Yara detected Malware at: {path}\n')
                            log.write('__________USED RULE DETAILS__________')
                            log.write(
                                f'{extract_description_sections(rule_path)}\n\n')
                            time.sleep(1)
                        try:
                            # extract and log elf or pe infor if the file is \
                            # any of them
                            data_dumb = '/home/user/MDART/dumb/dumb.xml'
                            if is_elf(path):
                                logger.info('Get elf data..')
                                progress_show()
                                get_elf_infor(path)
                                time.sleep(5)
                                with open(data_dumb) as log:
                                    log.write(
                                        '@@@@@@@@@ELF FILE INFO @@@@@@@@@')
                                    log.write(get_elf_infor(path))
                            elif is_pe(path):
                                logger.info('Get pe data..')
                                progress_show()
                                get_infor(path)
                                time.sleep(5)
                                with open(data_dumb) as log:
                                    log.write(
                                        '@@@@@@@@@PE FILE INFO @@@@@@@@@')
                                    log.write(get_elf_infor(path))
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
    log_path = '/home/user/MDART/log/'
    rule_dir = '/home/user/MDART/rules/'
    try:
        for root, dirs, files in os.walk(directory_path):

            for file_name in files:
                file_path = os.path.join(root, file_name)
                if log_path in file_path or rule_dir in file_path:
                    continue
                print(file_path)
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
    yara_entry('/home/user/MDART/malware/desquirr.plw')
