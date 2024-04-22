import os
import sys
import subprocess
import time
import capstone
import logging
import logging.handlers
import importlib.resources as impres
from .elf import is_elf, get_elf_infor
from .pe import is_pe, get_pe_infor
from .overwrite import clear_screen
from .date__time import get_date_time
from .show_progress import progress_show


logging.basicConfig(level=logging.INFO, format='%(levelname)-8s %(message)s')
logger = logging.getLogger(__name__)


# To obtain resources ie rules
def get_rules_folder_path():
    rules_folder = impres.files('MDART').joinpath('rules')
    return str(rules_folder)


# Based of the system create log file
if os.name == 'posix':
    username = os.getlogin()
    if not os.path.exists(f'/home/{username}/MDART/log/'):
        subprocess.run(['mkdir', '-p', f'/home/{username}/MDART/log/'])
    log_file = f'/home/{username}/MDART/log/capstone.log'
elif os.name == 'nt':
    if not os.path.exists('C:\\Users\\MDART_log'):
        subprocess.run(['mkdir', '-p', 'C:\\Users\\MDART_log'])
    log_file = 'C:\\Users\\MDART\\log\\capstone.log'

# capstone detection


def capstone_detection(path):
    try:
        with open(path, 'rb') as f:
            data = f.read()

        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        for i in md.disasm(data, 0):
            if i.mnemonic == 'int3' or i.mnemonic == 'int1':

                logger.warning(f'\033[31mCapstone detected Malware at:\
{path}\033[0m:')
                time.sleep(1)
                with open(log_file, 'a') as log:
                    log.write(f'\n{get_date_time()}\n Capstone detected \
Malware at {path}')
                try:
                    # extract and log elf or pe infor if the file is \
                    # any of them use sys.stdout
                    data_dumb = os.path.dirname(
                        log_file) + 'dumb.xml'
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
            # print('\033[34mCapstone detected no malware')
    except KeyboardInterrupt as e:
        print(f'{e}\nExiting')
        time.sleep(0.01)
        sys.exit(1)
    except PermissionError as e:
        logger.error(f'{e}')
        return False
    except Exception as e:
        logger.error({e})


def scan_directory(directory_path, verbosity=True):
    rule_dir = get_rules_folder_path()
    try:
        for root, dirs, files in os.walk(directory_path):

            for file_name in files:
                file_path = os.path.join(root, file_name)
                if log_file in file_path or rule_dir in file_path:
                    continue
                print(f'\033[1;32mScanning:\033[0m{file_path}')
                capstone_detection(file_path)
                if verbosity:
                    clear_screen()

    except Exception as e:
        logger.error({e})


def entry_cap(input_file, verbosity=False):
    print('\033[3;92m Response ..')
    try:
        if os.path.isdir(input_file):
            if verbosity:
                print('Verbose mode \033[33mON\033[0m')
                scan_directory(input_file, verbosity=False)
            else:
                print('Verbose mode \033[33mOFF\033[0m')
                scan_directory(input_file, verbosity=True)
        elif os.path.isfile(input_file):
            print(f'\033[1:32mScanning:{input_file}')
            capstone_detection(input_file)
    except KeyboardInterrupt as e:
        print(f'{e}\nExiting')
        sys.exit(1)
    except Exception:
        pass


if __name__ == '__main__':
    entry_cap('/home/user/Documents', verbosity=True)
