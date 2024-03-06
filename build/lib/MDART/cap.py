import os
import time
import datetime
import capstone
import logging
import logging.handlers
from .elf import is_elf, get_elf_infor
from .pe import is_pe, get_pe_infor


logging.basicConfig(level=logging.INFO, format='%(levelname)-8s %(message)s')
logger = logging.getLogger(__name__)

# get current date and time
current_datetime = datetime.datetime.now()

'''# Extrace year, month,hour, minute and second
year = current_datetime.year
month = current_datetime.month
day = current_datetime.day
hour = current_datetime.hour
minute = current_datetime.minute
second = current_datetime.second'''


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
                log_file = '/home/user/MDART/log/capstone.log'
                with open(log_file, 'a') as log:
                    log.write(f'\n{current_datetime}\n Capstone detected \
Malware at {path}')
                try:
                    data_dumb = '/home/user/MDART/dumb/dumb.xml'
                    if is_elf(path):
                        logger.info('Get elf data...')
                        progress_show()
                        get_elf_infor(path)
                        time.sleep(5)
                        with open(data_dumb) as log:
                            log.write(
                                '@@@@@@@@@ELF FILE INFO @@@@@@@@@')
                            log.write(get_elf_infor(path))
                    elif is_pe(path):
                        logger.info('Get pe data...')
                        progress_show()
                        get_pe_infor(path)
                        time.sleep(5)
                        with open(data_dumb) as log:
                            log.write(
                                '@@@@@@@@@PE FILE INFO @@@@@@@@@')
                            log.write(get_elf_infor(path))
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


def scan_directory(directory_path):
    log_path = '/home/user/MDART/log/'
    rule_dir = '/home/user/MDART/rules/'
    try:
        for root, dirs, files in os.walk(directory_path):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                if log_path in file_path or rule_dir in file_path:
                    # logger.info(f'Ignoring {file_path}')
                    continue
                print(file_path)
                capstone_detection(file_path)
                # time.sleep(0.2)

    except KeyboardInterrupt as e:
        print(f'{e}\nExiting')
        time.sleep(0.01)
        sys.exit(1)
    except Exception as e:
        logger.error({e})


def entry_cap(input_file):
    try:
        if os.path.isdir(input_file):
            scan_directory(input_file)
            print(f'\033[32mCheck log file at /home/user/MDART/log for \
any redlines\t{current_datetime}')
        elif os.path.isfile(input_file):
            print(f'\033[33mScanning {input_file}\033[0m')
            capstone_detection(input_file)
    except KeyboardInterrupt as e:
        print(f'{e}\nExiting')
        time.sleep(0.01)
        sys.exit(1)
    except Exception:
        pass


if __name__ == '__main__':
    entry_cap('/home/user/MDART/malware/desquirr.plw')