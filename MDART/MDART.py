import os
import time
import argparse
from mytimer import dynamic_countdown
from elf import get_elf_infor
from pe import get_pe_infor
from YARA import yara_entry
from cap import entry_cap
# from mach_O import get_macho_info
import logging
import logging.handlers

logging.basicConfig(level=logging.INFO, format='%(levelname)-8s %(message)s')
logger = logging.getLogger(__name__)


def check_os():
    try:
        # check current System
        if os.name == 'posix':
            logger.info('\033[35mRunning on unix system\033[0m')

        elif os.name == 'ms-dos':
            logger.info('\033[35mRunning on windows system\033[0m')
            # show additional information
        else:
            logger.info('Unable to identify current System')
    except KeyboardInterrupt as e:
        print(f'{e}\nExiting')
        time.sleep(1)
    except Exception as e:
        print(f'{e}')


def main():
    parser = argparse.ArgumentParser(description='MAREP is a Malware-Analysis-\
Reverse-Engineering-Platform is an advanced malware analysis, and reverse \
Engineering software')

    parser.add_argument('-P', '--path', help='scan a given directory or file')
    parser.add_argument('--verbose', '-V', help='show more information on the \
                        malware if detected')

    args = parser.parse_args()
    dir_path = args.path
    verboseness = args.verbose

    try:
        check_os()
        logger.info(f'Commencing scan in:')
        dynamic_countdown(5)
    except Exception as e:
        print(f'{e}')

    except Exception as e:
        print(f'{e}')

    if args.path:
        # Try using yara or capstone or redare2
        try:
            # use yara
            logger.info('\033[32mRound one using \033[35mYARA\033[0m')
            yara_entry(dir_path)
            logger.info('\033[32mRound two using \033[35mCapstone\033[0m')
            entry_cap(dir_path)
            logger.info('\033[32mRound three using \033[35mRedare2\033[0m')
            # elif entry_r2(dir_path):

        except KeyboardInterrupt as e:
            print(f'{e}\nExiting')
            time.sleep(1)
        except Exception as e:
            print(f'{e}')

    else:
        try:
            root_dir = os.getcwd()
            print(f'current directory = {root_dir}')
            # use yara
            logger.info('\033[32mRound one using \033[35mYARA\033[0m')
            yara_entry(root_dir)
            logger.info('\033[32mRound two using \033[35mCapstone\033[0m')
            entry_cap(root_dir)

        except KeyboardInterrupt as e:
            print(f'{e}\nExiting')
            time.sleep(1)
            sys.exit(1)
        except Exception as e:
            print(f'{e}')


if __name__ == '__main__':
    main()