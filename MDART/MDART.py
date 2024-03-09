import os
import time
import argparse
from .mytimer import dynamic_countdown
from .YARA import yara_entry
from .cap import entry_cap
from .date__time import get_date_time
# from mach_O import get_macho_info
import logging
import logging.handlers

logging.basicConfig(level=logging.INFO, format='%(levelname)-8s %(message)s')
logger = logging.getLogger(__name__)


def check_os():
    try:
        # check current System
        if os.name == 'posix':
            logger.info('\033[1;35mRunning on unix system\033[0m')

        elif os.name == 'nt':
            logger.info('\033[1;35mRunning on windows system\033[0m')
            # show additional information
        else:
            logger.info('\033[1;33mRunning on unidentified System')
    except KeyboardInterrupt as e:
        print(f'{e}\nExiting')
        time.sleep(1)
    except Exception as e:
        print(f'{e}')


def see_log():
    if os.name == 'posix':
        log = f'/home/{os.getlogin()}/MDART/log'
        print(log)
        if os.path.exists(log):
            print(f'\033[32mCheck log file at \
{log}for any redlines\t{get_date_time()}')
    elif os.name == 'nt':
        log = 'C:\\Users\\MDART\\log'
        if os.path.exists(log):
            print(f'\033[32mCheck log file at   for \
{log}any redlines\t{get_date_time()}')


def main():
    parser = argparse.ArgumentParser(description='MAREP is a Malware-Analysis-\
Reverse-Engineering-Platform is an advanced malware analysis, and reverse \
Engineering software')

    parser.add_argument('-p', '--path', help='scan a given directory or file')
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
            logger.info('\033[1;32mRound one using \033[1;35mYARA\033[0m')
            yara_entry(dir_path)
            logger.info('\033[1;32mRound two using \033[1;35mCapstone\033[0m')
            entry_cap(dir_path)
            logger.info('\033[1;32mRound three using \033[1;35mRedare2\033[0m')
            # elif entry_r2(dir_path):

        except KeyboardInterrupt as e:
            print(f'{e}\nExiting')
            time.sleep(1)
        except Exception as e:
            print(f'{e}')
        see_log()

    else:
        try:
            root_dir = os.getcwd()
            print(f'current directory = {root_dir}')
            # use yara
            logger.info('\033[1;32mRound one using \033[1;35mYARA\033[0m')
            yara_entry(root_dir)
            logger.info('\033[1;32mRound two using \033[1;35mCapstone\033[0m')
            entry_cap(root_dir)
        except KeyboardInterrupt as e:
            print(f'{e}\nExiting')
            see_log()
            time.sleep(1)
            sys.exit(1)
        except Exception as e:
            print(f'{e}')
        see_log()


if __name__ == '__main__':
    main()