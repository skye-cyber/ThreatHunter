import time
import os


def print_overwrite(msg):
    """Print message, overwriting the previous line."""
    rows, cols = os.popen('stty size', 'r').read().split()
    length = int(cols)

    padding = ' ' * length
    line = '\r{}\r{}'.format(padding, msg.ljust(length))

    print(line, end='\n' if len(msg) >= int(rows) else '', flush=True)


if __name__ == '__main__':
    ls = {'Processing iteration  # ',
          'hello nice to see ya, by bye, till later', '6666666', 'print_overwrite', 'Traceback (most recent call last):'}
    for i in ls:
        time.sleep(1)
        print_overwrite(f"{i}")