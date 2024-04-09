import time
import sys


def dynamic_countdown(seconds):
    start_time = time.time()
    end_time = start_time + seconds

    try:
        while time.time() < end_time:
            current_time = time.time()
            remaining_time = end_time - current_time
            minutes, seconds = divmod(remaining_time, 60)
            timer = '{:02d}:{:02d}'.format(int(minutes), int(seconds))
            print(timer, end="\r")
            # Adjust the sleep time to control the update frequency
            time.sleep(0.1)
    except KeyboardInterrupt as e:
        print(f'{e}\nExiting')
        time.sleep(1)
        sys.exit(1)
