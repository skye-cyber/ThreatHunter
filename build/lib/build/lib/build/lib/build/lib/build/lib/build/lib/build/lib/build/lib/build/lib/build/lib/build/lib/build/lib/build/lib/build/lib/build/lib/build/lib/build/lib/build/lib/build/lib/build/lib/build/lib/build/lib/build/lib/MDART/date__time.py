import datetime


def get_date_time():
    # get current date and time
    c_datetime = datetime.datetime.now()

    # Extrace year, month,hour, minute and second
    year = c_datetime.year
    month = c_datetime.month
    day = c_datetime.day
    hour = c_datetime.hour
    minute = c_datetime.minute
    second = c_datetime.second
    current_datetime = f'{day}-{month}-{year} {hour}:{minute}:{second}'
    return current_datetime