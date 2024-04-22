import r2pipe
import logging
import logging.handlers

logging.basicConfig(level=logging.INFO, format='%(levelname)-8s %(message)s')
logger = logging.getLogger(__name__)


# redare2 detection
def redare2_detection(path: str) -> bool:
    try:
        with r2pipe.open(path) as r2:
            r2.cmd("aaa")  # Analyze all code
            for i in r2.cmdj("afl"):
                if i["itype"] == "code" and "bad" in i["esil"]:
                    malware_type = 'Radare2 Detection'
                    print(f"\x1b[31mMalware detected:\x1b[0m {malware_type}")
                    return True
        r
    except (FileNotFoundError, PermissionError, IsADirectoryError) as e:
        print(f"{e}")
        return False
    except Exception as e:
        print(f"{e}")
        return False