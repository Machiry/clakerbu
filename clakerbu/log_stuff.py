def log_info(*args):
    log_str = "[*] "
    for curr_a in args:
        log_str = log_str + " " + str(curr_a)
    print log_str


def log_error(*args):
    log_str = "[!] "
    for curr_a in args:
        log_str = log_str + " " + str(curr_a)
    print log_str


def log_warning(*args):
    log_str = "[?] "
    for curr_a in args:
        log_str = log_str + " " + str(curr_a)
    print log_str


def log_success(*args):
    log_str = "[+] "
    for curr_a in args:
        log_str = log_str + " " + str(curr_a)
    print log_str
