failed_logins = {}

def detect_bruteforce(source_ip, event_type):

    if event_type == "login_failed":

        if source_ip not in failed_logins:
            failed_logins[source_ip] = 0

        failed_logins[source_ip] += 1

        if failed_logins[source_ip] >= 5:
            return True

    return False
