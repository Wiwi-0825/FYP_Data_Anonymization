import re
import hashlib

email_pattern = r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'
phone_pattern = r'\b\d{8}\b'
ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
password_pattern = r'password\s*:\s*\S+'
nric_pattern = r'\b[S|T|F|G]\d{7}[A-Z]\b'
age_pattern = r'Age:\s*(\d+)'
name_pattern = r'\b(John|Sarah|Michael|Aaliyah|David)\b'
version_pattern = r'\bVersion\s*:\s*v?\d+(\.\d+)*\b'
custom_name_pattern = r'\bMy Name is\s+(.+)\b'

token_map = {}
token_counter = 1


def pseudonymize_name(name):
    global token_counter

    if name not in token_map:
        token_map[name] = f"USER{token_counter:03}"
        token_counter += 1

    return token_map[name]


def hash_data(data):
    return hashlib.sha256(data.encode()).hexdigest()[:12]


def mask_phone(phone):
    return phone[:4] + "****"


def mask_email(email):
    username, domain = email.split("@")
    return username[0] + "*****@" + domain


def truncate_ip(ip):
    parts = ip.split(".")
    return f"{parts[0]}.{parts[1]}.xxx.xxx"


def generalize_age(age):
    age = int(age)

    if age <= 9:
        return "0-9"
    elif age <= 19:
        return "10-19"
    elif age <= 29:
        return "20-29"
    elif age <= 39:
        return "30-39"
    elif age <= 49:
        return "40-49"

    return "50+"


def anonymize_text(
    text,
    remove_nric=False,
    redact_password=False,
    mask_emails=False,
    mask_phones=False,
    truncate_ips=False,
    pseudonymize=False,
    hash_ids=False,
    generalize_ages=False,
    remove_secret=False
):

    if remove_nric:
        text = re.sub(nric_pattern, "[REDACTED]", text)

    if redact_password:
        text = re.sub(
            password_pattern,
            "password:[REDACTED]",
            text,
            flags=re.IGNORECASE
        )

    if mask_emails:
        emails = re.findall(email_pattern, text)
        for email in emails:
            text = text.replace(email, mask_email(email))

    if mask_phones:
        phones = re.findall(phone_pattern, text)
        for phone in phones:
            text = text.replace(phone, mask_phone(phone))

    if truncate_ips:
        ips = re.findall(ip_pattern, text)
        for ip in ips:
            text = text.replace(ip, truncate_ip(ip))

    if pseudonymize:
        names = re.findall(name_pattern, text)
        for name in names:
            text = text.replace(name, pseudonymize_name(name))

    if hash_ids:
        text = re.sub(
            r'ID:(\w+)',
            lambda m: "ID_HASH:" + hash_data(m.group(1)),
            text
        )

    if generalize_ages:
        ages = re.findall(age_pattern, text)
        for age in ages:
            text = re.sub(
                f'Age:\\s*{age}',
                f'Age: {generalize_age(age)}',
                text
            )

    if remove_secret:
        lines = text.splitlines()
        filtered = []

        for line in lines:
            if "SECRET" in line.upper():
                continue
            filtered.append(line)

        text = "\n".join(filtered)

    if pseudonymize:
        text = re.sub(
            custom_name_pattern,
            "My Name is USER001",
            text,
            flags=re.IGNORECASE
      )


    if generalize_ages:
        text = re.sub(
            version_pattern,
            "Version:vX.X.X",
            text,
            flags=re.IGNORECASE
       )

    return text