from app.utils.normalizer import normalize_log

def read_logs(file_path):
    logs = []

    with open(file_path, "r") as f:
        for line in f:
            if line.strip():  # مهم لتجاهل الأسطر الفارغة
                normalized = normalize_log(line)
                logs.append(normalized)

    return logs
