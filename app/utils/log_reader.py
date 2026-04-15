def read_logs(file_path):
    logs = []
    try:
        with open(file_path, "r") as f:
            for line in f:
                logs.append({
                    "message": line.strip(),
                    "source": "file"
                })
    except:
        pass
    return logs
