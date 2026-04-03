# ==========================================
# قواعد كشف الهجمات لـ Mini-SIEM
# ==========================================

def check_failed_login(logs):
    """كشف محاولات الدخول الفاشلة (Brute Force)"""
    failed_count = 0

    for log in logs:
        try:
            message = log.message
        except AttributeError:
            # لو log عبارة عن نص عادي
            message = str(log)

        if "Failed password" in message:
            failed_count += 1

    if failed_count >= 3:
        print("🚨 BRUTE FORCE ATTACK DETECTED")


def suspicious_upload(logs):
    """كشف رفع ملفات مشبوهة (.php)"""
    for log in logs:
        try:
            message = log.message
        except AttributeError:
            message = str(log)

        if "uploaded" in message and ".php" in message:
            print("⚠️ SUSPICIOUS FILE UPLOAD DETECTED")
