"""
Проєкт: CLI-генератор паролів (Advanced)
Автор: Марк Гапяк, група ІПЗ-22
"""

import string
import secrets
import hashlib
import json
import os

DATA_FILE = "hashes.json"
SIMILAR_CHARS = "il1Lo0O"

# ── Робота з файлами ────────────────────────────────────────────────────────

def load_hashes():
    """Завантажує збережені хеші з файлу."""
    if not os.path.exists(DATA_FILE):
        return []
    with open(DATA_FILE, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return []

def save_hashes(records):
    """Зберігає хеші паролів у файл."""
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(records, f, ensure_ascii=False, indent=2)

# ── Допоміжні функції ───────────────────────────────────────────────────────

def get_yes_no(prompt):
    """Запитує користувача так/ні з валідацією введення."""
    while True:
        choice = input(prompt).strip().lower()
        if choice in ['y', 'yes', 'так', 'т']:
            return True
        if choice in ['n', 'no', 'ні', 'н']:
            return False
        print(" Помилка: введіть 'y' (так) або 'n' (ні).")

# ── Основна логіка ──────────────────────────────────────────────────────────

def generate_password():
    """Генерує один пароль за заданими правилами."""
    print("\n Налаштування генерації:")
    try:
        length = int(input(" Довжина пароля (мінімум 4): ").strip())
        if length < 4:
            print(" Помилка: надто короткий пароль.")
            return
    except ValueError:
        print(" Помилка: введіть ціле число.")
        return

    use_lower = get_yes_no(" Використовувати малі літери? (y/n): ")
    use_upper = get_yes_no(" Використовувати великі літери? (y/n): ")
    use_digits = get_yes_no(" Використовувати цифри? (y/n): ")
    use_symbols = get_yes_no(" Використовувати спецсимволи? (y/n): ")
    exclude_sim = get_yes_no(" Виключити схожі символи (il1Lo0O)? (y/n): ")

    pool = ""
    if use_lower: pool += string.ascii_lowercase
    if use_upper: pool += string.ascii_uppercase
    if use_digits: pool += string.digits
    if use_symbols: pool += string.punctuation
    if exclude_sim: pool = ''.join(c for c in pool if c not in SIMILAR_CHARS)

    if not pool:
        print(" Помилка: пул символів порожній. Змініть налаштування.")
        return

    password = ''.join(secrets.choice(pool) for _ in range(length))
    print(f"\n ✓ Згенерований пароль: {password}")
    check_strength(password)

def bulk_generate_passwords():
    """Масова генерація паролів за базовим надійним шаблоном."""
    print("\n Масова генерація паролів")
    try:
        count = int(input(" Скільки паролів згенерувати?: ").strip())
        length = int(input(" Довжина кожного пароля (мінімум 8): ").strip())
        if count <= 0 or length < 8:
            print(" Помилка: некоректні дані (мінімум 1 пароль, довжина від 8).")
            return
    except ValueError:
        print(" Помилка: введіть цілі числа.")
        return

    pool = string.ascii_letters + string.digits + "!@#$%^&*"
    print("\n ✓ Результат:")
    for i in range(count):
        password = ''.join(secrets.choice(pool) for _ in range(length))
        print(f" [{i+1:02d}] {password}")

def check_strength(password=None):
    """Перевіряє надійність пароля за бальною системою."""
    if password is None:
        password = input("\n Введіть пароль для перевірки: ").strip()

    if not password:
        print(" Помилка: пароль не може бути порожнім.")
        return

    score = 0
    feedback = []

    if len(password) >= 8: score += 1
    else: feedback.append("занадто короткий (бажано 8+ символів)")

    if any(c.islower() for c in password) and any(c.isupper() for c in password): score += 1
    else: feedback.append("відсутні великі або малі літери")

    if any(c.isdigit() for c in password): score += 1
    else: feedback.append("відсутні цифри")

    if any(c in string.punctuation for c in password): score += 1
    else: feedback.append("відсутні спецсимволи")

    print(f" Довжина: {len(password)}")
    if score < 2: print(" Статус: [СЛАБКИЙ] ")
    elif score in (2, 3): print(" Статус: [СЕРЕДНІЙ] ")
    else: print(" Статус: [НАДІЙНИЙ] ")

    if feedback:
        print(f" Поради: {', '.join(feedback)}.")

def save_password_hash():
    """Хешує пароль із сіллю (SHA-256) і зберігає його разом із приміткою."""
    print("\n Збереження хешу пароля")
    purpose = input(" Для чого цей пароль (наприклад, пошта, github): ").strip()
    if not purpose:
        print(" Помилка: примітка не може бути порожньою.")
        return

    password = input(" Введіть пароль: ").strip()
    if not password:
        print(" Помилка: пароль не може бути порожнім.")
        return

    salt = secrets.token_hex(16)
    salted_input = salt + password
    pwd_hash = hashlib.sha256(salted_input.encode('utf-8')).hexdigest()
    
    records = load_hashes()
    new_id = 1 if not records else max(r.get("id", 0) for r in records) + 1
    
    records.append({
        "id": new_id,
        "purpose": purpose,
        "salt": salt,
        "hash": pwd_hash
    })
    
    save_hashes(records)
    print(" ✓ Хеш успішно збережено у файл.")

def verify_saved_password():
    """Перевіряє, чи збігається введений рядок зі збереженим хешем."""
    records = load_hashes()
    if not records:
        print("\n Помилка: База хешів порожня. Спочатку збережіть пароль.")
        return

    print("\n Доступні записи:")
    for r in records:
        print(f" ID: {r['id']} | Призначення: {r['purpose']}")

    try:
        target_id = int(input("\n Введіть ID запису для перевірки: ").strip())
    except ValueError:
        print(" Помилка: ID має бути числом.")
        return

    record = next((r for r in records if r["id"] == target_id), None)
    if not record:
        print(" Помилка: запис із таким ID не знайдено.")
        return

    test_password = input(" Введіть пароль для аутентифікації: ").strip()
    salt = record.get("salt", "")
    
    # Відтворюємо процес хешування з тією ж сіллю
    salted_test = salt + test_password
    test_hash = hashlib.sha256(salted_test.encode('utf-8')).hexdigest()

    if test_hash == record["hash"]:
        print(" ✓ Успішно! Пароль збігається. ")
    else:
        print(" ✗ Відмовлено! Пароль невірний. ")

def validate_policy():
    """Перевіряє, чи відповідає введений рядок жорсткій політиці безпеки."""
    print("\n Перевірка на відповідність політиці")
    print(" Політика: мінімум 8 символів, 1 велика, 1 мала літера, 1 цифра.")
    password = input(" Введіть пароль: ").strip()

    is_valid = True
    errors = []

    if len(password) < 8:
        is_valid, errors = False, errors + ["- Довжина менше 8 символів"]
    if not any(c.islower() for c in password):
        is_valid, errors = False, errors + ["- Немає малих літер"]
    if not any(c.isupper() for c in password):
        is_valid, errors = False, errors + ["- Немає великих літер"]
    if not any(c.isdigit() for c in password):
        is_valid, errors = False, errors + ["- Немає цифр"]

    if is_valid:
        print(" ✓ Пароль повністю відповідає політиці безпеки.")
    else:
        print(" ✗ Пароль порушує політику:")
        for error in errors:
            print(f"   {error}")

# ── Меню ────────────────────────────────────────────────────────────────────

def menu():
    """Головний цикл програми."""
    actions = {
        "1": generate_password,
        "2": bulk_generate_passwords,
        "3": check_strength,
        "4": save_password_hash,
        "5": verify_saved_password,
        "6": validate_policy,
    }

    while True:
        print("\n" + "=" * 45)
        print(" CLI-Генератор паролів (Advanced)")
        print("=" * 45)
        print(" 1. Згенерувати один пароль")
        print(" 2. Масова генерація паролів")
        print(" 3. Перевірити надійність пароля")
        print(" 4. Зберегти хеш пароля")
        print(" 5. Перевірити збережений пароль (Аутентифікація)")
        print(" 6. Перевірити на відповідність політиці")
        print(" 0. Вийти")
        
        choice = input("\n Ваш вибір: ").strip()

        if choice == "0":
            print(" Завершення роботи.")
            break

        action = actions.get(choice)
        if action:
            action()
        else:
            print(" Невідома команда. Спробуйте ще раз.")

if __name__ == "__main__":
    menu()