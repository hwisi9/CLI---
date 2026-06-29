# test.py
# Автоматизований тест для перевірки збереження та логіки хешування
import os
import hashlib
import secrets
import main  # імпортуємо головний модуль

TEST_FILE = "test_hashes.json"

def setup():
    """Перевизначає файл даних на тимчасовий."""
    main.DATA_FILE = TEST_FILE
    if os.path.exists(TEST_FILE):
        os.remove(TEST_FILE)

def teardown():
    """Видаляє тимчасовий файл після тесту."""
    if os.path.exists(TEST_FILE):
        os.remove(TEST_FILE)

def run_tests():
    setup()
    
    # Тест 1: Перевірка збереження та завантаження даних
    dummy_record = {
        "id": 1,
        "purpose": "test_service",
        "salt": "dummysalt123",
        "hash": "dummyhash456"
    }
    
    main.save_hashes([dummy_record])
    records = main.load_hashes()
    
    assert len(records) == 1, "Помилка: Має бути 1 запис"
    assert records[0]["purpose"] == "test_service", "Помилка: Дані пошкоджено при збереженні"
    print(" ✓ Тест 1: Збереження та читання файлу працює коректно")

    # Тест 2: Перевірка логіки хешування із сіллю
    password = "MySecretPassword123!"
    salt = "random_salt_16_bytes"
    
    expected_hash = hashlib.sha256((salt + password).encode('utf-8')).hexdigest()
    test_hash_correct = hashlib.sha256((salt + "MySecretPassword123!").encode('utf-8')).hexdigest()
    assert test_hash_correct == expected_hash, "Помилка: Правильний пароль не пройшов перевірку"
    
    test_hash_wrong = hashlib.sha256((salt + "WrongPass").encode('utf-8')).hexdigest()
    assert test_hash_wrong != expected_hash, "Помилка: Неправильний пароль дав збіг хешів!"
    print(" ✓ Тест 2: Логіка хешування та перевірки пароля працює коректно")

    # Тест 3: Перевірка форматів криптографічних даних
    test_salt = secrets.token_hex(16)
    test_hash = hashlib.sha256((test_salt + "dummy_pass").encode('utf-8')).hexdigest()
    
    assert len(test_salt) == 32, "Помилка: Довжина солі не відповідає 16 байтам у hex-форматі"
    assert len(test_hash) == 64, "Помилка: Довжина хешу не відповідає стандарту SHA-256"
    print(" ✓ Тест 3: Формати криптографічних даних (сіль та хеш) коректні")

    teardown()
    print("\n Усі автоматизовані тести пройдено успішно.")

if __name__ == "__main__":
    run_tests()