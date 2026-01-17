import struct
import hmac
import hashlib
import base64
import os
import sys
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Константы TPM 2.0
TPM_ALG_SHA256 = 0x000B
TPM_ALG_KEYEDHASH = 0x0008

def kdfa(hash_alg, key, label, context_u, context_v, bits):
    """
    Реализация функции KDFa (Key Derivation Function) согласно спецификации TPM 2.0.
    Используется для генерации симметричного ключа шифрования из Seed.
    """
    if hash_alg != TPM_ALG_SHA256: 
        raise ValueError("Only SHA256 supported in this script")
    
    label_bytes = label.encode('utf-8') + b'\x00' # Null-terminated string
    counter = 1
    bits_bytes = struct.pack('>I', bits)
    
    out_key = b''
    bytes_needed = (bits + 7) // 8
    
    while len(out_key) < bytes_needed:
        # Формат: [i]2 || Label || ContextU || ContextV || [L]2
        msg = struct.pack('>I', counter) + label_bytes + context_u + context_v + bits_bytes
        h = hmac.new(key, msg, hashlib.sha256)
        out_key += h.digest()
        counter += 1
        
    return out_key[:bytes_needed]

def usage():
    print("Usage: python3 luks_extractor.py <srk_seed_bin> <systemd_token_b64.txt>")
    print("Для получения srk_seed.bin необходимо запустить srk_extractor.py")
    print("Для получения systemd_token_b64.txt необходимо запустить sd_extractor.py")

def main():
    print("=== Systemd TPM2 LUKS Key Recovery Tool ===\n")

    srk_seed_file = None
    sd_b64_file = None
    if len(sys.argv) > 1:
        try:
            srk_seed_file = sys.argv[1]
            sd_b64_file = sys.argv[2]
        except IndexError:
            pass
        print(f"[*] Файл SRK Seed: {srk_seed_file}")
        if sd_b64_file:
            print(f"[*] Файл токена systemd: {sd_b64_file}")
    else:
        if os.path.isfile("srk_seed.bin"):
            srk_seed_file = "srk_seed.bin"
            print("[*] Принимается за SRK Seed: srk_seed.bin")
        else:
            print("[!] Файл SRK Seed не найден.")
            usage()
            return
        
        if os.path.isfile("systemd_token_b64.txt"):
            sd_b64_file = "systemd_token_b64.txt"
            print("[*] Принимается за токен systemd: systemd_token_b64.txt")
        else:
            print("[!] Файл токена systemd не найден.")
            usage()
            return
    
    try:
        with open(srk_seed_file, 'rb') as file:
            srk_seed = file.read()
        with open(sd_b64_file, 'rb') as file:
            token = json.load(file)
            blob = base64.b64decode(token['tpm2-blob'])
    except Exception as e:
        print(f"Ошибка при декодировании входных данных: {e}")
        sys.exit(1)
        
    print(f"[*] Длина SRK Seed: {len(srk_seed)} байт")
    print(f"[*] Общая длина blob: {len(blob)} байт")
    
    # --- ЭТАП 1: Разбор Blob ---
    # Systemd сохраняет данные в формате: TPM2B_PRIVATE || TPM2B_PUBLIC
    
    # 1. Читаем TPM2B_PRIVATE (Зашифрованная часть)
    # Первые 2 байта - это размер структуры
    priv_size = struct.unpack('>H', blob[0:2])[0]
    tpm2b_private = blob[0 : 2 + priv_size]
    
    # 2. Читаем TPM2B_PUBLIC (Открытая часть)
    # Идет сразу после PRIVATE
    tpm2b_public = blob[2 + priv_size :]
    
    print(f"[*] Размер TPM2B_PRIVATE: {len(tpm2b_private)}")
    print(f"[*] Размер TPM2B_PUBLIC: {len(tpm2b_public)}")
    
    # --- ЭТАП 2: Вычисление Name объекта ---
    # Name необходим для генерации ключа шифрования.
    # Name = HashAlg || Hash(TPMT_PUBLIC)
    
    # Пропускаем первые 2 байта размера TPM2B_PUBLIC, берем тело (TPMT_PUBLIC)
    pub_struct = tpm2b_public[2:] 
    
    # Парсим заголовок Public Area для проверки
    pub_type = struct.unpack('>H', pub_struct[0:2])[0]
    pub_name_alg = struct.unpack('>H', pub_struct[2:4])[0]
    
    if pub_name_alg != TPM_ALG_SHA256:
        raise ValueError("Неподдерживаемый алгоритм. Поддерживается только SHA256.")

    # Вычисляем хеш от структуры TPMT_PUBLIC
    name_hash = hashlib.sha256(pub_struct).digest()
    # Формируем полное имя: [AlgID] + [Hash]
    obj_name = struct.pack('>H', pub_name_alg) + name_hash
    
    print(f"[*] Name объекта: {obj_name.hex()}")
    
    # --- ЭТАП 3: Генерация ключа расшифровки (SymKey) ---
    # TPM использует KDFa для создания ключа AES из Seed родителя (SRK)
    # Params: Hash=SHA256, Key=SRK_Seed, Label="STORAGE", ContextU=Name, Bits=128
    
    sym_key = kdfa(
        TPM_ALG_SHA256,
        srk_seed,
        "STORAGE",
        obj_name,
        b'', # ContextV пустой
        128  # 128 бит для AES-128
    )
    
    print(f"[*] Производный симметричный ключ: {sym_key.hex()}")
    
    # --- ЭТАП 4: Извлечение зашифрованных данных (Ciphertext) и IV ---
    # Структура TPM2B_PRIVATE:
    # [Size: 2] [IntegritySize: 2] [Integrity: N] [EncryptedPart...]
    # EncryptedPart для AES-CFB родителя:
    # [IV Size: 2] [IV: 16] [Ciphertext...]
    
    cursor = 2 # Пропускаем общий size
    
    # Пропускаем Integrity (HMAC)
    integrity_size = struct.unpack('>H', tpm2b_private[cursor:cursor+2])[0]
    cursor += 2 + integrity_size
    
    # Читаем IV
    iv_size = struct.unpack('>H', tpm2b_private[cursor:cursor+2])[0]
    cursor += 2
    
    if iv_size != 16:
        raise ValueError(f"Неверный размер IV: {iv_size} (ожидалось 16 байт для AES-128)")
        
    iv = tpm2b_private[cursor : cursor + iv_size]
    cursor += iv_size
    
    # Всё, что осталось - это шифротекст
    ciphertext = tpm2b_private[cursor:]
    
    print(f"[*] IV: {iv.hex()}")
    print(f"[*] Размер шифротекста: {len(ciphertext)} байт")
    
    # --- ЭТАП 5: Расшифровка (AES-128-CFB) ---
    
    cipher = Cipher(algorithms.AES(sym_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    print(f"[*] Расшифровка прошла успешно.")
    
    # --- ЭТАП 6: Парсинг расшифрованной структуры (TPMT_SENSITIVE) ---
    # Структура:
    # [TotalSize: 2] (systemd specific padding/struct wrapper?)
    # [SensitiveType: 2]
    # [AuthSize: 2] [AuthData...]
    # [SeedSize: 2] [SeedData...]
    # [SensitiveDataSize: 2] [SensitiveData (KEY)...]
    
    d_cursor = 0
    
    # В расшифрованном блоке первым идет размер структуры TPMT_SENSITIVE
    # Мы его пропускаем
    d_cursor += 2 
    
    # Проверяем тип
    sens_type = struct.unpack('>H', decrypted_data[d_cursor:d_cursor+2])[0]
    d_cursor += 2
    
    if sens_type != TPM_ALG_KEYEDHASH:
        print(f"  ВНИМАНИЕ: неизвестный тип: 0x{sens_type:04x}")
    
    # Пропускаем Auth Value (обычно пустое или PIN hash)
    auth_size = struct.unpack('>H', decrypted_data[d_cursor:d_cursor+2])[0]
    d_cursor += 2 + auth_size
    
    # Пропускаем Seed Value (сид самого объекта)
    seed_size = struct.unpack('>H', decrypted_data[d_cursor:d_cursor+2])[0]
    d_cursor += 2 + seed_size
    
    # Читаем целевые данные (Sensitive Data)
    data_size = struct.unpack('>H', decrypted_data[d_cursor:d_cursor+2])[0]
    d_cursor += 2
    
    recovered_key = decrypted_data[d_cursor : d_cursor + data_size]
    
    print(f"\n[УСПЕХ] ВОССТАНОВЛЕН СЫРОЙ КЛЮЧ ({len(recovered_key)} байт):")
    print(f"HEX:    {recovered_key.hex()}")
    
    # Systemd кодирует эти случайные байты в Base64 перед записью в слот LUKS
    key_b64 = base64.b64encode(recovered_key).decode('utf-8')
    print(f"BASE64: {key_b64}")
    
    print(f"\nКоманда для монтирования:")
    print(f"printf \"{key_b64}\" | cryptsetup luksOpen /dev/luks_drive decrypted --key-file -")

if __name__ == "__main__":
    main()
