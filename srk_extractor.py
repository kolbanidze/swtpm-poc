#!/usr/bin/env python3
"""
srk_extractor.py - Извлечение SRK Seed из obj_0x81000001.bin (адрес может отличаться)
"""

import struct
from pathlib import Path

def extract_srk_from_object(obj_file: str):
    """
    Извлекает SRK Seed и Private Key из persistent object файла
    
    Структура obj_0x81000001.bin для ECC P-256:
    - Заголовок объекта
    - TPMT_PUBLIC (ECC public key: X, Y координаты)
    - TPMT_SENSITIVE:
        - sensitiveType (0x0023 = ECC)
        - authValue (TPM2B, обычно пустой)
        - seedValue (TPM2B, 32 байта) ← SRK SEED
        - privateKey (TPM2B, 32 байта) ← ECC private key
    """
    
    data = Path(obj_file).read_bytes()
    
    print(f"[*] Анализ {obj_file} ({len(data)} байт)")
    print(f"[*] Полный hex дамп:")
    
    for i in range(0, len(data), 32):
        hex_str = data[i:i+32].hex()
        print(f"    {i:04x}: {hex_str}")
    
    print("\n[*] Поиск блоков TPM2B размером 32 байт (потенциальные ключи)...")
    
    found_keys = []
    
    for i in range(0, len(data) - 34):
        # Ищем TPM2B с размером 32 (0x0020)
        size = struct.unpack_from('>H', data, i)[0]
        
        if size == 32 and i + 34 <= len(data):
            block = data[i+2:i+34]
            
            # Проверяем что это не нули
            if any(b != 0 for b in block):
                # Проверяем предыдущие 2 байта - могут указывать на тип
                context = ""
                if i >= 2:
                    prev = struct.unpack_from('>H', data, i-2)[0]
                    if prev == 0x0023:
                        context = "(после маркера ECC)"
                    elif prev == 0x0020:
                        context = "(после другого TPM2B)"
                
                found_keys.append({
                    'offset': i,
                    'data': block,
                    'context': context
                })
                
                print(f"\n    Offset 0x{i:04X}: TPM2B size=32 {context}")
                print(f"    Data: {block.hex()}")
    
    print(f"\n[*] Найдено {len(found_keys)} потенциальных ключей размером в 32 байта.")
    
    # Для ECC P-256 SRK структура обычно:
    # После публичных X,Y координат идёт TPMT_SENSITIVE
    # sensitiveType (2) + authValue (TPM2B) + seedValue (TPM2B) + privateKey (TPM2B)
    
    # Эвристика: ищем последовательность из 2-3 TPM2B блоков по 32 байта
    # Первый (после нулей authValue) = seedValue = SRK_SEED
    # Второй = privateKey
    
    if len(found_keys) >= 4:
        # Предполагаем: X, Y, Seed, PrivateKey
        print("\n[*] Структура: X, Y, SeedValue, PrivateKey")
        
        # Ищем блок который следует за нулевым authValue
        for i, key in enumerate(found_keys):
            offset = key['offset']
            
            # Проверяем если перед этим блоком есть 0x0020 + 32 нуля
            if offset >= 34:
                check_offset = offset - 34
                check_size = struct.unpack_from('>H', data, check_offset)[0]
                if check_size == 32:
                    check_data = data[check_offset+2:check_offset+34]
                    if all(b == 0 for b in check_data):
                        print(f"\n    🔑 Найден seedValue!")
                        print(f"    SRK_SEED @ 0x{offset:04X}: {key['data'].hex()}")
                        
                        # Следующий блок должен быть privateKey
                        if i + 1 < len(found_keys):
                            next_key = found_keys[i + 1]
                            print(f"    PRIVATE_KEY @ 0x{next_key['offset']:04X}: {next_key['data'].hex()}")
                        
                        return {
                            'seed': key['data'],
                            'private_key': found_keys[i + 1]['data'] if i + 1 < len(found_keys) else None
                        }
    
    # Fallback: просто выводим все найденные ключи
    print("\n[!] Не удалось определить структуру. Нужен ручной анализ.")    
    return None


def main():
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python3 srk_extractor.py <obj_0x81000001.bin>")
        print("\nОбычно файл находится здесь после запуска permall_parser.py:")
        print("  ./extracted/obj_0x81000001.bin")
        sys.exit(1)
    
    result = extract_srk_from_object(sys.argv[1])
    
    if result:
        print("\n" + "=" * 60)
        print("  ИЗВЛЕЧЕННЫЕ КЛЮЧИ")
        print("=" * 60)
        print(f"\nSRK_SEED = \"{result['seed'].hex()}\"")
        if result['private_key']:
            print(f"SRK_PRIVATE_KEY = \"{result['private_key'].hex()}\"")
        
        # Save to files
        Path("srk_seed.bin").write_bytes(result['seed'])
        print("\n[+] SRK сохранен в srk_seed.bin")
        
        if result['private_key']:
            Path("srk_private_key.bin").write_bytes(result['private_key'])
            print("[+] Приватный ключ сохранен в srk_private_key.bin")


if __name__ == "__main__":
    main()
