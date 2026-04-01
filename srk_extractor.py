#!/usr/bin/env python3
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
        - seedValue (TPM2B, 32 байта) <- SRK SEED
        - privateKey (TPM2B, 32 байта) <- ECC private key
    """
    
    data = Path(obj_file).read_bytes()
    
    print(f"[*] Selected {obj_file} ({len(data)} bytes)")
    
    print("\n[*] Searching for 32 bytes TPM2B blocks (potential keys)...")
    
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
                        context = "(after ECC marker)"
                    elif prev == 0x0020:
                        context = "(after another TPM2B)"
                
                found_keys.append({
                    'offset': i,
                    'data': block,
                    'context': context
                })
                
                print(f"\n\tOffset 0x{i:04X}: TPM2B size=32 {context}")
                print(f"\tData: {block.hex()}")
    
    print(f"\n[*] Detected {len(found_keys)} potential 32 byte keys.")
    
    # Для ECC P-256 SRK структура обычно:
    # После публичных X,Y координат идёт TPMT_SENSITIVE
    # sensitiveType (2) + authValue (TPM2B) + seedValue (TPM2B) + privateKey (TPM2B)
    
    # Эвристика: ищем последовательность из 2-3 TPM2B блоков по 32 байта
    # Первый (после нулей authValue) = seedValue = SRK_SEED
    # Второй = privateKey
    
    if len(found_keys) >= 4:
        print("\n[*] Structure: X, Y, SeedValue, PrivateKey")
        
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
                        print(f"\n[!!!] Seed value extracted!")
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
    print("\n[!] Failed to detect structure.")    
    return None


def main():
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python3 srk_extractor.py <obj_0x81000001.bin>")
        print("\nTypically the file is located here after running permall_parser.py:")
        print("  ./extracted/obj_0x81000001.bin")
        sys.exit(1)
    
    result = extract_srk_from_object(sys.argv[1])
    
    if result:        
        # Save to files
        Path("srk_seed.bin").write_bytes(result['seed'])
        print("\n[+] SRK seed saved to srk_seed.bin")
        
        if result['private_key']:
            Path("srk_private_key.bin").write_bytes(result['private_key'])
            print("[+] The private key is saved in srk_private_key.bin")


if __name__ == "__main__":
    main()
