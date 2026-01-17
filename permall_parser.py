#!/usr/bin/env python3
"""
Парсер состояния swtpm/libtpms (TPM 2.0)
С поддержкой swtpm envelope

Использование: python3 permall_parser.py /path/to/tpm2-00.permall
"""

import struct
import sys
from dataclasses import dataclass
from typing import Optional, List, Tuple
from pathlib import Path

# Константы
PERSISTENT_ALL_MAGIC = 0xAB364723
USER_NVRAM_MAGIC = 0x094F22C3
NV_INDEX_MAGIC = 0x2547265A

TPM_HT_NV_INDEX = 0x01
TPM_HT_PERSISTENT = 0x81

# Структуры
@dataclass
class NVHeader:
    version: int
    magic: int
    min_version: int
    
    @classmethod
    def size(cls) -> int:
        return 8
    
    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> 'NVHeader':
        version, magic, min_version = struct.unpack_from('>HLH', data, offset)
        return cls(version=version, magic=magic, min_version=min_version)


@dataclass
class NVPublicArea:
    nv_index: int
    name_alg: int
    attributes: int
    auth_policy: bytes
    data_size: int


@dataclass
class NVIndexEntry:
    handle: int
    public: NVPublicArea
    auth_value: bytes
    data_size: int
    data: bytes
    raw_offset: int


@dataclass
class PersistentObjectEntry:
    handle: int
    raw_data: bytes
    raw_offset: int


# Иииии сам парсер
class PermallParser:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0
        self.nv_indices: List[NVIndexEntry] = []
        self.persistent_objects: List[PersistentObjectEntry] = []
        self.libtpms_start = 0  # Смещение начала данных libtpms
        
    def read_bytes(self, n: int) -> bytes:
        result = self.data[self.offset : self.offset + n]
        self.offset += n
        return result
    
    def read_uint8(self) -> int:
        val = struct.unpack_from('>B', self.data, self.offset)[0]
        self.offset += 1
        return val
    
    def read_uint16(self) -> int:
        val = struct.unpack_from('>H', self.data, self.offset)[0]
        self.offset += 2
        return val
    
    def read_uint32(self) -> int:
        val = struct.unpack_from('>L', self.data, self.offset)[0]
        self.offset += 4
        return val
    
    def read_uint64(self) -> int:
        val = struct.unpack_from('>Q', self.data, self.offset)[0]
        self.offset += 8
        return val
    
    def read_tpm2b(self) -> bytes:
        size = self.read_uint16()
        return self.read_bytes(size)
    
    def read_header(self) -> NVHeader:
        header = NVHeader.parse(self.data, self.offset)
        self.offset += NVHeader.size()
        return header

    def find_libtpms_start(self) -> Optional[int]:
        """Найти начало данных libtpms по magic number"""
        magic_bytes = struct.pack('>L', PERSISTENT_ALL_MAGIC)
        
        # Ищем magic в первых 256 байтах
        for i in range(min(256, len(self.data) - 4)):
            if self.data[i:i+4] == magic_bytes:
                # Magic находится на +2 от начала заголовка
                header_start = i - 2
                if header_start >= 0:
                    # Проверяем version
                    version = struct.unpack_from('>H', self.data, header_start)[0]
                    if 1 <= version <= 10:  # Разумный диапазон версий
                        return header_start
        return None
    
    def find_magic(self, magic: int, start: int = 0) -> Optional[int]:
        """Поиск супер пупер магического числа в файле"""
        magic_bytes = struct.pack('>L', magic)
        pos = start
        while pos < len(self.data) - 4:
            idx = self.data.find(magic_bytes, pos)
            if idx == -1:
                return None
            if idx >= 2:
                return idx - 2
            pos = idx + 1
        return None
    
    def parse_swtpm_envelope(self) -> bool:
        """Анализ и пропуск swtpm envelope"""
        print("[*] Анализ swtpm envelope...")
        
        # Показываем первые 32 байта
        print("    Первые 32 байта файла:")
        for i in range(0, min(32, len(self.data)), 16):
            hex_str = ' '.join(f'{b:02x}' for b in self.data[i:i+16])
            ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in self.data[i:i+16])
            print(f"    {i:04x}: {hex_str}  {ascii_str}")
        
        # Ищем начало libtpms данных
        libtpms_offset = self.find_libtpms_start()
        if libtpms_offset is None:
            print("[!] Не удалось найти начало данных libtpms!")
            return False
        
        self.libtpms_start = libtpms_offset
        print(f"\n[+] Данные libtpms начинаются с смещения: 0x{libtpms_offset:X} ({libtpms_offset} байт)")
        
        # Анализируем envelope
        if libtpms_offset > 0:
            # Нет, я не буду переводить envelope как конверт
            print(f"    swtpm envelope size: {libtpms_offset} bytes")
            envelope = self.data[:libtpms_offset]
            print(f"    Envelope hex: {envelope.hex()}")
        
        self.offset = libtpms_offset
        return True
    
    def parse_file_header(self) -> bool:
        """Парсинг заголовка libtpms"""
        print("\n[*] Парсинг заголовка PERSISTENT_ALL...")
        
        header = self.read_header()
        print(f"    Version: {header.version}")
        print(f"    Magic: 0x{header.magic:08X}")
        print(f"    MinVersion: {header.min_version}")
        
        if header.magic != PERSISTENT_ALL_MAGIC:
            print(f"[!] Неверный magic!")
            return False
        
        print("[+] Заголовок валиден")
        
        # JSON Profile (TPM2B string) - версия >= 4
        if header.version >= 4:
            json_profile = self.read_tpm2b()
            if json_profile:
                try:
                    profile_str = json_profile.decode('utf-8')
                    print(f"\n[*] Профиль JSON ({len(json_profile)} байт):")
                    # Показываем первые 200 символов
                    if len(profile_str) > 200:
                        print(f"    {profile_str[:200]}...")
                    else:
                        print(f"    {profile_str}")
                except:
                    print(f"    (binary, {len(json_profile)} bytes)")
        
        return True
    
    def parse_nv_index_structure(self, entry_start: int, entry_size: int) -> Optional[NVIndexEntry]:
        """Парсинг NV_INDEX"""
        save_offset = self.offset
        
        try:
            # NV_INDEX Header
            nv_header = self.read_header()
            if nv_header.magic != NV_INDEX_MAGIC:
                print(f"      [!] Неверный NV_INDEX magic: 0x{nv_header.magic:08X}")
                self.offset = entry_start + entry_size
                return None
            
            # TPMS_NV_PUBLIC
            nv_index = self.read_uint32()
            name_alg = self.read_uint16()
            attributes = self.read_uint32()
            auth_policy = self.read_tpm2b()
            declared_size = self.read_uint16()
            
            public = NVPublicArea(
                nv_index=nv_index,
                name_alg=name_alg,
                attributes=attributes,
                auth_policy=auth_policy,
                data_size=declared_size
            )
            
            # Auth Value
            auth_value = self.read_tpm2b()
            
            # Block skip
            has_block = self.read_uint8()
            if has_block:
                block_len = self.read_uint16()
                self.read_bytes(block_len)
            
            # Data
            actual_data_size = self.read_uint32()
            nv_data = self.read_bytes(actual_data_size)
            
            return NVIndexEntry(
                handle=nv_index,
                public=public,
                auth_value=auth_value,
                data_size=actual_data_size,
                data=nv_data,
                raw_offset=entry_start
            )
            
        except Exception as e:
            print(f"      [!] Ошибка: {e}")
            self.offset = entry_start + entry_size
            return None
    
    def parse_user_nvram(self) -> bool:
        """Парсинг USER_NVRAM"""
        print("\n[*] Поиск USER_NVRAM...")
        
        nvram_offset = self.find_magic(USER_NVRAM_MAGIC, self.libtpms_start)
        if nvram_offset is None:
            print("[!] USER_NVRAM не найден!")
            # Попробуем показать все найденные magic numbers
            print("\n[*] Поиск известных magic numbers в файле...")
            magics = [
                (PERSISTENT_ALL_MAGIC, "PERSISTENT_ALL"),
                (USER_NVRAM_MAGIC, "USER_NVRAM"),
                (NV_INDEX_MAGIC, "NV_INDEX"),
                (0x00104732, "PERSISTENT_DATA"),
            ]
            for magic, name in magics:
                off = self.find_magic(magic, 0)
                if off is not None:
                    print(f"    {name}: 0x{off:X}")
            return False
        
        print(f"[+] USER_NVRAM @ 0x{nvram_offset:X}")
        self.offset = nvram_offset
        
        header = self.read_header()
        print(f"    Version: {header.version}")
        
        source_size = self.read_uint64()
        print(f"    Source size: {source_size}")
        
        # Entries
        entry_count = 0
        print("\n[*] Записи USER_NVRAM:")
        
        while self.offset < len(self.data) - 8:
            entry_start = self.offset
            entry_size = self.read_uint32()
            
            if entry_size == 0:
                print(f"\n    [Конец списка]")
                break
            
            if entry_size > 100000:
                print(f"    [!] entry_size слишком большой: {entry_size}")
                break
                
            handle = self.read_uint32()
            handle_type = (handle >> 24) & 0xFF
            
            entry_count += 1
            print(f"\n    Entry #{entry_count}:")
            print(f"      Offset: 0x{entry_start:X}")
            print(f"      Size: {entry_size}")
            print(f"      Handle: 0x{handle:08X}")
            
            if handle_type == TPM_HT_NV_INDEX:
                print(f"      Type: NV_INDEX")
                nv_entry = self.parse_nv_index_structure(entry_start, entry_size)
                if nv_entry:
                    self.nv_indices.append(nv_entry)
                    print(f"      Attributes: 0x{nv_entry.public.attributes:08X}")
                    print(f"      Data: {nv_entry.data_size} bytes")
                    
            elif handle_type == TPM_HT_PERSISTENT:
                print(f"      Type: PERSISTENT_OBJECT")
                body_size = entry_size - 8
                raw_data = self.read_bytes(body_size)
                self.persistent_objects.append(PersistentObjectEntry(
                    handle=handle,
                    raw_data=raw_data,
                    raw_offset=entry_start
                ))
            else:
                print(f"      Type: OTHER (0x{handle_type:02X})")
                self.offset = entry_start + entry_size
        
        print(f"\n[+] Итого: {len(self.nv_indices)} NV indices, {len(self.persistent_objects)} объедков")
        return True
    
    def dump_results(self, output_dir: Path):
        """Сохранение результатов"""
        output_dir.mkdir(parents=True, exist_ok=True)
        print(f"\n[*] Сохранение в {output_dir}/")
        
        for nv in self.nv_indices:
            # Binary data
            bin_file = output_dir / f"nv_0x{nv.handle:08X}.bin"
            bin_file.write_bytes(nv.data)
            
            # Info
            info_file = output_dir / f"nv_0x{nv.handle:08X}.txt"
            with open(info_file, 'w') as f:
                f.write(f"Handle: 0x{nv.handle:08X}\n")
                f.write(f"Attributes: 0x{nv.public.attributes:08X}\n")
                f.write(f"NameAlg: 0x{nv.public.name_alg:04X}\n")
                f.write(f"DataSize: {nv.data_size}\n")
                f.write(f"AuthPolicy: {nv.public.auth_policy.hex() if nv.public.auth_policy else 'none'}\n")
                f.write(f"AuthValue: {nv.auth_value.hex() if nv.auth_value else 'none'}\n")
                f.write(f"\nData (hex):\n{nv.data.hex()}\n")
            
            print(f"    [+] nv_0x{nv.handle:08X}.bin ({nv.data_size} bytes)")
        
        for obj in self.persistent_objects:
            bin_file = output_dir / f"obj_0x{obj.handle:08X}.bin"
            bin_file.write_bytes(obj.raw_data)
            print(f"    [+] obj_0x{obj.handle:08X}.bin ({len(obj.raw_data)} bytes)")
    
    def parse(self) -> bool:
        if not self.parse_swtpm_envelope():
            return False
        if not self.parse_file_header():
            return False
        if not self.parse_user_nvram():
            return False
        return True


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 permall_parser.py <permall_file> [output_dir]")
        sys.exit(1)
    
    permall_path = Path(sys.argv[1])
    output_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("./extracted")
    
    if not permall_path.exists():
        print(f"[!] File not found: {permall_path}")
        sys.exit(1)
    
    print("=" * 60)
    print("  SWTPM PERMALL PARSER")
    print("=" * 60)
    print(f"\n[*] Файл: {permall_path}")
    print(f"[*] Размер: {permall_path.stat().st_size} байт\n")
    
    data = permall_path.read_bytes()
    parser = PermallParser(data)
    
    if parser.parse():
        parser.dump_results(output_dir)
        print("\n" + "=" * 60)
        print("  ПАРСИНГ ЗАВЕРШЕН")
        print("=" * 60)
    else:
        print("\n[!] Ошибка парсинга")
        sys.exit(1)


if __name__ == "__main__":
    main()
