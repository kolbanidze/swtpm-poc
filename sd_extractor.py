import subprocess
import sys
import os

def get_token(drive: str, token_id: str):
    process = subprocess.run(['cryptsetup', 'token', 'export', '--token-id', token_id, drive], check=True, capture_output=True)
    return process.stdout.decode()

def usage():
    print("Usage: sudo python sd_extractor.py <luks_drive> <token_id> <output>")
    print("Если <output> не указан, то используется systemd_token.json")

def main():
    if os.getuid() != 0:
        print("[!] Требуются права root")
        usage()
        return

    if len(sys.argv) < 3:
        usage()
        return
    drive = sys.argv[1]
    token_id = sys.argv[2]
    try:
        output_file = sys.argv[3]
    except IndexError:
        output_file = "systemd_token.json"
    print(f"[*] LUKS диск: {drive}")
    print(f"[*] Номер токена: {token_id}")
    
    token = get_token(drive, token_id)
    with open(output_file, "w") as file:
        file.write(token)
    print(f"[*] Данные о токене успешно записаны в {output_file}")

if __name__ == "__main__":
    main()

