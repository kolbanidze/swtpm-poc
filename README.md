# swtpm-poc

[![Russian](https://img.shields.io/badge/README-на_русском-red.svg)](README.ru.md)


*This project demonstrates a vulnerability in the TPM+PIN protection scheme used by systemd-cryptenroll - a fully software-based emulation of the faulTPM attack without any physical interference with the hardware TPM.*

## Requirements

* Python 3
* `cryptography` library
* `cryptsetup` installed (only for the first step)

Install dependencies:
```bash
pip install cryptography
```

## Execution Order

The entire process is divided into 4 stages. They must be performed strictly in order.

### 1. Extracting the systemd token (sd_extractor.py)
The script reads the LUKS disk header and saves the public part of the systemd token to a JSON file. Requires root privileges.

```bash
sudo python3 sd_extractor.py /dev/vda2 0
```
*   `/dev/vda2` — your encrypted partition.
*   `0` — token ID (usually 0, can be checked via `cryptsetup luksDump`).
*   Output file: `systemd_token.json`

<p align="center">
    <img src="https://raw.githubusercontent.com/kolbanidze/swtpm-poc/refs/heads/main/screenshots/stage_1.png" width=576>
</p>

### 2. Parsing the swtpm dump (permall_parser.py)
You need to locate the swtpm state file (usually `tpm2-00.permall`). That file usually located at `/var/lib/libvirt/swtpm/<UUID>/tpm2/tpm2-00.permall`. The script parses its structure and extracts all stored objects and keys into the `extracted` folder.

```bash
python3 permall_parser.py /path/to/tpm2-00.permall
```

<p align="center">
    <img src="https://raw.githubusercontent.com/kolbanidze/swtpm-poc/refs/heads/main/screenshots/stage_2.png" width=576>
</p>

### 3. Extracting the SRK Seed (srk_extractor.py)
Now you need to extract the seed of the Storage Root Key (SRK). It is usually stored in the object with handle `0x81000001`.

```bash
python3 srk_extractor.py extracted/obj_0x81000001.bin
```
The script will find the seed and save it to `srk_seed.bin`.

<p align="center">
    <img src="https://raw.githubusercontent.com/kolbanidze/swtpm-poc/refs/heads/main/screenshots/stage_3.png" width=576>
</p>

### 4. Recovering the LUKS key (luks_extractor.py)
The final step. The script takes `srk_seed.bin` and `systemd_token.json`, emulates the TPM's operation (KDFa algorithm), and decrypts the disk key.

```bash
python3 luks_extractor.py
```

<p align="center">
    <img src="https://raw.githubusercontent.com/kolbanidze/swtpm-poc/refs/heads/main/screenshots/stage_4.png" width=576>
</p>

If everything succeeds, the script will output:
1. The recovered key in HEX and Base64.
2. A ready-to-use `cryptsetup` command to unlock/mount the disk.

<p align="center">
    <img src="https://raw.githubusercontent.com/kolbanidze/swtpm-poc/refs/heads/main/screenshots/luks_access.png" width=576>
</p>