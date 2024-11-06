from lib.constants import (
    FlashInfo,
    PatchInfo,
    internal_path,
    ecu_control_module_identifier,
)
from lib.crypto import aes


# Block transfer sizes for MED17.5.25
def med17_block_transfer_sizes_patch(block_number: int, address: int) -> int:
    if block_number not in [2, 3, 4, 5]:  # Blocks typically modifiable
        print("Only patching ASW and CAL blocks is supported at this time!")
        exit()
    if block_number == 5:  # CAL
        return 0x100 if address < 0x80400000 else 0x8
    return 0xFFD  # Default for most patches


# Block names and identifiers for MED17.5.25
block_names_frf_med17 = {1: "FD_0", 2: "FD_1", 3: "FD_2", 4: "FD_3", 5: "FD_4"}

# MED17.5.25 Flash Info
base_addresses_med17 = {
    0: 0x80000000,  # SBOOT
    1: 0x80020000,  # CBOOT
    2: 0x80040000,  # ASW1
    3: 0x80140000,  # ASW2
    4: 0x80240000,  # ASW3
    5: 0x80340000,  # CAL
}

block_lengths_med17 = {
    1: 0x20000,  # CBOOT
    2: 0x100000,  # ASW1
    3: 0x100000,  # ASW2
    4: 0x100000,  # ASW3
    5: 0x40000,  # CAL
}

# AES encryption key and IV (placeholders, replace securely)
med17_key = bytes.fromhex("YOUR_AES_KEY_HEX")
med17_iv = bytes.fromhex("YOUR_AES_IV_HEX")

# Sample script for MED17 operation (replace with correct bytecode if available)
sa2_script_med17 = bytes.fromhex(
    "6802814A10680493080820094A05872212195482499307122011824A058703112010824A0181494C"
)

# Binfile offsets for MED17.5.25 (replace with actual offsets if different)
med17_binfile_offsets = {
    0: 0x0,  # SBOOT
    1: 0x20000,  # CBOOT
    2: 0x40000,  # ASW1
    3: 0x140000,  # ASW2
    4: 0x240000,  # ASW3
    5: 0x340000,  # CAL
}

med17_binfile_size = 4194304  # Example total size, adjust if necessary
med17_project_name = "MED17"

# Crypto configuration for MED17
med17_crypto = aes.AES(med17_key, med17_iv)

# Patch and flash information setup
med17_patch_info = PatchInfo(
    patch_box_code="MED17_CODE_HERE",
    patch_block_index=5,  # Assuming patch for CAL block
    patch_filename=internal_path("docs", "patch.bin"),
    block_transfer_sizes_patch=med17_block_transfer_sizes_patch,
)

block_transfer_sizes_med17 = {1: 0xFFD, 2: 0xFFD, 3: 0xFFD, 4: 0xFFD, 5: 0xFFD}

med17_flash_info = FlashInfo(
    base_addresses_med17,
    block_lengths_med17,
    sa2_script_med17,
    block_names_frf_med17,
    None,  # Assuming no specific block identifiers
    None,  # Assuming no checksums required
    ecu_control_module_identifier,
    None,  # Replace with software version location if known
    None,  # Replace with box code location if known
    block_transfer_sizes_med17,
    med17_binfile_offsets,
    med17_binfile_size,
    med17_project_name,
    med17_crypto,
    None,  # Block name to int mapping, replace if needed
    med17_patch_info,
    None,  # Checksum location, replace if needed
)
