from lib.constants import FlashInfo, internal_path, ecu_control_module_identifier
from .simosshared import (
    block_identifiers_simos,
    block_checksums_simos,
    box_code_location_simos,
    software_version_location_simos,
    block_transfer_sizes_simos,
)

# Simos10 Flash Info

# block sizes for s10
block_lengths_s10 = {
    1: 0x13E00,  # BOOT
    2: 0x19FA00,  # SOFTWARE
    3: 0x3C000,  # CALIBRATION
}

# The base address of each block on simos10

base_addresses_s10 = {
    1: 0x8000C000,  # BOOT
    2: 0x80020000,  # SOFTWARE
    3: 0xA01C0000,  # CALIBRATION
}

s10_binfile_offsets = {
    1: 0xC000,  # BOOT
    2: 0x20000,  # SOFTWARE
    3: 0x1C0000,  # CALIBRATION
}

s10_sa2_script = bytes.fromhex(
    "6803824A10680284443932244A05872709200481499384251648824A058712082001824A0181494C"
)

s10_binfile_size = 2097152

block_names_frf_s10 = {1: "FD_1", 2: "FD_2", 3: "FD_3"}

s10_project_name = "SA3"

s10_flash_info = FlashInfo(
    base_addresses_s10,
    block_lengths_s10,
    s10_sa2_script,
    None,
    None,
    None,
    block_names_frf_s10,
    "",
    0,
    "",
    block_identifiers_simos,
    block_checksums_simos,
    ecu_control_module_identifier,
    software_version_location_simos,
    box_code_location_simos,
    block_transfer_sizes_simos,
    s10_binfile_offsets,
    s10_binfile_size,
    s10_project_name,
)
