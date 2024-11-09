# RSA Signature Validation in Simos18

VW Simos18 uses RSA signatures to validate the content of each software block. As with all system-level cryptography
primitives, the RSA code lives inside of the One Time Programmed (OTP) area between SBOOT and CBOOT.

There are five public keys contained in the OTP area beginning at `80014408` . The first key is the production software
key used to sign production update blocks. The third key is the Continental SSM "service mode" key. It is unknown what
the other keys are used for at this time.

Each logical software block contains a "security header", at 0x0 or 0x300. This header specifies a CRC checksum, a
number of address ranges, and the address ranges themselves which are verified in this software block. During the flash
process, block data is written directly to Flash (as there is nowhere near enough RAM in this processor to store the
content of even a single Flash block, this is a simple necessity) - but, the "validity" flag for that block is erased
prior to writing.

During the Checksum routine in CBOOT, a method in the Boot ROM at `affff120` is invoked which simply calls back out into
`80014110` in the OTP area (presumably, as an obfuscation mechanism). This procedure verifies that the RSA signature of
the flashed block validates. If so, the CBOOT writes the Valid flags for this block.

The RSA signature itself is standard - constructed using RSA PKCS#1 v1.5, with the ASN.1 container inside indicating the
NIST SHA256 algorithm. As for what data is checksummed to generate the signature : the data which is signed is NOT only
the block data, making a signature reuse attack impossible. The block data is salted with the addresses which produced
the data as well as scrambled using a fixed algorithm based on address prior to being checksummed, so signatures wisely
cannot be reused to sign data at a different location in memory, or slid to a different location inside of a signed
block. This property can be observed in practice in CBOOT blocks, which contain two security headers and thus two RSA
signatures due to their ability to live at two locations in Flash (CBOOT_temp and
CBOOT). [rsadecodesimos18.py](../rsadecodesimos18.py) contains a worked example of "encrypting" (decrypting) the RSA
signature on a given software block using the Production public key, producing an ASN.1 structure containing the SHA
checksum for the block.

While the end-user cannot alter the addresses in the security header areas (as they are incorporated into the signed
data as a header), there is a mistake in early Simos18 CBOOTs which has proved highly beneficial - the "CBOOT" security
header is excluded from the ranges checked in the "CBOOT_temp" security header, meaning two things: early Simos18 CBOOTs
can be forged to install on any Simos18.1 ECU as the production keys were not changed, and the "CBOOT" security header
can be tampered with and still successfully promoted through "CBOOT_temp."
