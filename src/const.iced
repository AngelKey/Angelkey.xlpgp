
T =
  version : 1
  magic : 0x88892192
  cipher :
    key_size : 32 # AES256
    iv_size  : 8  # AES256, with 8 bytes of 0s in the LSBs.
  hmac :
    key_size :    32 # SHA256
    output_size : 32 # SHA256
  defaults :
    blocksize : 0x100000
    hashes_per_index_packet : 0x100

module.exports = T
