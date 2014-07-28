
T =
  version : 1
  cipher :
    key_size : 32 # AES256
    iv_size  : 8  # AES256, with 8 bytes of 0s in the LSBs.
  hmac :
    key_size :    32 # SHA256
    output_size : 32 # SHA256
  defaults :
    blocksize : 0x100000

T.defaults.hashes_per_block = Math.floor( (T.defaults.blocksize - 16)/ T.hmac.output_size )

module.exports = T
