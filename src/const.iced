
T = 
  version : 1
  cipher :
    key_size : 32 # AES256
    iv_size  : 16 # AES256
  hmac :
    key_size : 32 # SHA256
  defaults :
    blocksize : 0x100000

T.defaults.hashes_per_block = T.defaults.blocksize / T.hmac_key_size

module.exports = T
