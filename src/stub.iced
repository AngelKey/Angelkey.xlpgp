

#
# Abstract stubs for how to use this library
#
class Stubs

  constructor : () ->
  _unimplemented : (cb) -> cb new Error "unimplemented!"

  decode_pgp_header : ({asp, buf}, cb) ->     @_unimplemented cb
  encode_pgp_header : ({asp, buf}, cb) ->     @_unimplemented cb
  initialize_aes256 : ({key, iv, asp}, cb) -> @_unimplemented cb
  initialize_hmac_sha256 : ({key}, cb) ->     @_unimplemented cb
  aes256_encrypt : ({buf}, cb) ->             @_unimplemented cb
  aes256_decrypt : ({buf}, cb) ->             @_unimplemented cb
  hmac_sha256 : ( {buf}, cb) ->               @_unimplemented cb
  read : ({start, bytes}, cb) ->              @_unimplemented cb
  write : ({buf, start, bytes}, cb) ->        @_unimplemented cb
  get_length : (cb) ->                        @_unimplemented cb
  set_length : (cb) ->                        @_unimplemented cb
  prng : ({n}, cb) ->                         @_unimplemented cb



