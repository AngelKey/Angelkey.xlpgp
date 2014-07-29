

#
# Abstract stubs for how to use this library
#
exports.Stubs = class Stubs

  constructor : () ->
  _unimplemented : (cb) -> cb new Error "unimplemented!"

  init : ({asp}, cb) ->                           @_unimplemented cb
  encrypt_pgp_header : ({buf}, cb) ->             @_unimplemented cb
  decrypt_pgp_header : ({buf}, cb) ->             @_unimplemented cb
  init_aes256ctr : ({key, iv}, cb) ->             @_unimplemented cb
  init_hmac_sha256 : ({key}, cb) ->               @_unimplemented cb
  aes256ctr_encrypt : ({buf}, cb) ->              @_unimplemented cb
  aes256ctr_decrypt : ({buf}, cb) ->              @_unimplemented cb
  hmac_sha256 : ( {buf}, cb) ->                   @_unimplemented cb
  read : ({start, bytes}, cb) ->                  @_unimplemented cb
  write : ({buf, start}, cb) ->                   @_unimplemented cb
  prng : (n, cb) ->                               @_unimplemented cb
  close : (cb) ->                                 @_unimplemented cb
  estimate_pgp_header_length : (cb) ->            @_unimplemented cb
