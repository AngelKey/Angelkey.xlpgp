
purepack = require 'msgpack'
{make_esc} = require 'iced-error'
{HashIndex} = require './hash_index'
{Header} = require './header'
C = require './const'

#===============================================================

class Encryptor 

  constructor : ({@stubs}) ->
    @_hash_index = new HashIndex
    @_data = { cipeher : {}, hmac : {} }

  #------------------------

  run : (cb) ->
    esc = make_esc cb, "Encryptor::run"
    await @_generate_keys esc defer()
    await @_write_dummy_header esc defer()
    await @_write_dummy_hash_blocks esc defer()
    await @_write_file esc defer()
    await @_write_header esc defer()
    await @_write_hash_blocks esc defer()
    cb null

  #------------------------

  _generate_keys : (cb) ->
    esc = make_esc cb, "Encryptor::_generate_keys"
    await @stubs.prng C.cipher.key_size, esc defer @_data.cipher.key
    await @stubs.prng C.cipher.iv_size,  esc defer @_data.cipher.iv
    await @stubs.prng C.hmac.key_size,   esc defer @_data.hmac.key
    cb null

  #------------------------

  #------------------------

#===============================================================

