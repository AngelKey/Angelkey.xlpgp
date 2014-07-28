
{mpack} = require 'purepack'
{make_esc} = require 'iced-error'

#===============================================================

pad = (buf, len) ->
  if (diff = (len - buf.length)) < 0
    throw new Error "Can't shrink a packet, can only pad it with 0s"
  else
    buf = Buffer.concat [ buf, (new Buffer (0 for [0...diff]))]
  buf

#===============================================================

class Packet

  #---------

  constructor : ({@stubs}) ->
    @_buf_cache = null
    @_hmac_cache = null

  #---------

  reset : () -> @_buf_cache = @_hmac_cache = null

  #---------

  to_buffer : (args = {}) ->
    unless @_buf_cache = null
      obj = [ @packet_tag(), @to_json() ]
      packed = mpack obj
      if args?.len then packet = pad packet, args.len
      len = mpack packed.length
      @_buf_cache = Buffer.concat [ len, packed ]
    @_buf_cache

  #---------

  compte_hmac : (cb) ->
    err = null
    unless @hmac?
      await @stubs.hmac_sha256 { buf : @to_buffer() }, defer err, @hmac
    cb err, @_hmac_cache

  #---------

  get_hmac : () -> @_hmac_cache

#===============================================================

exports.IndexPacket = class IndexPacket extends Packet

  TAG : 0x2

  #---------

  constructor : ( {stubs, @index}) -> super { stubs }
  packet_tag : () -> IndexPacket.TAG
  to_json : () -> @index

#===============================================================

exports.DataPacket = class DataPacket extends Packet

  TAG : 0x3

  #---------

  constructor : ( {@plaintext, stubs}) ->
    super { stubs }
    @hmac = null
    @ciphertext = null

  #---------

  packet_tag : () -> DataPacket.TAG

  #---------

  encrypt : (cb) ->
    esc = make_esc cb, "DataPacket.encrypt"
    await @stubs.aes256ctr_encrypt { buf : @plaintext }, esc defer @ciphertext
    await @compute_hmac esc defer()
    cb null

  #---------

  to_json : () -> @ciphertext

#===============================================================

