
C = require './const'
{pack} = require 'purepack'
{make_esc} = require 'iced-error'
{HeaderPacket} = require './packet'

#===============================================================

exports.Header = class Header

  #-------------

  constructor : ( {@stubs, @keys, @hmac_packet_1 }) ->
    @_encrypted = null

  #-------------

  generate : (cb) ->
    json = [ C.version, @keys.cipher.key, @keys.cipher.iv, @keys.hmac.key, @hmac_packet_1 ]
    buf = pack json
    await @stubs.encrypt_pgp_header { buf }, defer err, @_encrypted
    cb err, @_encrypted

  #-------------

  set_hmac_packet_1 : (b) -> @hmac_packet_1 = b

  #-------------

  to_packet : (cb) ->
    esc = make_esc cb, "Header::to_packet"
    to_buf_args = {}
    if @hmac_packet_1?
      await @generate esc defer pgp
      padded_len = @_dummy.len if @_dummy?
    else
      console.log "ok, in the rewrite1"
      await @stubs.estimate_pgp_header_length defer err, len
      @_dummy = pgp = new Buffer (0 for [0...len])
      padded_len = null
    pkt = new HeaderPacket { pgp, @stubs, len : padded_len }
    cb null, pkt

#===============================================================

