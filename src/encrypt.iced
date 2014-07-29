
{make_esc} = require 'iced-error'
{Index} = require './index'
{Header} = require './header'
C = require './const'
{DataPacket} = require './packet'
{PacketWriter} = require './io'

#===============================================================

exports.Encryptor = class Encryptor

  constructor : ({@stubs, config}) ->
    @_data = { cipher : {}, hmac : {} }
    @_packet_writer = new PacketWriter { @stubs }
    @config = config or {}
    @config.blocksize or= C.defaults.blocksize
    @config.hashes_per_index_packet or= C.defaults.hashes_per_index_packet
    @_index = new Index { @stubs, @config }

  #------------------------

  run : (cb) ->
    esc = make_esc cb, "Encryptor::run"
    await @_init esc defer()
    await @_generate_keys esc defer()
    await @_write_header {}, esc defer()
    await @_write_file esc defer()
    await @_index.regen esc defer first_hmac
    await @_packet_writer.rewind esc defer()
    await @_write_header { first_hmac }, esc defer()
    await @_write_index esc defer()
    await @stubs.close esc defer()
    cb null

  #------------------------

  _init : (cb) ->
    await @stubs.init {}, defer err
    cb err

  #------------------------

  _generate_keys : (cb) ->
    esc = make_esc cb, "Encryptor::_generate_keys"
    await @stubs.prng C.cipher.key_size, esc defer @_data.cipher.key
    await @stubs.prng C.cipher.iv_size,  esc defer @_data.cipher.iv
    await @stubs.prng C.hmac.key_size,   esc defer @_data.hmac.key

    console.log "XXX"
    console.log @_data

    await @stubs.init_aes256ctr @_data.cipher, esc defer()
    await @stubs.init_hmac_sha256 @_data.hmac , esc defer()

    @_hdr = new Header { @stubs, keys : @_data }
    cb null

  #------------------------

  _write_index : (cb) ->
    await @_index.rewrite { packet_writer : @_packet_writer }, defer err
    cb err

  #------------------------

  _write_header : ({first_hmac}, cb) ->
    esc = make_esc cb, "Encryptor::_write_header"
    @_hdr.set_hmac_packet_1 first_hmac if first_hmac?
    await @_hdr.to_packet esc defer packet
    await @_packet_writer.write {packet}, esc defer()
    cb null

  #------------------------

  _write_file : (cb) ->
    esc = make_esc cb, "Encryptor::_write_file"
    go = true
    i = 0
    while go
      console.log "A #{i}"
      packetno = (i + 1)
      if (i % @config.hashes_per_index_packet) is 0
        await @_index.gen_dummy { packetno }, esc defer packet
      else
        await @stubs.read esc defer buf, eof
        go = false if eof
        packet = new DataPacket { buf, @stubs, packetno }
      console.log "B"
      await packet.crypto esc defer()
      console.log "C"
      await @_packet_writer.write { packet }, esc defer offset
      @_index.index { packetno , hmac : packet.hmac }
      packet.set_offset offset
      i++
    cb null

#===============================================================

exports.encrypt = ({stubs, config}, cb) ->
  e = new Encryptor { stubs, config }
  await e.run defer err
  cb err

#===============================================================

