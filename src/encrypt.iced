
purepack = require 'msgpack'
{make_esc} = require 'iced-error'
{HashIndex} = require './hash_index'
{Header} = require './header'
C = require './const'
{Packet,PacketWriter} = require './packet'
{ASP} = require('pgp-utils').util

#===============================================================

class Encryptor 

  constructor : ({@stubs, asp, blocksize}) ->
    @_hash_index = new HashIndex
    @_data = { cipeher : {}, hmac : {} }
    @_packet_writer = new PacketWriter { @stubs }
    @asp = ASP.make asp
    @_blocksize = blocksize or C.defaults.blocksize

  #------------------------

  run : (cb) ->
    esc = make_esc cb, "Encryptor::run"
    await @_init esc defer()
    await @_generate_keys esc defer()
    await @_write_dummy_header esc defer()
    await @_write_dummy_hash_blocks esc defer()
    await @_write_file esc defer()
    await @_generate_hash_index esc defer()
    await @_write_header esc defer()
    await @_write_hash_blocks esc defer()
    cb null

  #------------------------

  init : (cb) ->
    await @stubs.init { @asp }, defer err
    @_hash_index = new HashIndex {}
    cb err

  #------------------------

  _generate_keys : (cb) ->
    esc = make_esc cb, "Encryptor::_generate_keys"
    await @stubs.prng C.cipher.key_size, esc defer @_data.cipher.key
    await @stubs.prng C.cipher.iv_size,  esc defer @_data.cipher.iv
    await @stubs.prng C.hmac.key_size,   esc defer @_data.hmac.key

    await @stubs.init_aes256ctr @_data.cipher, esc defer()
    await @stubs.init_hmac_ah256 @_data.hmac , esc defer()
    cb null

  #------------------------

  _write_header : (cb) ->
    hdr = new Header { keys : @_data, hash_index_1 : @_hash_index_packets[0].hmac }
    @_packet_writer.rewind()
    await @_write_header_2 { hdr }, defer err
    cb err

  #------------------------

  _write_hash_blocks : (cb) ->
    await @_packet_write { packets : @_hash_index_packets }, defer err
    cb err

  #------------------------

  _write_dummy_header : (cb) ->
    hdr = Header.new_dummy({ @stubs })
    await @_write_header_2 { hdr }, defer err
    cb err

  #------------------------

  _write_header_2 : ({hdr}, cb) ->
    esc = make_esc cb, "Encryptor::_write_dummy_header"
    await hdr.to_packet esc defer()
    await @_packet_writer.write {packet}, esc defer()
    cb null

  #------------------------

  _write_dummy_hash_blocks : (cb) ->
    packets = HashIndex.new_dummy({ @stubs }).to_packet()
    await @_packet_writer.write { packets }, defer err
    cb err

  #------------------------

  _generate_hash_index : (cb) ->
    await @_hash_index.generate {stubs }, defer err, @_hash_index_packets
    cb err

  #------------------------

  _write_file : (cb) ->
    esc = make_esc cb, "Encryptor::_write_file"
    await @stubs.get_length esc defer len
    i = 0
    while i < len
      end = Math.min(i + @_blocksize, len)
      await @stubs.read { start, bytes : (end - start) }, esc defer buf
      packet = new EncryptedPacket { buf, @stubs }
      await packet.encrypt esc defer()
      await @_packet_writer.write { packet, compute_hash : true }, esc defer index
      @_hash_index.index { index, hmac : packet.hmac }
    cb null

#===============================================================

