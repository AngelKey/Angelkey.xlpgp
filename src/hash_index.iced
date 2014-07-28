
exports.HashIndex = class HashIndex

  constructor : ( {@stubs} ) ->
    @_hmacs = []

  index : ( {index, hmac } ) ->
    @_hmacs[index] = hmac

  gen_dummy : ({blocksize}, cb) ->
    await @stubs.get_length esc defer len




