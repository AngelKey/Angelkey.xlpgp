
divmod = (n,d) -> [ Math.floor(n/d), n%d]


exports.HashIndex = class HashIndex

  constructor : ( {@stubs, @config } ) ->
    @_hmacs = []

  index : ( {index, hmac } ) ->
    @_hmacs[index] = hmac

  gen_dummy : (args, cb) ->
    await @stubs.get_length esc defer len
    n_blocks = Math.ceil(len / @blocksize)
    [q,r] = divmod (n_blocks-2), (@hashes_per_block-1)
    r += 2

    # the total number of hash blocks needed.  The last one will have
    # r hashes in it, and all of the others will have (hashes_per_block-1) hashes
    # and also a next pointer
    n_hash_blocks = q + 1




# total_blocks = #hashblocks + #fileblocks
# #fileblocks = ceil(len / blocksize)
# #hashblocks = ceil(total_blocks / hashes_per_block)
#
# t = # of total blocks
# h = # of hash blocks
# f = # of file blocks
# l = # of bytes in the file
# b = blocksize in bytes
# n = number of hashes per block
#
# t = h + f
# f = ceil (l / b)
# h = ceil(t / n)
#
# nh = h + ceil(l/b)
#

# 2 = ceil(9/5)
# 10 = 9






