##
# ecbreaker.rb
# Created: January 6, 2013
# By: Ron Bowes
#
# This class implements a simple chosen plaintext attack against ciphers that
# use the Electronic Codebook mode (ECB). It requires a 'module', which
# implements a couple simple methods:
#
# NAME A constant representing the name of the module, used for output.
#
# blocksize() The blocksize of whatever cipher is being used, in bytes (eg, #
# 16 for AES, 8 for DES, etc)
#
# do_encrypt(ciphertext) Attempt to decrypt the given data, and return
# true if there was no padding error and false if a padding error occured.
#
# character_set() [optional] If character_set() is defined, it is expected to
# return an array of characters in the order that they're likely to occur in
# the string. This allows modules to optimize themselves for, for example,
# filenames. The list doesn't need to be exhaustive; all other possible values
# are appended from 0 to 255.
#
# See LocalTestModule.rb and RemoteTestModule.rb for examples of how this can
# be implemented.
##
#

module ECBreaker
  attr_accessor :verbose

  @@guesses = 0

  def ECBreaker.guesses
    return @@guesses
  end

  def ECBreaker.ord(c)
    if(c.is_a?(Fixnum))
      return c
    end
    return c.unpack('C')[0]
  end

  def ECBreaker.generate_set(base_list)
    mapping = []
    base_list.each do |i|
      mapping[ord(i)] = true
    end

    0.upto(255) do |i|
      if(!mapping[i])
        base_list << i.chr
      end
    end

    return base_list
  end

  def ECBreaker.do_block(mod, block, previous, has_padding = false, verbose = false)
    # Default result to all question marks - this lets us show it to the user
    # in a pretty way
    result = "?" * block.length
    plaintext = ""

    puts("TODO")

    exit
    return plaintext
  end

  # This is the public interface. Call this with the mod, data, and optionally
  # the iv, and it'll return the decrypted text or throw an error if it can't.
  # If no IV is given, it's assumed to be NULL (all zeroes).
  def ECBreaker.decrypt(mod, data, verbose = false)
    # Validate the blocksize
    if(data.length % mod.blocksize != 0)
      puts("Encrypted data isn't a multiple of the blocksize! Is this a block cipher?")
    end

    blockcount = data.length / mod.blocksize

    # Tell the user what's going on
    if(verbose)
      puts("> Starting ECBreaker decrypter with module #{mod.class::NAME}")
      puts(">> Encrypted length: %d" % data.length)
      puts(">> Blocksize: %d" % mod.blocksize)
      puts(">> %d blocks:" % blockcount)
    end

    # Split the data into blocks - using unpack is kinda weird, but it's the
    # best way I could find that isn't Ruby 1.9-specific
    blocks = data.unpack("a#{mod.blocksize}" * blockcount)
    i = 0
    blocks.each do |b|
      i = i + 1
      if(verbose)
        puts(">>> Block #{i}: #{b.unpack("H*")}")
      end
    end

    # Decrypt all the blocks - from the last to the first (after the IV).
    # This can actually be done in any order.
    result = ''
    0.upto(blocks.size - 1) do |i|
      is_last_block = (i == blocks.size - 1)
      new_result = do_block(mod, blocks[i], blocks[i - 1], is_last_block, verbose)
      if(new_result.nil?)
        return nil
      end
      result = new_result + result
      if(verbose)
        puts(" --> #{result}")
      end
    end

    # Validate and remove the padding
    pad_bytes = result[result.length - 1].chr
    if(result[result.length - ord(pad_bytes), result.length - 1] != pad_bytes * ord(pad_bytes))
      puts("Bad padding:")
      puts(result.unpack("H*"))
      return nil
    end

    # Remove the padding
    result = result[0, result.length - ord(pad_bytes)]

    return result
  end
end
