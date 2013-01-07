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

  def ECBreaker.to_blocks(mod, data)
    block_count = data / mod.blocksize
    return goal.unpack("a#{mod.blocksize}" * block_count)
  end

  def ECBreaker.find_character(mod, current_plaintext)
    index = current_plaintext.size % mod.blocksize
    block =  current_plaintext.size / mod.blocksize
    prefix = ("A" * (mod.blocksize - index - 1))

    goal = mod.encrypt_with_prefix(to_blocks(prefix)[index])

    generate_set(mod.character_set).each do |c|
      encrypted_text = mod.encrypt_with_prefix(prefix + current_plaintext + c)[0, mod.blocksize]
      blocks = encrypted_text.unpack("a#{mod.blocksize}" * (encrypted_text.length / mod.blocksize))

#      if(index == 15)
#        puts("encrypting: #{prefix + current_plaintext + c}")
#        puts("Result: #{encrypted_text.unpack("H*")}")
#      end


      if(blocks[0] == goal)
        puts("Discovered: '#{c}'")
        return c
      end
    end

    puts("Couldn't find a character!")
    exit
  end

  def ECBreaker.decrypt(mod, data, verbose = false)
    result = ''

    # Validate the blocksize
    if(data.length % mod.blocksize != 0)
      puts("Encrypted data isn't a multiple of the blocksize! Is this a block cipher?")
    end

    puts("Data: #{data.unpack("H*")}")

    blockcount = data.length / mod.blocksize

    loop do
      result = result + find_character(mod, result)
    end

    # Tell the user what's going on
    if(verbose)
      puts("> Starting ECBreaker decrypter with module #{mod.class::NAME}")
      puts(">> Encrypted length: %d" % data.length)
      puts(">> Blocksize: %d" % mod.blocksize)
      puts(">> %d blocks:" % blockcount)
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
