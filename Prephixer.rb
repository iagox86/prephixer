## Prephixer.rb
# Created: January 6, 2013
# By: Ron Bowes
#
# This class implements a simple chosen plaintext attack against ciphers that
# use the Electronic Codebook mode (ECB). It requires a 'module', which
# implements a couple simple methods:
#
# NAME A constant representing the name of the module, used for output.
#
# block_size() [optional] The blocksize of whatever cipher is being used, in
# bytes (eg, # 16 for AES, 8 for DES, etc)
#
# do_encrypt(ciphertext) Attempt to decrypt the given data, and return true if
# there was no padding error and false if a padding error occured.
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

module Prephixer
  attr_accessor :verbose

  @@guesses = 0

  def Prephixer.guesses
    return @@guesses
  end

  def Prephixer.ord(c)
    if(c.is_a?(Fixnum))
      return c
    end
    return c.unpack('C')[0]
  end

  def Prephixer.generate_set(base_list)
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

  def Prephixer.to_blocks(data, block_size)
    block_count = data.length / block_size
    return data.unpack("a#{block_size}" * block_count)
  end

  def Prephixer.find_character(mod, current_plaintext, block_size, character_set)
    index = current_plaintext.size % block_size
    block =  current_plaintext.size / block_size
    prefix = ("A" * (block_size - (current_plaintext.size % block_size) - 1))

    goal = to_blocks(mod.encrypt_with_prefix(prefix), block_size)[block]

    character_set.each do |c|
      encrypted_text = mod.encrypt_with_prefix(prefix + current_plaintext + c)

      result = to_blocks(encrypted_text, block_size)[block]

      if(result == goal)
        return c
      end
    end
    return nil
  end

  def Prephixer.get_block_size(mod)
    if(mod.respond_to?(:block_size) && mod.block_size > 0)
      return mod.block_size
    end

    # Possible block sizes, ordered by size (smallest has to be first)
    possible_sizes = [ 4, 8, 16, 24, 32, 64, 128, 256 ]

    possible_sizes.each do |s|
      a = to_blocks(mod.encrypt_with_prefix(("A" * s) + "A"), s)[0]
      b = to_blocks(mod.encrypt_with_prefix(("A" * s) + "B"), s)[0]

      if(a == b)
        return s
      end
    end
  end

  def Prephixer.decrypt(mod, data, verbose = false)
    result = ''

    block_size = get_block_size(mod)

    # Validate the block_size
    if(data.length % block_size != 0)
      puts("Encrypted data isn't a multiple of the block size! Is this a block cipher?")
    end

    blockcount = data.length / block_size

    # Tell the user what's going on
    if(verbose)
      puts("> Starting Prephixer decrypter with module #{mod.class::NAME}")
      puts(">> Encrypted length: %d" % data.length)
      puts(">> Block size: %d" % block_size)
      puts(">> %d blocks:" % blockcount)
    end

    character_set = ' eationsrlhdcumpfgybw.k:v-/,CT0SA;B#G2xI1PFWE)3(*M\'!LRDHN_"9UO54Vj87q$K6zJY%?Z+=@QX&|[]<>^{}'.chars.to_a
    if(mod.respond_to?(:character_set))
      character_set = mod.character_set
    end
    character_set = generate_set(character_set)

    0.upto(data.length - 1) do |i|
      c = find_character(mod, result, block_size, character_set)
      break if(c.nil?)
      result = result + c

      if(verbose)
        puts(result)
      end
    end

    # 'Result' should have \x01 as padding, because of how the decryption works:
    # 00000000  45 76 65 72 79 74 68 69 6E 67 20 49 20 64 6F 01   Everything.I.do.
    # 00000010  45 76 65 72 79 74 68 69 6E 67 20 49 20 64 6F      Everything.I.do
    # Length: 0x1F (31)
    #
    # Validate it!
    if(ord(result[result.length - 1]) != 1)
      puts("Invalid padding on result: #{result.unpack("H*")}")
      exit
    end
    result = result[0, result.length - 1]

    return result
  end
end
