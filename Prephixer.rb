## Prephixer.rb
# Created: January 6, 2013
# By: Ron Bowes
#
# This class implements a simple chosen plaintext attack against block ciphers
# that use electronic codebook (ECB) or cipherblock chaining (CBC) modes. This
# is done by inserting known plaintext strings into the ciphertext, and
# analyzing the resulting ciphertext.  It requires an encryption oracle that
# returns E(k, u || a || s), where 'k' is an unknown key, 'u' is unknown data
# of an arbitrary length (possibly 0 bytes), 'a' is attacker-controlled data,
# and 's' is the secret data that will be encrypted.
#
# This is done by manipulating 'a' such that the first character of 's' falls
# right before a block boundary, and can therefore be narrowed down to 256
# possible guesses.
#
# To use this module, a module must be created that implements the interface to
# the oracle. This module must implement a couple simple methods:
#
# NAME A constant representing the name of the module, used for output.
#
# block_size() [optional] The blocksize of whatever cipher is being used, in
# bytes (eg, # 16 for AES, 8 for DES, etc). Prephixer will automatically
# determine the blocksize if it's not given.
#
# encrypt_with_prefix(ciphertext) Attempt to decrypt the given data, and return
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

module Prephixer
  attr_accessor :verbose

  # Implement an ord() function that works in both Ruby 1.8 and Ruby 1.9
  def Prephixer.ord(c)
    if(c.is_a?(Fixnum))
      return c
    end
    return c.unpack('C')[0]
  end

  # Take a base_list, and add every charcter not already in the list
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

  # Divide the given data into blocks of size "block_size", as an array. The
  # last block is shorter if the total length of data isn't a multiple of the
  # requested blocksize.
  def Prephixer.to_blocks(data, block_size)
    block_count = data.length / block_size
    return data.unpack("a#{block_size}" * block_count)
  end

  # Determine the next character in the string
  def Prephixer.find_character(mod, current_plaintext, block_size, character_set, offset, padding)
    # Figure out the current index within the block
    index = current_plaintext.size % block_size

    # Figure out the current block within the plaintext
    block = current_plaintext.size / block_size

    # Generate a prefix based on:
    # 1. padding, which ensures that we're starting on a block boundary
    # 2. a bunch of "A"s, specifically, enough to put the next unknown character
    #    right before a boundary
    prefix = padding + ("A" * (block_size - (current_plaintext.size % block_size) - 1))

    # Figure out the 'goal' - that is, what the the block (known_data || unknown_character)
    # encrypts to
    goal = to_blocks(mod.encrypt_with_prefix(prefix), block_size)[block + offset]

    # Now, try each of the 256 characters - ordered by character_set - to determine which of
    # them encrypts to the same as the goal (therefore telling us the next byte)
    character_set.each do |c|
      # Encrypt the block with our current plaintext character
      encrypted_text = mod.encrypt_with_prefix(prefix + current_plaintext + c)

      # Divide the result into blocks
      result = to_blocks(encrypted_text, block_size)[block + offset]

      # Check if the block we're currently working on matches the goal
      if(result == goal)
        return c
      end
    end

    # If we fail - or we're at the end - return nil
    return nil
  end

  # Figure out what the blocksize of the encryption algorithm is - either by
  # using one that the module provides, or by adding character slowly until the
  # size of the encrypted data changes
  def Prephixer.get_block_size(mod)
    # Check if the module has a block_size argument, and simply use it if it does
    if(mod.respond_to?(:block_size) && mod.block_size > 0)
      return mod.block_size
    end

    # Get the original size - with no encrypted data
    old_size = mod.encrypt_with_prefix("").length

    # Try to add anywhere between 4 and 64 characters until it changes (every
    # algorithm I know of has either a 8 or 64-bit blocksize)
    1.step(64, 4) do |i|
      # Get the new size
      new_size = mod.encrypt_with_prefix("A" * i).length

      # When the size changes, return the difference
      if(new_size != old_size)
        return new_size - old_size
      end
    end
  end

  # Compare two strings and return the first index where they differ
  def Prephixer.str_diff(a, b)
    if(a.length != b.length)
      raise("Strings are different lengths!")
    end

    0.upto(a.length - 1) do |i|
      return i if(a[i] != b[i])
    end

    return -1
  end

  # Returns two values: the first is the number of the block we need to start
  # checking at, and the second is the prefix that needs to be attached to
  # the start of every request
  def Prephixer.get_offset(mod, block_size)
    # First, figure out the first block that we control
    a = mod.encrypt_with_prefix("A" * (block_size * 2))
    b = mod.encrypt_with_prefix("B" * (block_size * 2))
    orig_offset = str_diff(a, b) / block_size

    # Now, add 'A's to the start until we get a matching block, since at that point we
    # know where the block boundary is
    0.upto(block_size * 2) do |i|
      b = mod.encrypt_with_prefix(("A" * i) + ("B" * ((block_size * 2) - i)))
      new_offset = str_diff(a, b) / block_size

      if(new_offset != orig_offset)
        return new_offset, "X" * i
      end
    end
  end

  # This is the main interface into Prephixer - it decrypts the data based on the
  # module given as the 'mod' parameter.
  #
  # has_padding is a little tricky - ECB and CBC mode wind up with padding,
  # and CTR mode does not, just by nature of how they're decrypted. You'll
  # get an error if you set has_padding = true on a cipher that doesn't, and you'll
  # get a "\x01" byte at the end of your string if you set has_padding = false when
  # there is supposed to be padding. Good luck!
  def Prephixer.decrypt(mod, has_padding = true, verbose = false)
    result = ''

    block_size = get_block_size(mod)
    #puts("block_size = #{block_size}")
    offset, prefix = get_offset(mod, block_size)

    # Tell the user what's going on
    if(verbose)
      puts("> Starting Prephixer decrypter with module #{mod.class::NAME}")
      puts(">> Block size: %d" % block_size)
    end

    # This is the default character ordering, based on the Battlestar Galactica wiki
    character_set = ' eationsrlhdcumpfgybw.k:v-/,CT0SA;B#G2xI1PFWE)3(*M\'!LRDHN_"9UO54Vj87q$K6zJY%?Z+=@QX&|[]<>^{}'.chars.to_a
    # If the module has a character_set() method, use it to get the optimal character set
    if(mod.respond_to?(:character_set))
      character_set = mod.character_set
    end
    # Fill in the gaps in the character set
    character_set = generate_set(character_set)

    # Keep looping will we runo ut of characters
    loop do
      # Find the next character
      c = find_character(mod, result, block_size, character_set, offset, prefix)

      # Break if we're at the end
      break if(c.nil?)

      # Add the character to the result
      result = result + c

      # Print the character if we're in verbose mode
      if(verbose)
        puts(result)
      end
    end

    # Fail ifno bytes were decrypted
    if(result.length == 0)
      raise("Failed to decrypt any bytes")
    end

    if(has_padding)
      # 'Result' should have \x01 as padding, because of how the decryption works - at the
      # point where we're bruteforcing the padding, there will be exactly blocksize-1 character
      # at the end, and therefore one byte of padding.
      #
      # 00000000  45 76 65 72 79 74 68 69 6E 67 20 49 20 64 6F 01   Everything.I.do.
      # 00000010  45 76 65 72 79 74 68 69 6E 67 20 49 20 64 6F      Everything.I.do
      # Length: 0x1F (31)
      #
      # Validate it!
      if(ord(result[result.length - 1]) != 1)
        raise("Invalid padding on result: #{result.unpack("H*")}")
      end

      # Remove the one byte of padding
      result = result[0, result.length - 1]
    end

    return result
  end
end
