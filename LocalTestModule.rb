## LocaltestModule.rb
# Created: December 10, 2012
# By: Ron Bowes
#
# A very simple application that's vulnerable to a padding oracle attack. It's
# initialized with data and a mode, and the decrypt() function will try to
# decrypt the given ciphertext with the given key.
##

require 'openssl'

class LocalTestModule
  attr_reader :ciphertext, :blocksize

  NAME = "LocalTestModule(tm)"

  def initialize(mode, data, key = nil, verbose = false)
    # Save these variables
    @mode = mode
    @verbose = verbose
    @data = data

    # Create the cipher
    c = OpenSSL::Cipher::Cipher.new(mode)

    # Set up the required variables
    @blocksize = c.block_size
    @key = key.nil? ? (1..c.key_len).map{rand(255).chr}.join : key

    # Set up the cipher
    c.encrypt
    c.key = @key

    @ciphertext = c.update(data) + c.final

    if(verbose)
      puts()
      puts("-" * 80)
      puts("Generated test data: #{data} (#{data.unpack("H*")})")
      puts("-" * 80)
      puts("mode: #{mode}")
      puts("key:  #{@key.unpack("H*")}")
      puts("enc:  #{@ciphertext.unpack("H*")}")
      puts("-" * 80)
    end
  end

  def encrypt_with_prefix(ciphertext)
    c = OpenSSL::Cipher::Cipher.new(@mode)
    c.encrypt
    c.key = @key
    return c.update(ciphertext + @data) + c.final()
  end
end

