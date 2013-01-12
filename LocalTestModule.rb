## LocaltestModule.rb
# Created: December 10, 2012
# By: Ron Bowes
#
##

require 'openssl'

class LocalTestModule
  attr_reader :ciphertext

  NAME = "LocalTestModule(tm)"

  def initialize(mode, data, key = nil, verbose = false, offset = nil)
    # Save these variables
    @mode = mode
    @verbose = verbose
    @data = data

    # Create the cipher
    c = OpenSSL::Cipher::Cipher.new(mode)

    # Set up the required variables
    @block_size = c.block_size
    @key = key.nil? ? (1..c.key_len).map{rand(255).chr}.join : key
    @offset = offset.nil? ? rand(64) : offset
    @offset_text = (1..@offset).map{rand(255).chr}.join

    # Set up the cipher
    c.encrypt
    c.key = @key

    @ciphertext = c.update(@offset_text + data) + c.final

    if(verbose)
      puts()
      puts(to_s())
      puts()
    end
  end

  def to_s()
    return ("-" * 80) + "\n" +
           ("Generated test data: #{@data} (#{@data.unpack("H*")})") + "\n" +
           ("-" * 80) + "\n" +
           ("mode:   #{@mode}") + "\n" +
           ("key:    #{@key.unpack("H*")}") + "\n" +
           ("enc:    #{@ciphertext.unpack("H*")}") + "\n" +
           ("prefix: #{@offset}") + "\n" +
           ("-" * 80) + "\n"
  end

  def encrypt_with_prefix(prefix)
    c = OpenSSL::Cipher::Cipher.new(@mode)
    c.encrypt
    c.key = @key
    return c.update(@offset_text + prefix + @data) + c.final()
  end
end

