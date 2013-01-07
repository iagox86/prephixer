$LOAD_PATH << File.dirname(__FILE__) # A hack to make this work on 1.8/1.9

##
# RemoteTestServer
# Created: December 10, 2012
# By: Ron Bowes
#
# A very simple application that is vulnerable to a ECB chosen prefix attack.
##

require 'openssl'
require 'sinatra'

set :port, 20222

# Note: Don't actually generate keys like this!
@@key = (1..32).map{rand(255).chr}.join
@@iv  = (1..32).map{rand(255).chr}.join
TEXT = "SkullSpace is a hackerspace in Winnipeg, founded December 2010. SkullSpace is a place for hackers, builders, programmers, artists, and anybody interested in how stuff works to gather in a common place and help focus their knowledge and creativity."
MODE = "AES-256-CBC"

get('/get_encrypted_data')do
  c = OpenSSL::Cipher::Cipher.new(MODE)
  c.encrypt
  c.key = @@key
  c.iv  = @@iv

  encrypted = (c.update(TEXT) + c.final).unpack("H*")
  puts("Encrypted data: #{encrypted}")
  return encrypted
end

get(/\/encrypt\/([a-fA-F0-9]*)$/) do |prefix|
  c = OpenSSL::Cipher::Cipher.new(MODE)
  c.encrypt
  c.key = @@key

  prefix = [prefix].pack("H*")

  encrypted = ''
  if(prefix.length > 0)
    encrypted +=c.update(prefix)
  end
  encrypted +=c.update(TEXT)
  encrypted += c.final()

  return encrypted.unpack("H*")
end

