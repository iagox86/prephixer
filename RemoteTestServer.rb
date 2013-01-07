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
TEXT = "SkullSpace is a hackerspace in Winnipeg, founded December 2010. SkullSpace is a place for hackers, builders, programmers, artists, and anybody interested in how stuff works to gather in a common place and help focus their knowledge and creativity."

get('/get_encrypted_data')do
  c = OpenSSL::Cipher::Cipher.new("AES-256-ECB")
  c.encrypt
  c.key = @@key

  return (c.update(TEXT) + c.final).unpack("H*")
end

get(/\/encrypt\/([a-fA-F0-9]*)$/) do |prefix|
#get /\/decrypt\/([a-fA-F0-9]+)$/ do |data|
  c = OpenSSL::Cipher::Cipher.new("AES-256-ECB")
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

