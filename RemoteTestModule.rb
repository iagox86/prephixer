##
# RemoteTestModule.rb
# Created: December 10, 2012
# By: Ron Bowes
##
#
require 'httparty'

class RemoteTestModule
  NAME = "RemoteTestModule(tm)"

  # Nothing is required to initialize
  def initialize()
  end

  def encrypt_with_prefix(prefix)
    result = HTTParty.get("http://localhost:20222/encrypt/#{prefix.unpack("H*").pop}")

    return [result.parsed_response].pack("H*")
  end

  def character_set()
    # Return the perfectly optimal string, as a demonstration
    return ' earnisoctldpukhmf,gSywb0.vWD21'.chars.to_a
  end
end

