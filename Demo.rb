##
# RemoteTestModule.rb
# Created: December 10, 2012
# By: Ron Bowes
##
#
require 'httparty'
require './prephixer'

class DemoModule
  NAME = "DemoModule(tm)"

  # Nothing is required to initialize
  def initialize()
  end

  # Encrypt the data and get the result
  def encrypt_with_prefix(prefix)
    result = HTTParty.get("http://localhost:20222/encrypt/#{prefix.unpack("H*").pop}").parsed_response

    # TODO: Extract the result from the page

    return [result].pack("H*")
  end

  # (optional) define the best possible set of characters for the expected data
  # to speed things up
  def character_set()
    return ' eationsrlhdcumpfgybw.k:v-/,CT0SA;B#G2xI1PFWE)3(*M\'!LRDHN_"9UO54Vj87q$K6zJY%?Z+=@QX&|[]<>^{}'.chars.to_a
  end
end

mod = DemoModule.new
Prephixer.decrypt(mod, true, true)

