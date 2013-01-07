$LOAD_PATH << File.dirname(__FILE__) # A hack to make this work on 1.8/1.9

require 'benchmark'
require 'openssl'

require 'LocalTestModule'
require 'RemoteTestModule'
require 'ECBreaker'

if(ARGV[0] == 'remote')
  # Attempt a remote check
  puts("Starting remote test (this requires RemoteTestServer.rb to be running on localhost:20222)")
  begin
    mod = RemoteTestModule.new

    time = Benchmark.measure do
      puts ECBreaker.decrypt(mod, mod.data, true)
    end

    puts("Guesses: #{ECBreaker.guesses}")
    puts("Time: #{time}")

  rescue Errno::ECONNREFUSED => e
    puts(e.class)
    puts("Couldn't connect to remote server: #{e}")
  end
end

# Perform local checks
ciphers = OpenSSL::Cipher::ciphers - OpenSSL::Cipher::ciphers.grep(/cfb|ofb|rc4/i)
srand(123456)

passes = 0
failures = 0

# Do a bunch of very short strings
(0..64).to_a.each do |i|
  data = (0..rand(100)).map{rand(255)}.join
  cipher = ciphers.shuffle[0]
  print("> #{cipher} with random short data... ")
  mod = LocalTestModule.new(cipher, data, nil, nil)
  d = ECBreaker.decrypt(mod, mod.ciphertext)
  if(d == data)
    passes += 1
    puts "Passed!"
  else
    failures += 1
    puts "Failed!"
    exit
  end
end

# Try the different ciphers
ciphers.each do |cipher|
  (0..64).to_a.shuffle[0, 8].each do |i|
    print("> #{cipher} with random data (#{i} bytes)... ")

    data = (0..i).map{(rand(0x7E - 0x20) + 0x20).chr}.join
    mod = LocalTestModule.new(cipher, data)
    d = ECBreaker.decrypt(mod, mod.ciphertext, false)
    if(d == data)
      passes += 1
      puts "Passed!"
    else
      failures += 1
      puts "Failed!"
    end
  end
end

puts("Ciphers tested: #{ciphers.join(", ")}")
puts("Tests passed: #{passes}")
puts("Tests failed: #{failures}")


