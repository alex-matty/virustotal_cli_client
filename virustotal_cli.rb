#!/usr/bin/ruby

# Trying to create an CLI for virustotal using ruby

# Required libraries (Research what these two do)
require 'uri'
require 'net/http'

#Global variables
$api_key = 'API-KEY'


# -------------------- IP address function -------------------- 
# Function for full IP address report 
def ip_address_report(ip)
	uri = URI("https://www.virustotal.com/api/v3/ip_addresses/#{ip}")
	req = Net::HTTP::Get.new(uri)
	req['x-apikey'] = $api_key

	res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == 'https') { 
		|http|
		http.request(req)
	}

	puts res.body
end

# -------------------- Domain function --------------------
# Function for full domain report
def domain_report(domain_to_check)
	uri = URI("https://www.virustotal.com/api/v3/domains/#{domain_to_check}")
	req = Net::HTTP::Get.new(uri)
	req['x-apikey'] = $api_key

	res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == 'https') { 
		|http|
		http.request(req)
	}

	puts res.body
end
# -------------------- Hash address function --------------------
# Function for full domain report
def hash_report(hash_to_check)
	uri = URI("https://www.virustotal.com/api/v3/files/#{hash_to_check}")
	req = Net::HTTP::Get.new(uri)
	req['x-apikey'] = $api_key

	res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == 'https') { 
		|http|
		http.request(req)
	}

	puts res.body
end

# Define menu function to print it every time so we can create a loop
def menu
	#Option Menu displayed for user
	menu = "[1] IP Report
[2] Domain Report
[3] Hash Report
[0] Exit"
	puts menu
end

# Print welcome message and menu
puts "virustotal IP lookup".upcase

cycle = 'open'

while cycle == 'open'
	menu()
	print 'Select option: '
	option = gets.chomp.to_i

	if option == 1
		print "IP: "
		IP = gets.chomp
		ip_address_report(IP)
	elsif option == 2
		print "Domain: "
		domain = gets.chomp
		domain_report(domain)
	elsif option == 3
		print 'Hash: '
		user_hash = gets.chomp
		hash_report(user_hash)
	elsif option == 0
		exit
		cycle = closed
	end
end
