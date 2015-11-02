def get_owner_hash(ip)
	if (system("scp user@#{ip}:~/flag.txt ."))
		return IO.read("flag.txt", 6)
	end

	return -1.to_s
end

puts "Scorebot 1.0"

puts "Loading basic vulnerabilities..."

hosts_file = open("hosts.txt")
hosts = Hash.new()

basic_vulns_file = open("b_vulns.txt")
basic_vulns = Array.new()

player_hash_file = open("p_hash.txt")
player_hash = Hash.new()

while line = hosts_file.gets do
	if line =~ /^hostname: (.*) ip: ([0-9]*\.[0-9]*\.[0-9]*\.[0-9]*)$/
		hosts[$1] = $2
	end
end

hosts_file.close()

while line = player_hash_file.gets do
	if line =~ /^team_name: (.*) team_hash: (.*)$/
		player_hash[$2] = $1
	end
end

player_hash_file.close()

while line = basic_vulns_file.gets do
	if line =~ /^vuln_name: (.*) vuln_check: (.*) vuln_expected_output: (.*) vuln_points: ([0-9]*)$/
		vuln = Array.new()
		vuln[0] = $1
		vuln[1] = $2
		vuln[2] = $3
		vuln[3] = $4.to_i
		basic_vulns << vuln
	end
end

basic_vulns_file.close()
x = 1
while (x == 1)
	hosts.each { |hostname, ip|
		if ((hash = get_owner_hash(ip)) != -1.to_s)
			puts "#{hostname} is owned by #{player_hash[hash]}!"
			
			basic_vulns.each { |vuln|
				puts vuln[1]
				if (!system(vuln[1]))
					puts "#{player_hash[hash]} earned #{vuln[3]} points for patching #{vuln[0]} on host #{hostname}"
				end			
			}
		end
	}
	x += 1
end

puts player_hash.to_s
puts basic_vulns.to_s
puts hosts.to_s
