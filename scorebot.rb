#!/usr/bin/ruby

require 'open3'

class Game

  def execq(cmd)
    val = 1
    Open3.popen3(cmd) { |stdin, stdout, stderr, wait_thr|
      val = wait_thr.value.exitstatus
    }
    return val == 0
  end
  
  def award_points(hash, points, reason)
    team = @player_hash[hash][0]
    @player_hash[hash][1] = @player_hash[hash][1] + points
    
    if (points < 0)
      puts "#{team} lost #{-1 * points} points for #{reason}"
      IO.write(@ticker_file, "#{@player_hash[hash][0]} lost #{-1 * points} points for #{reason}\n", mode: 'a')
    else
      puts "#{team} earned #{points} points for #{reason}"
      IO.write(@ticker_file, "#{@player_hash[hash][0]} earned #{points} points for #{reason}\n", mode: 'a')
    end
  end

  def is_host_up?(ip)
    return execq("ping -c4 -i0.2 -w1 #{ip}")
  end
  
  def get_owner_hash(ip)
	if (execq("scp -q user@#{ip}:~/flag.txt ."))
	  return IO.read("flag.txt", 6)
	end
    
	return -1.to_s
  end

  def initialize()
    puts "------------------------"
    puts "|     Scorebot 1.0     |"
    puts "------------------------"
    
    hosts_file = open("hosts.txt")  
    basic_vulns_file = open("b_vulns.txt")
    player_hash_file = open("p_hash.txt")

    @ticker_file = "/cyberfront/scoring/ticker.txt"
    @score_file = "/cyberfront/scoring/leaderboard.txt"
    
    @hosts = Hash.new()
    @basic_vulns = Hash.new()
    @player_hash = Hash.new()
    @player_scores = Hash.new()
    
    while line = player_hash_file.gets do
	  if line =~ /^team_name: (.*) team_hash: (.*)$/
		@player_hash[$2] = [$1, 0]
        @player_scores[$2] = 0
      end
    end
    
    player_hash_file.close()
    puts "Loaded #{@player_hash.length()} team hash(es)!"
    
    while line = basic_vulns_file.gets do
	  if line =~ /^vuln_name: (.*)$/
		vuln = Array.new()
		vuln[0] = $1
        
        next_line = basic_vulns_file.gets
        vuln[1] = /^\tvuln_check: (.*)$/.match(next_line)[1]
        
        next_line = basic_vulns_file.gets
        vuln[2] = /^\tvuln_expected_output: (.*)$/.match(next_line)[1]

        next_line = basic_vulns_file.gets
		vuln[3] = /^\tvuln_points: ([0-9]*)$/.match(next_line)[1].to_i
        
		@basic_vulns[vuln[0]] = vuln
	  end
    end
    
    basic_vulns_file.close()
    puts "Loaded #{@basic_vulns.length()} vulnerabilities!"

    while line = hosts_file.gets do
      if line =~ /^hostname: (.*)$/
	    name = $1
        @hosts[name] = Array.new()
        
        next_line = hosts_file.gets
        
        if next_line =~ /^\tip: ([0-9]*\.[0-9]*\.[0-9]*\.[0-9]*)$/
          @hosts[name][0] = $1
        else
          @hosts[name][0] = "INVALID_IP"
        end
        
        next_line = hosts_file.gets
        h_vulns = /^\tvulns: \[ (?:"(.*)")* \]$/.match(next_line).captures

        @hosts[name][1] = Array.new()
        h_vulns.each { |vuln_name|
          @hosts[name][1] << [vuln_name, false]
        }
        
        next_line = hosts_file.gets
        h_services = /^\tservices: \[ (?:"(.*)")* \]$/.match(next_line).captures
        @hosts[name][2] = h_services

        next_line = hosts_file.gets
        @hosts[name][3] = /^\tuptime_points: (\d*)$/.match(next_line)[1].to_i
      end
    end
    
    hosts_file.close()
    puts "Loaded #{@hosts.length()} host(s)!"
    puts "----- Init Complete -----"
  end
  
  def score_update()
    puts "\n==== Score Update ===="
        
    @hosts.each { |hostname, data|
      ip = data[0]
      changed = false
      
      if (!is_host_up?(ip))
        puts "#{hostname} is down!"
        next
      end
      
      if ((hash = get_owner_hash(ip)) != -1.to_s)
	    #puts "#{hostname} is owned by #{@player_hash[hash][0]}!"

        award_points(hash, data[3], "controlling host #{hostname}")
        
	    data[1].each { |vuln_data|
          vuln_name = vuln_data[0]
          vuln_patched = vuln_data[1]
          
          vuln = @basic_vulns[vuln_name]
          
          if (!execq(vuln[1]))
            if (!vuln_patched)
              award_points(hash, vuln[3], "patching #{vuln[0]} on host #{hostname}")
              changed = true
              vuln_data[1] = true
            end
          elsif (vuln_patched)
            award_points(hash, -1 * vuln[3], "exposing #{vuln[0]} on host #{hostname}")
            vuln_data[1] = false
            changed = true
          end
        }
      end

      if (changed = true)
        score = ""
        scores = Array.new()

        @player_hash.each { |hash, data|
          scores << [data[1], data[0]]
        }

        scores.sort!()

        scores.each { |score_d|
          score += "#{score_d[1]}\t#{score_d[0]}\n"
        }

        IO.write(@score_file, score)
      end
      
    }

    puts "======================"
  end

  def print_game_setup()
    puts "\nGame setup:"
    puts @player_hash.to_s
    puts @basic_vulns.to_s
    puts @hosts.to_s
  end
  
end

g = Game.new()

while gets.to_i != -1
  g.score_update()
end
