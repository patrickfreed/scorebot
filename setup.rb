#!/usr/bin/ruby

require 'rubygems'
require 'net/ssh'
require 'net/scp'

INSTALL_SCRIPT_DIR = "/opt/install_scripts/"

def get_hostonly_ip(name)
  line = `VBoxManage guestproperty enumerate #{name} | grep eth2`

  if line =~ /^Name: (.*)\/Name, value: eth2/
    return `VBoxManage guestproperty get #{name} #{$1}/V4/IP | awk '{ print $2 }'`.strip
  end

  return "0.0.0.0"
end

def execute_remote_cmd(ip, cmd)
  Net::SSH.start(ip, "root", :password => "pdsfassword") { |ssh|
    ssh.exec!("#{cmd}")
  }
  #system("ssh -t root@#{ip} #{cmd}")
end

def execute_remote_script(ip, path_to_script, script_name)
  Net::SCP.start(ip, "root", :password => "using ssh keys") { |scp|
    scp.upload!(path_to_script, INSTALL_SCRIPT_DIR + script_name)
  }
  
  Net::SSH.start(ip, "root", :password => "using ssh keys") { |ssh|
    ssh.exec!("chmod +x #{INSTALL_SCRIPT_DIR + script_name}")
    ssh.exec!(INSTALL_SCRIPT_DIR + script_name) { |ch, stream, data|
      if stream == :sdout
        puts data
      else
        system("echo #{data} >> /home/patrick/error.log")
      end
    }
    ssh.exec!("rm #{INSTALL_SCRIPT_DIR + script_name}")
  }
end

def assign_ip(hostonly_ip, interface, address, netmask, gateway)
  execute_remote_cmd(hostonly_ip, "echo -e \"auto #{interface}\niface #{interface} inet static\naddress #{address}\nnetmask #{netmask}\ngateway #{gateway}\" >> /etc/network/interfaces")
  execute_remote_cmd(hostonly_ip, "/etc/init.d/networking restart")
  execute_remote_cmd(hostonly_ip, "ifup #{interface}")
end

basic_vulns_file = open("b_vulns.txt")
basic_vulns = Hash.new()

while line = basic_vulns_file.gets do
  if line =~ /^vuln_name: (.*)$/
	vuln = Array.new()
	vuln[0] = $1
    
    next_line = basic_vulns_file.gets
    vuln[1] = /^\tvuln_check: (.*)$/.match(next_line)[1]
    
    next_line = basic_vulns_file.gets
    vuln[2] = /^\tvuln_install: (.*)$/.match(next_line)[1]
    
    next_line = basic_vulns_file.gets
	vuln[3] = /^\tvuln_points: ([0-9]*)$/.match(next_line)[1].to_i
    
	basic_vulns[vuln[0]] = vuln
  end
end

basic_vulns_file.close()
hosts_file = open("hosts.txt")

while line = hosts_file.gets do
  if line =~ /^hostname: (.*)$/
    name = $1

    next_line = hosts_file.gets
    os = /^\tos: (.*)$/.match(next_line)[1]

    if os == "UBUNTU"
      print "Creating host \"#{name}\""
      #system("VBoxManage clonevm ubuntu-gi --name #{name}")
      print "\n"
      #system("VBoxManage startvm #{name}")
    end

    hostonly_ip = get_hostonly_ip(name)
    assign_ip(hostonly_ip, "eth2", hostonly_ip, "255.255.255.0", "192.168.56.1")
    puts "Hostonly ip: #{hostonly_ip}"

    execute_remote_cmd(hostonly_ip, "mkdir #{INSTALL_SCRIPT_DIR}")
    
    next_line = hosts_file.gets
    if next_line =~ /^\tip: ([0-9]*\.[0-9]*\.[0-9]*\.[0-9]*)$/
      ip = $1
      assign_ip(hostonly_ip, "eth1", ip, "255.255.255.0", "192.168.1.1")
    else
      ip = "INVALID_IP"
    end

    next_line = hosts_file.gets
    h_vulns = /^\tvulns: \[ (?:"(.*)")* \]$/.match(next_line).captures

    h_vulns.each { |vuln|
      puts "Installing vulnerability #{vuln}..."
      execute_remote_script(hostonly_ip, basic_vulns[vuln][2], vuln)
    }
    
    next_line = hosts_file.gets
    h_services = /^\tservices: \[ (?:"(.*)")* \]$/.match(next_line).captures
    
    next_line = hosts_file.gets
    uptime_points = /^\tuptime_points: (\d*)$/.match(next_line)[1].to_i
  end
end
