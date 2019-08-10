#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Created on Tue Jun 25 17:17:21 2019

"""
import os
import subprocess
import socket
import sys
import telnetlib
import time
import glob
import ConfigParser
from mon_util import mon_cmd

conf = ConfigParser.ConfigParser()
conf.read("project.config")

logdir_path = conf.get("main", "logdir_path")

panda_exe = conf.get("panda", "panda_exe")
image_path = conf.get("panda", "image_path")
guest_os = conf.get("panda", "guest_os")
rr_name = conf.get("panda", "rr_name")
wait_time = conf.getint("panda", "wait_time")
record_time = conf.getint("panda", "record_time")
monitor_port = conf.getint("panda", "monitor_port")
vnc_port = conf.getint("panda", "vnc_port")
attack_wrap_script = conf.get("panda", "attack_wrap_script")

record_args = [panda_exe,
               "-m", "4096M",
               "--monitor", "telnet:localhost:{0},server,nowait".format(monitor_port),
               "-netdev", "user,hostfwd=tcp::443-:443,id=mynet",
               "-device", "e1000,netdev=mynet",
               "-usbdevice", "tablet",
               "-vnc", ":{0}".format(vnc_port),
               image_path,
               ]

# 启动QEMU虚拟机,准备进行记录
print("Start the record process")
record_stdout = open(os.path.join(logdir_path, "record.stdout"), "w")
record_stderr = open(os.path.join(logdir_path, "record.stderr"), "w")
record = subprocess.Popen(record_args, stdin=subprocess.PIPE, stdout=record_stdout, stderr=record_stderr)

# 打印虚拟机vnc端口号
# host_ip = socket.gethostbyname(socket.getfqdn(socket.gethostname()))
print("Vnc of VM is on port {0}".format(5900 + vnc_port))

# 连接控制台
tries = 10
mon = None
for i in range(tries):
    try:
        print('Connecting to monitor, try {0}/{1}'.format(i, tries))
        mon = telnetlib.Telnet('localhost', monitor_port)
        break
    except socket.error:
        time.sleep(1)

if not mon:
    print("Couldn't connect to monitor on port {0}".format(monitor_port))
    sys.exit(1)
else:
    print("Successfully connected to monitor on port {0}".format(monitor_port))

# 等待提示
mon.read_until("(qemu)")

# 等待虚拟机完全启动，apache服务完全开启
print("Waiting {0} minutes for VM coming up...".format(wait_time/60))
time.sleep(wait_time)

# 清理上次记录的文件
for rr_file in glob.glob(os.path.join(os.getcwd(), rr_name + "-rr-*")):
    # print("Remove " + rr_file)
    os.unlink(rr_file)

# 需要远程访问https://222.20.79.157 事先填入用户名和密码(手动模拟环境)
print("Please visit the forum website and type in the username and password!")
tmp = raw_input("Being ready to record? Enter any key: ")

# 开启攻击(按框架图这里的攻击应该由bro控制，这里只是方便测试)
attack_args = ["python", attack_wrap_script]
attack = subprocess.Popen(attack_args, stdin=subprocess.PIPE, stdout=None, stderr=None)

# 开启记录
print("Begining the record")
mon_cmd("begin_record " + rr_name + "\n", mon)
time.sleep(2)

## 按下登录按钮
#print("Please click on the Login button!")
#time.sleep(2)

# 等待记录
print("Recording...")
time.sleep(record_time)

## 关闭攻击
attack.kill()

# 结束记录
print("Ending the record")
mon_cmd("end_record\n", mon)
time.sleep(10)
mon_cmd("q\n", mon)
mon.write("q\n")
print("Recording is completed!")


replay_args = [panda_exe,
               "-m", "4096M",
               "-netdev", "user,id=mynet",
               "-device", "e1000,netdev=mynet",
               "-usbdevice", "tablet",
               "-replay", rr_name,
               "-os", guest_os,
               "-panda", "stringsearch:name=keyword",
               "-panda", "tstringsearch",
               "-panda", "tainted_net:query_outgoing_network=true,file=keyword_tainted.csv",
               "-panda", "jsonlog:name=panda",
               ]

# 进行重放分析
print("Start the replay process")
replay_stdout = open(os.path.join(logdir_path, "replay.stdout"), "w")
replay_stderr = open(os.path.join(logdir_path, "replay.stderr"), "w")
replay = subprocess.Popen(replay_args, stdin=subprocess.PIPE, stdout=sys.stdout, stderr=sys.stderr)
print("Analysing...")
replay.wait()

# 清除上次的分析日志
replay_log = os.path.join(logdir_path, "panda.json")
if os.path.exists(replay_log):
    os.unlink(replay_log)

# 拷贝生成的分析结果日志到指定目录
replay_log = os.path.join(os.getcwd(), "panda.json")
if os.path.exists(replay_log):
    cp_cmd = "cp " + replay_log + " " + logdir_path
    os.system(cp_cmd)
    print("Replay analysing is completed")
else:
    print("Replay analysing is failed")


