# -*- coding: utf-8 -*-
"""
Created on Wed Jun 26 08:44:22 2019

"""
import subprocess
import os
import time
import ConfigParser

conf = ConfigParser.ConfigParser()
conf.read("project.config")

logdir_path = conf.get("main", "logdir_path")

attack_script = conf.get("attack", "attack_script")
agent_ip = conf.get("attack", "agent_ip")
attack_port = conf.getint("attack", "attack_port")
attack_period = conf.getfloat("attack", "attack_period")

# 攻击(按框架图这里的攻击应该由bro控制，这里只是方便测试)
attack_args = ["python", attack_script, agent_ip, "-p", str(attack_port)]
attack_stdout = open(os.path.join(logdir_path, "attack.stdout"), "w")
attack_stderr = open(os.path.join(logdir_path, 'attack.stderr'), "w")
attack_stdout.close()
attack_stderr.close()
attack_stdout = open(os.path.join(logdir_path, "attack.stdout"), "a")
attack_stderr = open(os.path.join(logdir_path, 'attack.stderr'), "a")
while True:
    attack = subprocess.Popen(attack_args, stdin=None, stdout=attack_stdout, stderr=attack_stderr)
    attack.wait()
    time.sleep(attack_period)
    
    
