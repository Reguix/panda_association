#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Created on Wed Jun 26 21:47:50 2019

"""
import subprocess
import sys
import time
import ConfigParser

conf = ConfigParser.ConfigParser()
conf.read("project.config")

# attack_wrap_script = conf.get("panda", "attack_wrap_script")
decaf_script = conf.get("decaf", "decaf_script")
decaf_log = conf.get("decaf", "decaf_log")
association_script = conf.get("association", "association_script")
panda_log = conf.get("association", "panda_log")
eip_log = conf.get("mdump", "eip_log")
mdump_script = conf.get("mdump", "mdump_script")
mdump_log = conf.get("mdump", "mdump_log")
mdump_pm = conf.get("mdump", "mdump_pm")
association_log = conf.get("association", "association_log")

# 开启HTTP服务器及攻击
print("""
##########################################
#              Task 5                    #
##########################################
""")
print("Http server at port 8000")
http_server_args = ["nohup","python", "-m","SimpleHTTPServer" ,"8000", "&"]
http_server = subprocess.Popen(http_server_args, stdin=None, stdout=None, stderr=None)
time.sleep(5)

# attack_args = ["python", attack_wrap_script]
# attack = subprocess.Popen(attack_args, stdin=None, stdout=None, stderr=None)

# 调用decaf
print("""
##########################################
#         Data Flow Trace Analyse        #
##########################################
""")
# decaf_args = ["echo", "decaf pass"]
decaf_args = ["python", decaf_script]
decaf = subprocess.Popen(decaf_args, stdin=sys.stdin, stdout=sys.stdout, stderr=sys.stderr)
decaf.wait()

## 调用panda
print("""
##########################################
#         Record & Replay Analyse        #
##########################################
""")
panda_args = ["python", "panda.py"]
# panda_args = ["echo", "panda pass"]
panda = subprocess.Popen(panda_args, stdin=sys.stdin, stdout=sys.stdout, stderr=sys.stderr)
panda.wait()

# 第一阶段关联分析
print("""
##########################################
#          Association Analyse 1         #
##########################################
""")
association_1_args = ["python", "association.py",
                      "--step", "1",
                      "--panda", panda_log,
                      "--decaf", decaf_log,
                      "--generate", eip_log]
association_1 = subprocess.Popen(association_1_args, stdin=sys.stdin, stdout=sys.stdout, stderr=sys.stderr)
association_1.wait()
print("Association Analysing 1 is completed")

# 调用mdump
print("""
##########################################
#     Successive Memory Image Analyse    #
##########################################
""")
# mdump_args = ["echo", "mdump pass"]
mdump_args = ["python", mdump_script, "-f", eip_log, "-d", mdump_log, "-pm", mdump_pm]
mdump = subprocess.Popen(mdump_args, stdin=sys.stdin, stdout=sys.stdout, stderr=sys.stderr)
mdump.wait()
# attack.kill()

# 第二阶段关联分析
print("""
##########################################
#         Association Analyse 2          #
##########################################
""")
association_2_args = ["python", association_script,
                      "--step", "2",
                      "--panda", panda_log,
                      "--decaf", decaf_log,
                      "--mdump", mdump_log,
                      "--generate", association_log]
association_2 = subprocess.Popen(association_2_args, stdin=sys.stdin, stdout=sys.stdout, stderr=sys.stderr)
association_2.wait()
print("Association Analysing 2 is completed")
