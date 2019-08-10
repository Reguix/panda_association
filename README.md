### 安装

1. 下载安装panda及association

   ```shell
   git clone https://gitee.com/lwmhust/task-5.git
   cd task-5/panda_association
   sudo ./install.sh
   ```
2. 将镜像文件拷贝或下载到task-5/panda_association/images/

### 操作

1. 配置project.config里面的参数，需要修改[mdump]，[decaf]下的参数，其余参数默认就能正常使用：

   ```
   [main]
   logdir_path = log
   
   [panda]
   panda_exe = build-panda/i386-softmmu/qemu-system-i386
   image_path = images/cn_windows_xp_sp3_x86_heartbleed.qcow2
   guest_os = windows-32-xpsp3
   rr_name = winxpsp3x86_heartbleed
   attack_wrap_script = attack_wrap.py
   wait_time = 360
   record_time = 15
   monitor_port = 7377
   vnc_port = 8
   
   [attack]
   attack_script = ssltest.py
   agent_ip = localhost
   attack_port = 443
   attack_period = 0.1
   
   [association]
   association_script = association.py
   decaf_log = log/decaf.json
   panda_log = log/panda.json
   association_log = log/association.json
   
   [mdump]
   mdump_script = /home/cll/pyrebox_mdump/mdump_start.py
   eip_log = /home/cll/pyrebox_mdump/pyrebox_1/EIP.csv
   mdump_log = /home/cll/pyrebox_mdump/pyrebox_1/log/memdump_result.json
   mdump_log_dir = /home/cll/pyrebox_mdump/pyrebox_1/log/
   mdump_pm = /home/cll/pyrebox_mdump/pyrebox_1/
   
   [decaf]
   ```

2. 运行如下命令：

   ```shell
   cd task-5/panda_association
   sudo python main.py
   ```

3. 等待终端上出现如下提示：

   ```
   Please visit the forum website and type in the username and password!
   Being ready to record? Enter any key: 
   ```

   用chrome浏览器访问**https://服务器ip/bbs**， 在网站右上角填入用户名和密码，然后在终端里输入回车。

   等到终端出现提示如下提示，在浏览器网站中点击登录。

   ```
   Begining the record
   Recording...
   ```

4. 等待全部分析完毕。