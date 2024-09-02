##!/usr/bin/expect -f
scp $1/build/libs/authorization-server-0.0.1-SNAPSHOT.jar root@152.136.167.59:/root/prod

# 设置超时时间为30秒
#set timeout 30

# 设置需要传输的文件路径和远程服务器的登录信息
#set src_file "/Users/xuhongzhi/studen/ocpx/piao888-service/piao888-storage/build/libs/piao888-storage-0.0.1-SNAPSHOT.jar"
#set user "root"
#set host "152.136.167.59"
#set target_path "root@152.136.167.59:/root/prod/"
#set password "Kshanpao8848"

# 执行SCP命令
#spawn scp $src_file $target_path

# 等待密码提示
#expect "password:"

# 发送密码
#send "$password\r"

# 等待SCP传输完成
#expect eof

# 结束

