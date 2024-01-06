# 使用官方 OpenJDK 17 镜像作为基础镜像
FROM openjdk:17-jdk-alpine

# 设置工作目录
WORKDIR /app

# 将编译好的 JAR 文件复制到容器中
COPY build/libs/user-service.jar .

# 暴露应用程序的端口
EXPOSE 8080

# 定义默认的启动命令
CMD ["java", "-jar", "user-service.jar"]
