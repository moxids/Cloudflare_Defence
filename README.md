# Cloudflare_Defence
Use GraphQL to grab Cloudflare firewall event, calculate the number of requests and submit exception IP to Access Rules

使用GraphQL获取防火墙事件，在本地统计异常IP，提交给Access Rules做出处理。
目前处于Beta测试阶段，还有大量的工作需要完成，Github仅发布Stable版本

# 项目优点
1. 可以脱离网站服务器，在任何地方做出反馈（未来可能会支持运行在容器服务中）
2. 不需要获取本地日志，节约资源
3. 当源站死后可以继续对攻击者IP进行处理，在最短的时间内重新上线
4. 封禁操作由Cloudflare执行，被封禁IP将不会对服务器造成任何资源损耗
5. 使用Access Rules做出拦截，不会影响到当前任何规则
6. 项目各操作仅需Free Plan即可完成，不花费一分钱

# 项目缺点
1. 必须使用Cloudflare接管
2. 涉及大量API操作，Cloudflare可能会不开心
3. 需要占用一个防火墙规则槽位，用于记录所有被放行请求
4. 因CN大陆环境对于Cloudflare支持并不友好，如果选择部署在该地的机器上可能会出现大量请求错误

# 使用教程

打开`main.py`并按照提示自定义配置

安装python3

运行`python main.py`

*项目允许无人执行





本项目欢迎提交Pr

Telegram: https://t.me/moxids

Telegram Channel: https://t.me/moxids_channel
