# xdp_banner

一个简单的 XDP 小程序，用于防止目标 IP 的访问。

## 功能介绍

**该程序目前提供了以下几个功能**：

1. 支持通过文件配置 IPv4 / IPv6 CIDR 块黑名单（按照 banned_ipv4 中给出的注释配置即可）
2. 支持临时黑名单，以根据需求灵活地封禁 IP（黑名单默认每 30s 同步一次，可根据需求更改 | 最低 30s）
3. 支持通过接口动态地添加/移除 xdp_banner 到网卡设备上
4. 支持通过接口动态地添加/移除 IP 到黑名单中，同时会更改黑名单源文件以持久化变更
5. 提供了基本的 Prometheus 指标接口，可以用于获取指标
6. IP 被 Ban 时，如果其持有 TCP 连接，那么自动 RST

**该程序将会提供以下几个功能：**

1. 支持通过配置文件配置一些基本参数，而非修改源代码

   > 注：目前变更配置需通过更改 mirrors_banner_main.py 进行，需求相关项均已批注。

2. 支持在添加 CIDR 块时判断是否有覆盖现象，如果已经存在范围更大的 CIDR 块，那么放弃变更

4. 支持流量控制，以根据需求限制目标 IP 的流量

   进度：无

## 使用方法

当前版本下，如果不想修改 mirrors_banner_main.py，那么请采用如下方式使用该项目

1. 将该项目放置到 `/etc/xdp_rules` 下:

   ```bash
   mkdir /etc/xdp_rules 
   cd /etc/xdp_rules
   git clone https://github.com/evilsp/xdp_banner.git
   ```

2. 在 `banned_ipv4` 和 `banned_ipv6` 文件中添加想要被永久封禁的 IP (每行一个)

3. 将 `mirrors_banner.service` 移动到 `/usr/lib/systemd/system`

   ```bash
   mv mirrors_banner.service /usr/lib/systemd/system
   ```

4. 启用 `mirrors_banner.service` 

   ```bash
   systemctl enable mirrors_banner.service --now
   ```

## 接口列表

**接口的使用方法以 curl 为示例。{xxx} 代表该位置可填充的值是一个变量，xxx 是该变量的一个例子**

1. 添加 IPV4/IPV6 地址到 Ban 列表中

   ```bash
   curl "0.0.0.0:8080/update?cidr={例子：192.168.1.1/24}&ban_type={0/1}&ban_time={例子: 100}"
   ```

   `ban_type`：0 为暂时，1 为永久

   `ban_time(s)`：ban 的时长，s 为单位

2. 从 Ban 列表中移除 IPV4/IPV6 地址

   ```bash
   curl "0.0.0.0:8080/remove?cidr={例子：192.168.1.1/24}"
   ```

3. 查看 xdp_banner 在设备上的挂载情况（要求主机上安装了 `iproute2` 工具包，原理为调用 `ip link show`）

   ```bash
   curl "0.0.0.0:8080/status"
   ```

4. 重新装载源文件中的 ipv6 和 ipv4 地址到 ban 列表

   ```bash
   curl "0.0.0.0:8080/reload"
   ```

5. 将 xdp_banner 从某个网络设备上移除

   ```bash
   curl "0.0.0.0:8080/detach?device={net_device_name}&attach_type={xdp 挂载位置（1 为驱动，0 为 skb 组织之后）}"
   ```

6. 将 xdp_banner 挂载到某个网络设备上

   ```bash
   curl "0.0.0.0:8080/attach?device={net_device_name}&attach_type={xdp 挂载位置（1 为驱动，0 为 skb 组织之后）}"
   ```

7. Prometheus 指标接口

   ```bash
   curl "0.0.0.0:8080/metrics"
   ```

   
