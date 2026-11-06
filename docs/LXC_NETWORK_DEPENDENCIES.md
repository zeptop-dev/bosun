# Network dependencies and LXC

The installer choices and runtime recovery described here ship in bosun v0.91.0.
Captain v1.57.0 exposes the separate OS-package choice; older Captain releases
can continue managing upgraded agents through the existing protocol.

The installer prepares dependencies before starting a full native bosun service.
Package availability, kernel permissions, and applied protection are separate
results. A container running as root does not guarantee host kernel support.

| System | Network dependencies |
| --- | --- |
| Debian 11, 12, 13 | `nftables iproute2` |
| Alpine | `nftables iproute2 iproute2-tc` |

`wireguard-tools` is installed separately. Its failure does not prevent installation
of nftables or the ip/tc utilities. It is needed for managed WireGuard tunnels,
not as evidence that user traffic shaping or the egress guard works.

## Installation choices

`--system-packages auto` is the default: GitHub downloads attempt OS package
installation, while Captain downloads leave it to the administrator.
`--system-packages install` explicitly permits OS repository access even when
Captain delivers bosun and its managed cores. `--system-packages skip` prevents
OS package installation. This choice is installation-only; it adds no config keys.
Monitor-only, OpenWrt and Docker installations do not install these host packages.

Debian package installation retries once after refreshing indexes if the first
attempt fails. Alpine explicitly includes the separate traffic-control package.
Failures show fixed diagnostic categories rather than raw repository URLs, which
may contain credentials. Installation remains best effort; missing protection is
reported, not silently disabled or presented as successful.

The optional bounded `nft list tables` check only proves read access. It does not
prove that nft rules can be written, that HTB/IFB and tc actions work, or that
user upload/download limits have been measured. LXC host restrictions must be
resolved by the host operator. bosun does not make containers privileged, change
host capability policies or remove core isolation.

## Recovery after dependencies are installed

The agent retains the current desired user limits when it renders a temporarily
degraded configuration. After a successful control-state pull discovers that
missing helpers are available, the normal serial control loop retries the
current configuration, with backoff and at most three recovery attempts.
Recovery uses current authorization and is withheld during pause, monitoring mode,
offline recovery or revoked authorization. New consumed configuration resets the
recovery budget. Typed helper/kernel failures with tools already installed use
the same bounded path; unrelated core or accounting errors retain their own retry
behavior. An old retry cannot restore deleted
users or an earlier limit. Persistent kernel failures remain visible.

Doctor requests remain read-only. They do not install packages, restart the
service or write nft/tc rules. No effective user limits means shaping is not
verified; an installed binary or an empty user list does not produce a success
claim. Core account configuration and applied egress-guard rules are reported
separately. Already running older agents still need their normal update or a
configuration reapply/restart after dependencies are installed.

## 中文说明

Debian 11/12/13 需要 `nftables` 和 `iproute2`；Alpine 还需要独立的
`iproute2-tc`。Captain 下载源负责 bosun 和托管内核，不代理系统软件源。
使用 `--system-packages install` 可以明确允许从系统源安装依赖；`skip`
则禁止安装。默认保留原行为：GitHub 模式尝试安装，Captain 模式跳过。

安装器先检查、准备依赖，再启动服务。软件源失败会说明原因，WireGuard
工具独立安装。补装后，新版 Agent 根据最新配置有限重试，不恢复已撤销的
用户权限。诊断检查本身不修改规则。没有限速用户时显示未配置／未验证；
工具存在、规则已应用和实际吞吐限速是三种不同证据。

LXC 使用宿主机提供的内核能力；容器内更换发行版或补装软件不能保证获得
HTB、IFB、tc actions 或 nft 写权限。需要宿主机支持时应联系供应商，
不自动关闭隔离或改为特权容器。
