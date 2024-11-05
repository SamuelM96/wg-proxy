# WireGuard Proxy Setup

TLDR: Automagically setup WireGuard servers that (optionally) proxy traffic through MitM software and your VPN.

During security assessments, you'll often need to monitor an application's network traffic. Setting up proxying through a MitM solution like Burp Suite can sometimes be a pain depending on the platform, and proxy unaware apps make life more difficult.

A WireGuard VPN solves a lot of that headache, since it's the same setup between platforms and traffic from proxy unaware apps gets forced through it. With some `iptables` rules, you can forward all HTTP(S) traffic to your MitM software for analysis, and ensure all app traffic goes through your testing VPN. Rather than faffing around with all that manually, this script does it for you.

Tested on a Kali Linux host and Android + iOS devices. Should work on any client that supports WireGuard.

## Usage

Download the `wg-setup.sh` script and `chmod +x ./wg-setup.sh`, then run it as `root`.

```bash
Usage: sudo ./wg-setup.sh [options]

Options:
  --default-setup                 Perform default setup (create servers and add Android/iOS clients)
  --setup-servers                 Setup WireGuard servers
  --http-ports <ports>            Comma-separated list of HTTP(S) ports to redirect (e.g., 80,443,8080)
  --add-client                    Add a client
    --interface <interface>       Specify WireGuard interface (wg-proxy or wg-noproxy)
    --client-name <name>          Specify client name
  --list-clients                  List existing clients
  --vpn-interface <interface>     Specify VPN interface
  --main-interface <interface>    Specify main network interface (default: eth0)
  --help                          Display this help message

Examples:
  ./wg-setup.sh --default-setup
  ./wg-setup.sh --default-setup --http-ports 80,443,8080,8443
  ./wg-setup.sh --setup-servers
  ./wg-setup.sh --add-client --interface wg-proxy --client-name mydevice
  ./wg-setup.sh --list-clients
```

> [!NOTE]
> The server setup will create two WireGuard servers: one with proxy forwarding rules, and one without. The latter is to give you an alternative where you need to send traffic over a VPN, but you cannot bypass the target app's certificate pinning.

Once you've setup the servers, create a new proxy listener in Burp Suite bound to `10.0.0.1:8081` (or whatever you set the IP/port to), and enable `Support invisible proxying` (under the `Request handling` tab when editing the proxy listener). Other MitM solutions will likely work too, but they're untested.

Scan the QR codes with the WireGuard app (or send the `.conf` files to the device to load), and you should be good to go.

If you're not using a VPN, you can probably set `VPN_INTERFACE` to your main interface (e.g., `eth0`). Untested, but should work.

> [!WARNING]
> The default setup just proxies traffic sent over 80/443. If your app uses other ports, use the `--http-ports` option to generate a new server config that proxies the relevant ports (use Wireshark to see what your app does). You'll need to redo the configs on the devices.

