# udev rules

This directory contains all of the udev rules for the supported devices as retrieved from vendor websites and repositories.
These are necessary for the devices to be reachable on linux environments.

 - `20-hw1.rules` (Ledger): https://github.com/LedgerHQ/udev-rules/blob/master/20-hw1.rules
 - `51-coinkite.rules` (Coldcard): https://github.com/Coldcard/ckcc-protocol/blob/master/51-coinkite.rules
 - `51-trezor.rules` (Trezor): https://github.com/trezor/trezor-common/blob/master/udev/51-trezor.rules
 - `51-usb-keepkey.rules` (Keepkey): https://github.com/keepkey/udev-rules/blob/master/51-usb-keepkey.rules
 - `53-hid-bitbox02.rules`, `54-hid-bitbox02.rules` (Bitbox02): https://github.com/BitBoxSwiss/bitbox-wallet-app/blob/master/frontends/qt/resources/deb-afterinstall.sh
 - `55-usb-jade.rules` (Jade) https://github.com/Blockstream/Jade/blob/master/flashing/98-jade-flasher.rules

# Usage

Apply these rules by copying them to `/etc/udev/rules.d/` and notifying `udevadm`.
Your user will need to be added to the `plugdev` group, which needs to be created if it does not already exist.

```shell
cd src/main/resources; \
  sudo cp udev/*.rules /etc/udev/rules.d/ && \
  sudo udevadm trigger && \
  sudo udevadm control --reload-rules  && \
  sudo groupadd -r plugdev && \
  sudo usermod -aG plugdev `whoami`
```

