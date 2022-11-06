# BitterJohn
Server and relay side infrastructure for RDA.

## Usage

### install

```bash
sudo ./BitterJohn install -g
sudo systemctl enable --now BitterJohn
```

### upgrade

**After v1.2.6**

```bash
sudo BitterJohn update
sudo systemctl restart BitterJohn.service
```

Warn: this method will not update the systemd service file.

**Before v1.2.5**

```bash
sudo ./BitterJohn install
sudo systemctl daemon-reload
sudo systemctl restart BitterJohn.service
```

## Troubleshot

1. User systemd service will be killed after logout. See [stackexchange](https://unix.stackexchange.com/questions/521538/system-service-running-as-user-is-terminated-on-logout).

## Credit

[v2fly/v2ray-core](https://github.com/v2fly/v2ray-core)
