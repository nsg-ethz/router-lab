# Getting the lab setup

This library must know which routers are available under which address, and how many interfaces are available, and how they are connected. To do that, you first need to edit `config/routers.toml`. Write all router names there. Make sure that you have proper `ssh` configuration. Each router must be reachable using `ssh ${router_name}` without any password (using SSH keys). Then, generate the configurations for each router as follows:

```bash
ssh_name = "router-name"
mgnt_addr = "1.2.3.4"
ifaces = [
  # [iface name, MAC, Tofino port descriptor, Tofino internal port number]
  ["Ethernet1/1", 0xaabbccddee01, "1/0", 130],
  ["Ethernet1/2", 0xaabbccddee02, "1/1", 131],
  ["Ethernet1/3", 0xaabbccddee03, "1/2", 132],
  ["Ethernet1/4", 0xaabbccddee04, "1/3", 133],
]
```

Also, make sure to export the path to the configuration into the environment variable `LAB_SETUP_CONFIG`.
