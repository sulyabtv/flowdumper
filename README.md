# Flowdumper

flowdumper is a measurement tool that runs in the background, obtains information about network flows from the kernel, and dumps it into a temporary file.
It is bundled with a script that uploads the dump file to a remote endpoint every night for research purposes.

flowdumper is packaged for OpenWRT, and has been tested on OpenWRT 22.03, 23.05 and 24.10.

## Build Instructions (general, non-OpenWRT)

- Install dependencies: `libnetfilter_conntrack`, `libnetfilter_conntrack-devel`, 
`libmnl`, `libmnl-devel`, `libnfnetlink`, `libnfnetlink-devel`, `libstdc++`
- Navigate to `src/` and run `make`

## Run instructions (general, non-OpenWRT)

- Enable `netfilter` accounting
    - Create (as root) `/etc/sysctl.d/42-flowdumper.conf`, write the line 
        `net.netfilter.nf_conntrack_acct=1` and save
    - Reload `sysctl` config: `sudo sysctl --system`
    - Generate a random identity for uploading reports
    - `tr -dc A-Za-z0-9 </dev/urandom | head -c 16 | sudo tee /etc/flowdumper_id > /dev/null`
- Set up upload script
    - `cp src/flowdumper_upload.sh /usr/bin/flowdumper_upload.sh`
    - `chmod +x /usr/bin/flowdumper_upload.sh`

- Set up cron job for upload
    - `sudo crontab -e -u root`, add `30 0 * * * /usr/bin/flowdumper_upload.sh` and save
- Run the tool
    - `sudo -b ./flowdumper > /tmp/flowdumper.out 2>&1`

