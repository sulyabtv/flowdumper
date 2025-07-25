
# Flowdumper

Description goes here.

## Build Instructions

- Build instructions
- Install dependencies: `libnetfilter_conntrack`, `libnetfilter_conntrack-devel`, 
`libmnl`, `libmnl-devel`, `libnfnetlink`, `libnfnetlink-devel`, `libstdc++`
- Navigate to `src/` and run `make`
- Run instructions
- Enable `netfilter` accounting
- Create (as root) `/etc/sysctl.d/42-flowdumper.conf`, write the line 
`net.netfilter.nf_conntrack_acct=1` and save
- Reload `sysctl` config: `sudo sysctl --system`
- Generate a random identity for uploading reports
- `tr -dc A-Za-z0-9 </dev/urandom | head -c 16 | sudo tee /etc/flowdumper_id > /dev/
null`
- Set up upload script
- Create (as root) `/usr/bin/flowdumper_upload.sh`, write the following contents, and
save:
```bash
endpoint="https://ant.isi.edu/cgi-bin/thottung/up.cgi"

id=$(cat /etc/flowdumper_id)
id=${id:-unknown}

for FILE in $(ls -t /tmp/flowdumper | tail -n +2);
do
curl -F "uploaded_file=@/tmp/flowdumper/${FILE}" \
-F "name=fd.${id}.${FILE}" \
$endpoint --fail || continue
rm -f /tmp/flowdumper/${FILE}
done

exit 0
```
- Set up cron job for upload
- `sudo crontab -e -u root`, add `30 0 * * * /usr/bin/flowdumper_upload.sh` and save
- Run the tool
- `sudo -b ./flowdumper > /tmp/flowdumper.out 2>&1`

