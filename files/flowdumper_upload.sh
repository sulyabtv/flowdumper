#!/bin/sh

# Load UCI interface functions
. /lib/functions.sh

# Load upload endpoint from config
endpoint=""
config_load 'flowdumper'
config_get endpoint upload endpoint

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