from parsezeeklogs import ParseZeekLogs
from elasticsearch import Elasticsearch
import nmap
import json
import ndjson
from io import StringIO
import requests

if __name__ == '__main__':
    path = '/usr/local/zeek/logs/current/conn.log'
    # Open log file and convert it to a new file in JSON format
    with open('out.json', "w") as outfile:
        for log_record in ParseZeekLogs(path, output_format="json", safe_headers=False, fields=["id.orig_h"]):
            if log_record is not None:
                outfile.write(log_record + "\n")

    #create array to store json data
    res = []
    # Put JSON file lines into array
    with open('out.json', 'r') as fp:
        for line in fp:
            res.append(line.strip())

    #filter out ipv6 by length
    res2 = []
    for ip in res:
        if len(ip) < 32:
            res2.append(ip)

    print(res2)

    formatted = []
    for ip in res2:
        x = slice(15, 100)
        y = ip[x]
        formatted.append(y)

    print(formatted)
