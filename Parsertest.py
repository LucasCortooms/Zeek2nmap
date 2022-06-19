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
        for log_record in ParseZeekLogs(path, output_format="json", safe_headers=False, fields=["ts", "id.orig_h", "id.resp_h"]):
            if log_record is not None:
                outfile.write(log_record + "\n")

