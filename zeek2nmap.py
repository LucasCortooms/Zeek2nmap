from parsezeeklogs import ParseZeekLogs
from elasticsearch import Elasticsearch
import nmap
import json
import ndjson
from io import StringIO
import requests

if __name__ == '__main__':
    # Open log file and convert it to a new file in JSON format
    with open('out.json', "w") as outfile:
        for log_record in ParseZeekLogs("bruh.log[1992]", output_format="json", safe_headers=False):
            if log_record is not None:
                outfile.write(log_record + "\n")

    #create array to store json data
    res = []
    # Put JSON file lines into array
    with open('out.json', 'r') as fp:
        for line in fp:
            res.append(line.strip())

    # cut away timestamp from lines on file
    cut = []
    for line in res:
        x = slice(37, 100)
        y = line[x]
        cut.append(y)

    # cut away quotes after IP ands store host IP's in array
    ip = []
    for line in cut:
            ip = list(dict.fromkeys(ip))
            ip2 = line.split('"')
            ip.append(ip2[0])
    #Now we have the adresses stored in the ip list :)

    #json list
    json_data_list = []
    for line in ip:
        # greyed out for troubleshooting
        try:
            # take the range of ports to be scanned
            begin = 50
            end = 150

            #target == an IP from the ip list
            target = line

            # instantiate a PortScanner object
            scanner = nmap.PortScanner()

            #for al ports in range do:...
            for i in range(begin, end + 1):
                # scan the target port
                res = scanner.scan(target, str(i))
                #scan target ip with port from range and retrieve status
                res = res['scan'][target]['tcp'][i]['state']
                #if state of port is open add it to json array
                if res == 'open':
                        json_data_list.append({'ip': ''+line+'', 'openports': ''+str(i)+''})

                #print state of port
                print(f'{line} port {i} is {res}.')
        #greyed out for troubleshooting
        except:
            print(f'{line} is not reachable')

    print(json_data_list)
    #write the list which contains the open ports to a json file ready to be used by elkstack!
    with open('results.json', 'w') as f:

        ndjson.dump(json_data_list, f)

    ####################################################################################################################
    #Define Elastic server address
    es = Elasticsearch('http://192.168.1.110:9200')

    #send ndjson file to elastic
    def send_json_to_elk(index_name):
        try:
            with open("results.json") as fp:
                for line in fp:
                    es.index(index=index_name, body=line)
            print("Finished uploading: " + index_name)
        except Exception as e:
            print(e)

    send_json_to_elk("ports")
########################################################################################################################

