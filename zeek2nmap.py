from parsezeeklogs import ParseZeekLogs
import elasticsearch
import nmap
import json
import test

if __name__ == '__main__':
    # Open log file and convert it to a new file in JSON format
    with open('out.json', "w") as outfile:
        for log_record in ParseZeekLogs("bruh.log[1992]", output_format="json", safe_headers=False):
            if log_record is not None:
                outfile.write(log_record + "\n")

    # Put JSON file lines into array
    res = []

    with open('out.json', 'r') as fp:
        for line in fp:
            res.append(line.strip())

    # cut away timestamp from line
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
    print(ip)
    # nmap
    nm = nmap.PortScanner()
    #json list
    json_data_list = []
    for line in ip:
        try:
            # take the range of ports to
            # be scanned
            begin = 75
            end = 80

            # assign the target ip to be scanned to
            # a variable
            target = line

            # instantiate a PortScanner object
            scanner = nmap.PortScanner()

            for i in range(begin, end + 1):
                # scan the target port

                res = scanner.scan(target, str(i))
                res = res['scan'][target]['tcp'][i]['state']

                if res == 'open':
                        json_data_list.append({'ip': ''+{line}+'', 'openports': ''+{i}+''})

                print(f'{line} port {i} is {res}.')
        except:
            print(f'{line} is not reachable')

        print(json_data_list)
        #jsonString = json.dumps(json_data_list, indent=4)
        #print(jsonString)
        #line = "help me"
        #data_set = {""+line+"": [{i}, {res}]}
        #json_dump = json.dumps(data_set)
        #print(json_dump)

