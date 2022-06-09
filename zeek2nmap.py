from parsezeeklogs import ParseZeekLogs
import elasticsearch
import nmap

#Open log file and convert it to a new file in JSON format
with open('out.json',"w") as outfile:
    for log_record in ParseZeekLogs("bruh.log[1992]", output_format="json", safe_headers=False):
        if log_record is not None:
            outfile.write(log_record + "\n")

#Put JSON file lines into array
res = []

with open('out.json', 'r') as fp:
    for line in fp:
        res.append(line.strip())

#cut away timestamp from line
cut = []
for line in res:
    x = slice(37,100)
    y = line[x]
    cut.append(y)

#cut away quotes after IP ands store host IP's in array
ip = []
for line in cut:
    ip2 = line.split('"')
    ip.append(ip2[0])

#nmap
nm = nmap.PortScanner()
for line in ip:
    try:
        nm.scan(line, '21 - 443')
        nm.command_line()
    except:
        print("Host not reachable")




