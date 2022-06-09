import json

json_data_list = [{'ip':'','ports':''},{'ip':'','ports':''},{'ip':'','ports':''}]
json_data_list.append({'ip':'192.168.1.1','openports':'22,23'})
jsonString = json.dumps(json_data_list, indent=4)
print(jsonString)

#json_data_list.append("test")
#rint(json.dumps(json_data_list))

