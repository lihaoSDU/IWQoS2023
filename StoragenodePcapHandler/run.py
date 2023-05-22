import os
import sys
import pandas as pd
from StoragenodePcapHandler.packets_types import storjshare_ips

upload_client_ip_list = []
download_client_ip_list = []

client_port_list = []
satellite_ip_list = []

counter = 0


def filter(line):
    global counter
    storage_node_ip, storage_node_port, client_ip, client_port = line.split('_')[:4]

    if storage_node_port == '28967':
        if client_ip in storjshare_ips:
            print(line)
            counter += 1
        return client_ip

    else:
        if client_port not in client_port_list:
            client_port_list.append(client_port)
        return None


def data_loader(file_path):

    date = file_path.split('_')[-1].split('.')[0]

    upload_client_info = []
    download_client_info = []

    with open(file_path) as f:
        for line in f.readlines():
            line = line.strip().split(' - root - ')[-1]

            if 'upload' in line.strip():
                client_ip = filter(line)
                if client_ip is not None:
                    upload_client_info.append(client_ip)

            elif 'download' in line.strip():
                client_ip = filter(line)
                if client_ip is not None:
                    download_client_info.append(client_ip)
            else:
                if 'tcp' not in line:
                    continue
                line = line.split(': ')[-1]
                storage_node_ip, storage_node_port, client_ip, client_port = line.split('_')[:4]
                if client_port == '7777':
                    if client_ip not in satellite_ip_list:
                        satellite_ip_list.append(client_ip)

    return upload_client_info, download_client_info, date[:8]


def count_number_of_clients(file_path):
    upload_client_info, download_client_info, date = data_loader(file_path)
    print('Date: {}, upload clients ip: {}, download clients ip: {}'.format(date,
                                                                            len(set(upload_client_info)),
                                                                            len(set(download_client_info))))
    new_append_upload_client_ip = set(upload_client_info) - set(upload_client_ip_list) & set(upload_client_info)
    new_append_download_client_ip = set(download_client_info) - set(download_client_ip_list) & set(download_client_info)
    upload_client_ip_list.extend(new_append_upload_client_ip)
    download_client_ip_list.extend(new_append_download_client_ip)
    print('New append upload client ip: {}, Sum of client ip: {}'.format(len(new_append_upload_client_ip),
                                                                         len(upload_client_ip_list)))
    print('New append download client ip: {}, Sum of client ip: {}'.format(len(new_append_download_client_ip),
                                                                           len(download_client_ip_list)))
    print()
    uplink_ip_list = set(upload_client_ip_list + download_client_ip_list)
    pd.DataFrame(list(uplink_ip_list)).to_csv('uplink_data/uplink_ip_list.csv', header=None, index=None)


if __name__ == '__main__':

    path_dir = r'E:\PycharmProjects\pythonProject\StoragenodePcapHandler\logs'
    for log_file in os.listdir(path_dir):
        if log_file.endswith('.log'):
            path = os.path.join(path_dir, log_file)
            count_number_of_clients(path)

    print(satellite_ip_list)
    print(counter)

    sys.exit(0)