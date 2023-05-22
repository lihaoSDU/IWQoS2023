import argparse
import json
from collections import Counter


def data_loader(path):
    data = []
    with open(path) as file:
        for line in file.readlines():
            line = json.loads(line.strip())
            data.append(line)
    return data


def analyzer(data):

    country_name_counter = []
    asn_type_counter = []
    company_type_counter = []
    company_education_counter = []
    carrier_name_counter = []

    for item in data:
        country_name_counter.append(item['country_name'])
        if 'asn' in item.keys():
            asn_type_counter.append(item['asn']['type'])
        # print(item.keys())
        if 'company' in item.keys():
            company_type_counter.append(item['company']['type'])
            if item['company']['type'] == 'education':
                company_education_counter.append(item)
        if 'carrier' in item.keys():
            carrier_name_counter.append(item['carrier']['name'])
        if 'anycast' in item.keys():
            print(item)

    print()
    print('country_name_counter: {}'.format(Counter(country_name_counter).most_common(20)))
    print('asn_type: {}'.format(Counter(asn_type_counter).most_common(20)))
    print('company_type: {}'.format(Counter(company_type_counter).most_common(20)))
    print('carrier_name_counter: {}'.format(Counter(carrier_name_counter).most_common(20)))

    return 0


def resolution_analyzer(data):
    host_name_list = []
    ip_address_list = []
    for line in data:
        if line['meta']['count'] > 0:
            for item in line['data']:
                ip_address = item['attributes']['ip_address']
                host_name = item['attributes']['host_name']
                if 'storjshare' in host_name:
                    if ip_address not in ip_address_list:
                        ip_address_list.append(ip_address)
                        print(ip_address, host_name)
                    host_name_list.append(host_name)
    print(ip_address_list)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PCAP analyzer')
    parser.add_argument('--file_path', metavar='<ipinfo file name>',
                        default=r'E:\PycharmProjects\pythonProject\StoragenodePcapHandler\uplink_data\resolutions.json',
                        help='pcap file to parse', required=False)
    args = parser.parse_args()

    resolution_analyzer(data_loader(args.file_path))