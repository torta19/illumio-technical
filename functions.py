import csv
from collections import defaultdict

def load_lookup(csvfile):
    # return the dstport and protocols pairs
    # store as KV with such as (dst, protocol) : tag using 
    lookup_table = {}
    with open(csvfile, mode="r", newline='') as file:
        reader = csv.DictReader(file) #formats the csv into dict using first row as keys
        reader.fieldnames = [header.strip() for header in reader.fieldnames]

        for row in reader:
            dstport = row['dstport']
            protocol = row['protocol'].lower().strip()
            tag = row['tag'].strip()
            lookup_table[(dstport, protocol)] = tag
        
        return lookup_table

def parse_logs(log_files):
    # extract the necessary columns dstport and protocols
    # 7th column and 8th port
    # ver (0)   acct-id (1)     interface-id (2)   src-addr (3)    dst-addr (4)    sp (5)   dst port (6)    prot (7)
    # 2         123456789012    eni-0a1b2c3d       10.0.1.201      198.51.100.2    443      49153           6 
    # store the logs as list of tuples  
    logs = []

    with open(log_files, mode='r') as file1, open('./protocol-numbers-1.csv', mode='r') as file2:
        # map protocol number to keyword
        protocol_dict = {}
        reader = csv.DictReader(file2)
        for row in reader:
            protocol_dict[row["Decimal"]] = row["Keyword"].lower()
        # extract log information and store in list
        logs = []
        for log in file1: 
           log = log.split()
           protocol_keyword = protocol_dict[log[7]]
           logs.append((log[6], protocol_keyword)) 
    return logs


def lookup_logs(logs, lookup_table):
    # track information with a counter
    tag_counts = defaultdict(int) # tag: count
    port_protocol_combinations = defaultdict(int) # (port, protocol) count

    for pairs in logs: 
        if pairs in lookup_table:
            tag_counts[lookup_table[pairs]] += 1
        else:
            tag_counts["Untagged"] += 1

        port_protocol_combinations[pairs]  +=1 
    
    return tag_counts, port_protocol_combinations

def generate_output_file(tag_counts, port_protocol_combinations):
    with open('output_file.csv', 'w', newline='') as file: 
        fieldnames = ['Tag', 'Count']
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()

        for tag, count in tag_counts.items():
            writer.writerow({'Tag': tag, 'Count': count})

    with open('output_file.csv', 'a', newline='') as file: 
        
        fieldnames = ['Port', 'Protocol', 'Count']
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writerow({})
        writer.writeheader()

        for k, v in port_protocol_combinations.items():
            writer.writerow({'Port': k[0], 'Protocol': k[1], 'Count': v})
        