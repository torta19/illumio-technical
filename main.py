import sys
from functions import load_lookup, parse_logs, lookup_logs, generate_output_file

def main():
    if len(sys.argv) != 3:
        #   error handling
        print("Usage: python3 main.py <lookup_file> <log_file>")
        sys.exit(1)

    lookup_file = sys.argv[1]
    log_file = sys.argv[2]
    
    lookup_table = load_lookup(lookup_file)
    parsed_logs = parse_logs(log_file)
    tag_counts, port_protocol_combinations = lookup_logs(parsed_logs, lookup_table)

    generate_output_file(tag_counts, port_protocol_combinations)

    print("all done")


if __name__ == "__main__":
    main()