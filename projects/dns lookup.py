import argparse
import dns.resolver

def main():
    parser = argparse.ArgumentParser(description="Simple DNS enumeration tool")
    parser.add_argument("domain", help="Domain name to look up")
    parser.add_argument(
        "-t", "--type",
        help="Specific record type to query (default: all common types)",
        default=None
    )
    parser.add_argument(
        "-s", "--server",
        help="Custom DNS server to query (e.g. 8.8.8.8)",
        default=None
    )
    args = parser.parse_args()

    resolver = dns.resolver.Resolver()
    if args.server:
        resolver.nameservers = [args.server]

    record_types = [args.type] if args.type else ['A', 'AAAA', 'NS', 'CNAME', 'MX', 'PTR', 'SOA', 'TXT']

    for records in record_types:
        try:
            answer = resolver.resolve(args.domain, records)
            print(f'\n{records} Records')
            print('-' * 30)
            for server in answer:
                print(server.to_text())
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            print(f'{args.domain} does not exist.')
            return
        except dns.resolver.Timeout:
            print(f'Query for {records} timed out.')
        except KeyboardInterrupt:
            print('Quitting.')
            return

if __name__ == "__main__":
    main()