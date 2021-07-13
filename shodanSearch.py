#!/usr/bin/env python3
import shodan
import json 
import argparse 
import os

parser = argparse.ArgumentParser(prog='shodanSearch.py', usage='%(prog)s --file [apikeys.json] --query [query] --ip [ip]', description='Just a simple shodan interface')
parser.add_argument('--file', type=str, default="apikeys.json", help="api keys file")
parser.add_argument('--query', type=str, help="query to search")
parser.add_argument('--count', default=False, action="store_true", help="(with query) Just print statistics")
parser.add_argument('--countries', default=5, type=int, help="(with count) Number of countries to print")
parser.add_argument('--ip', type=str, help="ip to search")
args = parser.parse_args()

# The list of properties we want summary information on
FACETS = [
    'org',
    'domain',
    'port',
    'asn',
    ('country', args.countries),
]
FACET_TITLES = {
    'org': 'Top 5 Organizations',
    'domain': 'Top 5 Domains',
    'port': 'Top 5 Ports',
    'asn': 'Top 5 Autonomous Systems',
    'country': f'Top {args.countries} Countries',
}

if not args.query and not args.ip:
    parser.print_help()
    exit(-1)

def shodan_query(api, query):
    ''' 
        TODO:
            filter for good results 
    '''
    try:
        results = api.search(query)

        print(f'Results found: {results["total"]}')
        for result in results['matches']:
            print('IP: {}'.format(result['ip_str']))
            print(result['data'])

    except shodan.APIError as e:
	    print('Error: {}'.format(e))


def shodan_count(api, query):
    try:
        result = api.count(query, facets=FACETS)
        print('Shodan Summary Information')
        print(f'Query: {query}')
        print(f'Total Results: {result["total"]}\n')
        for facet in result['facets']:
            print(FACET_TITLES[facet])
            for term in result['facets'][facet]:
                print(f"{term['value']}: {term['count']}")
            print()
    except Exception as e:
        print('Error: {}'.format(e))


def shodan_ip(api, ip):
    host = api.host(ip)

    print(f"""Ip: {host['ip_str']}
Organization: {host.get('org', 'n/a')}
Operating System: {host.get('os', 'n/a')}
""")

    for item in host['data']:
        print(f"""Port: {item['port']}
Banner: {item['data']}
            """)

def main():
    ''' 
        TODO Gifs, query pages, scan
    '''
    if not os.path.exists(args.file):
        print(f"Please ensure the file: {KEYS} exists!")
        exit(1)

    SHODAN_API_KEY = json.loads(open(args.file, 'r').read())['shodan']
    api = shodan.Shodan(SHODAN_API_KEY)
    if not SHODAN_API_KEY:
        print("Please provide a valid api-keys file (default: apikeys.json)")
        exit(1)

    if args.query:
        if args.count:
            shodan_count(api, args.query)
        else:
            shodan_query(api, args.query)
    if args.ip:
        shodan_ip(api, args.ip)

if __name__ == "__main__":
    main()


