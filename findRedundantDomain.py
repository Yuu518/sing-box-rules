#!/usr/bin/env python3

import sys
print(sys.argv[1], sys.argv[2])

''' Find duplicate items in domain lists. '''

def load(list):
    ''' Parse conf file & return domain strings. '''

    results = []
    with open(list, 'r') as f:
        for line in f.readlines():
            line = line.strip()
            if line == '' or line.startswith('#'):
                continue
            results.append(line.lower())
    return results

def find(domains, removedDomainFile):
    ''' Find exact duplicate domains. '''

    seen = set()
    for domain in domains:
        if domain in seen:
            print(f"Duplicate found: {domain}")
            with open(removedDomainFile, "a") as f:
                f.write(domain)
                f.write("\n")
        else:
            seen.add(domain)

if __name__ == '__main__':
    find(load(sys.argv[1]), sys.argv[2])

