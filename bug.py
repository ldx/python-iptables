import iptc
import sys
import os
import time
import subprocess

table = iptc.Table(iptc.Table.FILTER)
chain = iptc.Chain(table, sys.argv[1])

pid = str(os.getpid())

#while True:
#table.refresh()
with open('/tmp/x.log', 'w') as f:
    for rule in chain.rules:
        f.write(str(rule.target))
        for match in rule.matches:
            f.write(str(match))
#time.sleep(1)
#print len(subprocess.check_output(['lsof', '-p', pid]).split('\n'))
