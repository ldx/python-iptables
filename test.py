#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys

try:
    input = raw_input
except NameError:
    pass

print("WARNING: this test will manipulate iptables rules.")
print("Don't do this on a production machine.")
while True:
    print("Would you like to continue? y/n")
    answer = input()
    if answer in "yYnN" and len(answer) == 1:
        break
if answer in "nN":
    sys.exit(0)

from iptc.test import test_iptc, test_matches, test_targets

results = [rv for rv in [test_iptc.run_tests(), test_matches.run_tests(),
                         test_targets.run_tests()]]
for res in results:
    if res:
        sys.exit(1)
