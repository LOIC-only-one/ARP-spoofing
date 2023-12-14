from scapy.all import *
import sys, argparse
from decouverte_active.py import ping

def main():
    decouverte_active.ping('192.168.1.1')