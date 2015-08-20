#!/usr/bin/env python
#
# Copyright (c) 2015 Sam Russell <sam.h.russell@gmail.com>
# Copyrite (c) 2014 SecurityKISS Ltd (http://www.securitykiss.com)  
#
# This file is part of rfw
#
# The MIT License (MIT)
#
# Yes, Mr patent attorney, you have nothing to do here. Find a decent job instead. 
# Fight intellectual "property".
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import inspect, re, subprocess, logging, json, copy, iptc
from collections import namedtuple
from threading import RLock

# Follow the logging convention:
# - Modules intended as reusable libraries have names 'lib.<modulename>' what allows to configure single parent 'lib' logger for all libraries in the consuming application
# - Add NullHandler (since Python 2.7) to prevent error message if no other handlers present. The consuming app may add other handlers to 'lib' logger or its children.
log = logging.getLogger('lib.{}'.format(__name__))
log.addHandler(logging.NullHandler())


RuleProto = namedtuple('Rule', [
                            'chain',
                            'num',
                            'pkts',
                            'bytes',
                            'target',
                            'prot',
                            'opt',
                            'inp',
                            'out',
                            'source',
                            'destination'
                        ]
                        )

class Rule(RuleProto):
    """Lightweight immutable value object to store iptables rule
    """
    # note that the 'in' attribute from iptables output was renamed to 'inp' to avoid python keyword clash
    #Rule._fields =      ['chain', 'num', 'pkts', 'bytes', 'target', 'prot', 'opt', 'inp', 'out', 'source', 'destination']
    RULE_TARGETS =      ['DROP', 'ACCEPT', 'REJECT']
    RULE_CHAINS =       ['INPUT', 'OUTPUT', 'FORWARD']
    RULE_DEFAULTS =     {
                            'chain': None,
                            'num': None,
                            'pkts': None,
                            'bytes': None,
                            'target': None,
                            'prot': 'all',
                            'opt': '--',
                            'inp': '*',
                            'out': '*',
                            'source': '0.0.0.0/0',
                            'destination': '0.0.0.0/0'
                        }

    def __new__(_cls, *args, **kwargs):
        """Construct Rule tuple from a list or a dictionary
        """
        if args:
            if len(args) != 1:
                raise ValueError('The Rule constructor takes either list, dictionary or named properties')
            props = args[0]
            if isinstance(props, list):
                return RuleProto.__new__(_cls, *props)
            elif isinstance(props, dict):
                for prop in props:
                    if prop not in Rule._fields:
                        raise ValueError('Property %s is not a valid argument to pass to Rule()', prop)
                default_settings = copy.deepcopy(Rule.RULE_DEFAULTS)
                default_settings.update(props)
                return RuleProto.__new__(_cls, **default_settings)
            else:
                raise ValueError('The Rule constructor takes either list, dictionary or named properties')
        elif kwargs:
            return RuleProto.__new__(_cls, **kwargs)
        else:
            return RuleProto.__new__(_cls, [])

    def __hash__(self):
        return hash((self.chain, self.target, self.prot, self.opt, self.inp, self.out, self.source, self.destination, ))

    def __eq__(self, other):
        """Rule equality should ignore such parameters like num, pkts, bytes
        """
        if isinstance(other, self.__class__):
            return self.chain == other.chain and self.target == other.target and self.prot == other.prot and self.opt == other.opt \
                and self.inp == other.inp and self.out == other.out and self.source == other.source and self.destination == other.destination
        else:
            return False

    def __ne__(self, other):
        return not self.__eq__(other)




class Iptables:

    IPTABLES_HEADERS =         ['num', 'pkts', 'bytes', 'target', 'prot', 'opt', 'in', 'out', 'source', 'destination'] 
    # global lock for system iptables access
    lock = RLock()
    # store ipt_path as class variable, it's a system wide singleton anyway
    ipt_path = 'iptables'

    def __init__(self, rules):
        # check the caller function name - the poor man's private constructor
        if inspect.stack()[1][3] == 'load':
            # after this initialization self.rules should be read-only
            self.rules = rules
        else:
            raise Exception("Use Iptables.load() to create an instance with loaded current list of rules")

    @staticmethod
    def load():
        rules = Iptables._iptables_list()
        inst = Iptables(rules)
        return inst

    @staticmethod
    def verify_install():
        """Check if iptables installed
        """
        try:
            Iptables.exe(['-h'])
            #subprocess.check_output([Iptables.ipt_path, '-h'], stderr=subprocess.STDOUT)
        except OSError, e:
            raise Exception("Could not find {}. Check if it is correctly installed and if the path is correct.".format(Iptables.ipt_path))

    @staticmethod
    def verify_permission():
        """Check if root - iptables installed but cannot list rules
        """
        try:
            Iptables.exe(['-n', '-L', 'OUTPUT'])
            #subprocess.check_output([Iptables.ipt_path, '-n', '-L', 'OUTPUT'], stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError, e:
            raise Exception("No sufficient permission to run {}. You must be root.".format(Iptables.ipt_path))

    @staticmethod
    def verify_original():
        #TODO check if iptables is pointing to original iptables program (and not to rfwc)
        pass

    @staticmethod
    def _iptables_list():
        """List and parse iptables rules. Do not call directly. Use Iptables.load().rules instead
        return list of rules of type Rule.
        """
        rules = []
        out = Iptables.exe(['-n', '-L', '-v', '-x', '--line-numbers'])
        #out = subprocess.check_output([Iptables.ipt_path, '-n', '-L', '-v', '-x', '--line-numbers'], stderr=subprocess.STDOUT)
        chain = None
        header = None
        for line in out.split('\n'):
            line = line.strip()
            if not line:
                chain = None  #on blank line reset current chain
                continue
            m = re.match(r"Chain (\w+) .*", line)
            if m and m.group(1) in Rule.RULE_CHAINS:
                chain = m.group(1)
                continue
            if "source" in line and "destination" in line:
                # check if iptables output headers make sense 
                assert line.split()  == Iptables.IPTABLES_HEADERS
                continue
            if chain:
                columns = line.split()
                if columns and columns[0].isdigit():
                    # deal with ports later (won't matter once we get iptc running
                    ## join all extra columns into one extra field
                    #extra = " ".join(columns[10:])
                    columns = columns[:10]
                    #columns.append(extra)
                    columns.insert(0, chain)
                    rule = Rule(columns)
                    rules.append(rule)
        return rules
    
   
    @staticmethod
    def rule_to_command(r):
        """Convert Rule object r to the list representing iptables command arguments like: 
        ['INPUT', '-p', 'tcp', '-d', '0.0.0.0/0', '-s', '1.2.3.4', '-j', 'ACCEPT']
        It is assumed that the rule is from trusted source (from Iptables.find())
        """
        # sam here, not going to do extra in this part anymore, will deal with this as a proper attribute
        #TODO handle extras e.g. 'extra': 'tcp dpt:7373 spt:34543'
        #TODO add validations
        #TODO handle wildcards
        assert r.chain == 'INPUT' or r.chain == 'OUTPUT' or r.chain == 'FORWARD'
        lcmd = []
        lcmd.append(r.chain)
        if r.prot != 'all':
            lcmd.append('-p')
            lcmd.append(r.prot)
        # sam here, breaking this
        # parsing out source port and dest port should be done by Iptables
        # TODO enhance. For now handle only source and destination port
        #if r.extra:
            #es = r.extra.split()
            #for e in es:
            #    if e[:4] == 'dpt:':
            #        dport = e.split(':')[1]
            #        lcmd.append('--dport')
            #        lcmd.append(dport)
            #    if e[:4] == 'spt:':
            #        sport = e.split(':')[1]
            #        lcmd.append('--sport')
            #        lcmd.append(sport)

        if r.destination != '0.0.0.0/0':
            lcmd.append('-d')
            lcmd.append(r.destination)
        if r.source != '0.0.0.0/0':
            lcmd.append('-s')
            lcmd.append(r.source)
        lcmd.append('-j')
        lcmd.append(r.target)
        return lcmd

    @staticmethod
    def convert_ip_and_cidr_to_ip_and_mask(ip_and_cidr):
        # trivial case: no cidr = /32
        if '/' not in ip_and_cidr:
            ip = ip_and_cidr
            return '%s/255.255.255.255' % ip
        ip, cidr_str = ip_and_cidr.split('/')
        cidr = int(cidr_str)
        # turn '/24' cidr into '255.255.255.0'
        octets = []
        octet_samples = [0, 128, 192, 224, 240, 248, 252, 254, 255]
        for threshold in [0, 8, 16, 24]:
            offset = cidr - threshold
            offset = min(offset, 8)
            offset = max(offset, 0)
            octets.append(octet_samples[offset])
        mask = '.'.join(['%d' % x for x in octets])
        return '%s/%s' % (ip, mask)

    # TODO: parse this somewhere better?
    @staticmethod
    def convert_rule_to_iptc_rule(rule):
        """
        Inputs:
        rule: Iptables.Rule object
        Returns:
        a Rule object from iptc
        """
        # parse these out
        # Rule._fields =      ['chain', 'num', 'pkts', 'bytes', 'target', 'prot', 'opt', 'inp', 'out', 'source', 'destination']
        #return hash((self.chain, self.target, self.prot, self.opt, self.inp, self.out, self.source, self.destination, ))
        # ignore index and counters
        iptc_rule = iptc.Rule()
        target = iptc.Target(iptc_rule, rule.target)
        iptc_rule.target = target
        if rule.prot != 'all':
            iptc_rule.protocol = rule.prot
        # ignore opt
        if rule.inp != '*':
            iptc_rule.in_interface = rule.inp
        if rule.out != '*':
            iptc_rule.out_interface = rule.out
        iptc_rule.src = Iptables.convert_ip_and_cidr_to_ip_and_mask(rule.source)
        iptc_rule.dst = Iptables.convert_ip_and_cidr_to_ip_and_mask(rule.destination)
        return iptc_rule

    @staticmethod
    def exe_rule_iptc(modify, rule):
        assert modify == 'I' or modify == 'D'
        # call python-iptables
        chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), rule.chain)
        iptc_rule = Iptables.convert_rule_to_iptc_rule(rule)
        if modify == 'I':
            chain.insert_rule(iptc_rule)
        if modify == 'D':
            chain.delete_rule(iptc_rule)

    @staticmethod
    def exe_rule(modify, rule):
        assert modify == 'I' or modify == 'D'
        lcmd = Iptables.rule_to_command(rule)
        return Iptables.exe(['-' + modify] + lcmd)

    @staticmethod
    def exe(lcmd):
        cmd = [Iptables.ipt_path] + lcmd
        try:
            log.debug('Iptables.exe(): {}'.format(' '.join(cmd)))
            with Iptables.lock:
                out = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
            if out: 
                log.debug("Iptables.exe() output: {}".format(out))
            return out
        except subprocess.CalledProcessError, e:
            log.error("Error code {} returned when called '{}'. Command output: '{}'".format(e.returncode, e.cmd, e.output))
            raise e

    @staticmethod
    def read_simple_rules(chain=None):
        assert chain is None or chain in Rule.RULE_CHAINS
        rules = []
        ipt = Iptables.load()
        # rfw originated rules may have only DROP/ACCEPT/REJECT targets and do not specify protocol and do not have extra args like ports
        if chain == 'INPUT' or chain is None:
            input_rules = ipt.find({'target': Rule.RULE_TARGETS, 'chain': ['INPUT'], 'destination': ['0.0.0.0/0'], 'out': ['*'], 'prot': ['all']})
            rules.extend(input_rules)
        if chain == 'OUTPUT' or chain is None:
            output_rules = ipt.find({'target': Rule.RULE_TARGETS, 'chain': ['OUTPUT'], 'source': ['0.0.0.0/0'], 'inp': ['*'], 'prot': ['all']})
            rules.extend(output_rules)
        if chain == 'FORWARD' or chain is None:
            forward_rules = ipt.find({'target': Rule.RULE_TARGETS, 'chain': ['FORWARD'], 'prot': ['all']})
            rules.extend(forward_rules)
        return rules

    @staticmethod
    def convert_ip_and_mask_to_ip_and_cidr(ip_and_mask):
        ip, mask = ip_and_mask.split('/')
        # turn '255.255.255.0' mask into '/24'
        mask_octets = mask.split('.')
        # we will do weird stuff with junk data
        # 255.255.0.255 will go to /24 with this method, for example
        cidr = 0
        for octet_str in mask_octets:
            octet = int(octet_str)
            while octet > 0:
                cidr = cidr + (octet & 1)
                octet = octet >> 1
        # ignore cidr if it is /32
        if cidr == 32:
            return '%s' % (ip, )
        return '%s/%d' % (ip, cidr)

    # TODO: parse this somewhere better?
    @staticmethod
    def convert_iptc_rule_to_rule(chain_name, index, rule):
        """
        Inputs:
        chain_name: name of the chain (string)
        index: index number of the rule
        rule: iptc.Rule object from iptc
        Returns:
        an Iptables.Rule object
        """
        # parse these out
        # Rule._fields =      ['chain', 'num', 'pkts', 'bytes', 'target', 'prot', 'opt', 'inp', 'out', 'source', 'destination']
        rule_attributes = {}
        rule_attributes['chain'] = chain_name
        # index is 0-based from list, num is 1-based
        rule_attributes['num'] = '%d' % (index + 1)
        # zero counters for now
        #return hash((self.chain, self.target, self.prot, self.opt, self.inp, self.out, self.source, self.destination, ))
        rule_attributes['pkts'] = 0
        rule_attributes['bytes'] = 0
        rule_attributes['target'] = rule.target.name
        protocol = rule.protocol
        if protocol == 'ip':
            protocol = 'all'
        rule_attributes['prot'] = protocol
        # set this blank - is not correct, but we will get better access later
        rule_attributes['opt'] = '--'
        rule_attributes['inp'] = rule.in_interface if rule.in_interface else '*'
        rule_attributes['out'] = rule.out_interface if rule.out_interface else '*'
        rule_attributes['source'] = Iptables.convert_ip_and_mask_to_ip_and_cidr(rule.src)
        rule_attributes['destination'] = Iptables.convert_ip_and_mask_to_ip_and_cidr(rule.dst)
        return Rule(rule_attributes)

    @staticmethod
    def read_simple_rules_iptc(chain=None):
        assert chain is None or chain in Rule.RULE_CHAINS
        rules = []
        filter_table = iptc.Table(iptc.Table.FILTER)
        filter_table.refresh()
        iptables_chains_by_name = {chain.name : chain for chain in filter_table.chains}
        chains_to_search = [chain] if chain is not None else Rule.RULE_CHAINS
        for chain_name in chains_to_search:
            # horrible variable name, but 'chain' is the arg (should change this instead)
            chain_chain = iptables_chains_by_name[chain_name]
            for index, rule in enumerate(chain_chain.rules):
                rules.append(Iptables.convert_iptc_rule_to_rule(chain_name, index, rule))
        return rules

    # find is a non-static method as it should be called after instantiation with Iptables.load()
    def find(self, query):
        """Find rules based on query
        For example:
            query = {'chain': ['INPUT', 'OUTPUT'], 'prot': ['all'], 'extra': ['']}
            is searching for the rules where:
            (chain == INPUT or chain == OUTPUT) and prot == all and extra == ''
        """
        ret = []
        for r in self.rules:
            matched_all = True    # be optimistic, if inner loop does not break, it means we matched all clauses
            for param, vals in query.items():
                rule_val = getattr(r, param)
                if rule_val not in vals:
                    matched_all = False
                    break
            if matched_all:
                ret.append(r)
        return ret


