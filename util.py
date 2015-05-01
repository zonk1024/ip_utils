from math import log
from re import match, compile


COMPILED_RE_TYPE = type(compile(r'could not find the class'))


def netmask_from_cidr(cidr):
    """
    :param cidr (srt): Classless inter-domain routing string ('192.168.1.0/24')
    :return int: cidr's netmask (24)
    """
    return int(cidr.split('/')[1])


def netmask_to_binary(netmask):
    """Converts cidr ('192.168.1.0/24'), an int, or ip-type to a binary representation"""
    if type(netmask) is str and netmask.count('/'):
        netmask = netmask_from_cidr(netmask)
    if type(netmask) is int:
        return ''.join(['1' if i < netmask else '0' for i in range(32)])
    return ip_to_bin(netmask)


def ip_to_int(ip):
    """
    Converts an ip address to the integer representation
    :param ip (str): IP address to convert to an int
    :return int: integer representation of the ip
    """
    return sum([int(v) * 256 ** (3 - i) for i, v in enumerate(ip.split('.'))])


def ip_to_bin(ip):
    """
    Converts an IP address to it's binary representation
    :param ip (str): IP address to convert to binary
    :return str: binary representation of the ip
    """
    return bin(ip_to_int(ip))[2:].zfill(32)


def int_to_ip(ip_int):
    """
    Converts an integer representation of an IP address to an IP address
    :param ip_int (int): Integer representation of an IP address
    :return str: IP address represented by integer value
    """
    digits = []
    for i in range(3, -1, -1):
        place = 256 ** i
        digits.append(ip_int / place)
        ip_int -= digits[-1] * place
    return '.'.join([str(d) for d in digits])


def bin_to_ip(bin_ip):
    """
    Converts a binary representation of an IP address to th IP address
    :param bin_ip (str): string of 32 zeroes or ones
    :return str: IP address represented by the string of binary digits
    """
    return int_to_ip(int(bin_ip, 2))


def cidr_to_ip_range(cidr):
    """
    Converts a cidr specification to an IP range
    :param cidr (string):cidr specification
    :return tuple of length 2: first and last IP addresses in the range specified
    """
    ip = cidr.split('/')[0]
    ip_bin = ip_to_bin(ip)
    netmask_int = netmask_from_cidr(cidr)
    netmask_bin = netmask_to_binary(netmask_int)
    start, end = '', ''
    for ip_part, netmask_part in zip(ip_bin, netmask_bin):
        start += ip_part if netmask_part == '1' else '0'
        end += ip_part if netmask_part == '1' else '1'
    return bin_to_ip(start), bin_to_ip(end)


def gen_ip_range(start, end):
    """
    Generator for all IP addresses in a range specified by the start and end strings
    :param start(string): the first IP in the range
    :param end(string): the last IP in the range
    :yield: each IP in the range
    """
    while True:
        yield start
        if start != end:
            start = increment_ip(start)
        else:
            break


def gen_ip_range_from_cidr(cidr):
    """
    Generator for all IP addresses specified by a cidr
    :param cidr: specifies the ip range to generate
    :return generator: generator for each IPs
    """
    return gen_ip_range(*cidr_to_ip_range(cidr))


def increment_ip(ip):
    """
    Increment an IP address by 1
    :param ip (str): The IP to increment
    :return str: The incremented IP
    """
    return int_to_ip(ip_to_int(ip) + 1)


def check_ip_in_cidr(ip, cidr):
    """
    return True if the IP is in the range specified
    :param ip(string):
    :param cidr(string):
    :return: True if IP is in the range specified by the cidr, False otherwise
    """
    start, end = cidr_to_ip_range(cidr)
    return ip_to_int(start) <= ip_to_int(ip) <= ip_to_int(end)


def check_ip_in_glob(ip, glob):
    """
    return True if the IP is contained in the range specified by the glob
    :param ip(string):
    :param glob(string):
    """
    glob = glob.rstrip('*')
    return ip.startswith(glob)


def check_ip_in_regex(ip, regex):
    """
    return True if the IP matches the regex
    :param ip (string): IP address
    :param regex (compiled re):regex to match on
    """
    return match(regex, ip) is not None


def check_ip_is_ip(ip, poss_match):
    return ip == poss_match


def route_check(poss_match):
    """Routes check to check funtion for input type"""
    if type(poss_match) is COMPILED_RE_TYPE:
        return check_ip_in_regex
    elif poss_match.endswith('*'):
        return check_ip_in_glob
    elif poss_match.count('/'):
        return check_ip_in_cidr
    return check_ip_is_ip


def check_ip_is_authorized(ip, poss_matches):
    """Check ip against each entry in poss_matches input list"""
    for poss_match in poss_matches:
        func = route_check(poss_match)
        if func(ip, poss_match):
            return True
    return False
