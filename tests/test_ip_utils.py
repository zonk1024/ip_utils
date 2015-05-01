from ip_utils import util
from re import compile
import pytest


def test_netmask_from_cidr():
    assert util.netmask_from_cidr('192.168.1.0/24') == 24
    assert util.netmask_from_cidr('192.168.1.0/25') == 25
    assert util.netmask_from_cidr('0.0.0.0/0') == 0


def test_netmask_to_binary():
    """Converts cidr ('192.168.1.0/24'), an int, or ip-type to a binary representation"""
    assert util.netmask_to_binary(0) == '00000000000000000000000000000000'
    assert util.netmask_to_binary(8) == '11111111000000000000000000000000'
    assert util.netmask_to_binary(12) == '11111111111100000000000000000000'
    assert util.netmask_to_binary(32) == '11111111111111111111111111111111'


def test_ip_to_int():
    assert util.ip_to_int('0.0.0.0') == 0
    assert util.ip_to_int('192.168.1.1') == 3232235777
    assert util.ip_to_int('255.255.255.255') == 4294967295


def test_ip_to_bin():
    assert util.ip_to_bin('255.255.255.255') == '11111111111111111111111111111111'
    assert util.ip_to_bin('255.255.255.0') == '11111111111111111111111100000000'
    assert util.ip_to_bin('255.255.0.0') == '11111111111111110000000000000000'


def test_int_to_ip():
    assert util.int_to_ip(0) == '0.0.0.0'
    assert util.int_to_ip(3232235777) == '192.168.1.1'
    assert util.int_to_ip(4294967295) == '255.255.255.255'


def test_bin_to_ip():
    assert util.bin_to_ip('11111111111111111111111111111111') == '255.255.255.255'
    assert util.bin_to_ip('11111111111111111111111100000000') == '255.255.255.0'
    assert util.bin_to_ip('11111111111111110000000000000000') == '255.255.0.0'
    assert util.bin_to_ip('11111111000000000000000000000000') == '255.0.0.0'
    assert util.bin_to_ip('00000000000000000000000000000000') == '0.0.0.0'
    assert util.bin_to_ip('00000000000000000000000000000010') == '0.0.0.2'
    assert util.bin_to_ip('00000000000000000000000000001010') == '0.0.0.10'
    assert util.bin_to_ip('00000000000000000000000000101010') == '0.0.0.42'


def test_cidr_to_ip_range():
    assert util.cidr_to_ip_range('192.168.1.0/24') == ('192.168.1.0', '192.168.1.255')
    assert util.cidr_to_ip_range('10.0.0.0/8') == ('10.0.0.0', '10.255.255.255')
    assert util.cidr_to_ip_range('172.16.0.0/12') == ('172.16.0.0', '172.31.255.255')
    assert util.cidr_to_ip_range('0.0.0.0/0') == ('0.0.0.0', '255.255.255.255')


def test_gen_ip_range():
    ip_format = '192.168.1.{}'
    for i, ip in enumerate(util.gen_ip_range('192.168.1.0', '192.168.1.255')):
        assert ip == ip_format.format(i)


def test_gen_ip_range_from_cidr():
    ip_format = '192.168.1.{}'
    for i, ip in enumerate(util.gen_ip_range_from_cidr('192.168.1.0/24')):
        assert ip == ip_format.format(i)


def test_increment_ip():
    assert util.increment_ip('192.168.1.1') == '192.168.1.2'
    assert util.increment_ip('192.168.1.254') == '192.168.1.255'
    assert util.increment_ip('192.168.1.255') == '192.168.2.0'


def test_check_ip_in_cidr():
    assert util.check_ip_in_cidr('192.168.1.2', '192.168.1.0/24')
    assert not util.check_ip_in_cidr('192.168.1.2', '192.168.2.0/24')
    assert util.check_ip_in_cidr('192.168.1.5', '0.0.0.0/0')
    assert not util.check_ip_in_cidr('192.168.1.5', '10.0.0.0/8')
    assert util.check_ip_in_cidr('192.168.1.1', '192.168.1.0/30')
    assert not util.check_ip_in_cidr('192.168.1.8', '192.168.1.0/30')


def test_check_ip_in_glob():
    assert util.check_ip_in_glob('192.168.1.1', '192.168.1.*')
    assert not util.check_ip_in_glob('192.168.1.1', '192.168.2.*')
    assert util.check_ip_in_glob('10.1.2.3', '10.*')
    assert not util.check_ip_in_glob('10.1.2.3', '11.*')
    assert util.check_ip_in_glob('172.16.2.3', '172.16.*')
    assert not util.check_ip_in_glob('172.16.2.3', '10.*')


def test_check_ip_in_regex():
    assert util.check_ip_in_regex('192.168.1.1', compile(r'192\.168\..*'))
    assert not util.check_ip_in_regex('192.167.1.1', compile(r'192\.168\..*'))
    assert util.check_ip_in_regex('192.168.1.1', compile(r'192\.[^.]*.1\..*'))
    assert not util.check_ip_in_regex('192.168.2.1', compile(r'192\.[^.]*.1\..*'))
    assert util.check_ip_in_regex('192.168.1.1', compile(r'^192\.([0-9]*\.){2}.*$'))
    assert not util.check_ip_in_regex('192.168.1.2', compile(r'192\.([0-9]*\.){2}\.3'))


def test_check_ip_is_ip():
    assert util.check_ip_is_ip('192.168.1.1', '192.168.1.1')
    assert not util.check_ip_is_ip('192.168.1.1', '192.168.1.2')


def test_route_check():
    assert util.route_check('192.168.1.*') is util.check_ip_in_glob
    assert util.route_check('192.168.1.0/24') is util.check_ip_in_cidr
    assert util.route_check(compile('192\.168\.1\..*')) is util.check_ip_in_regex
    assert util.route_check('192.168.1.1') is util.check_ip_is_ip


def test_check_ip_is_authorized():
    assert util.check_ip_is_authorized('192.168.1.1', ['127.0.0.1', '192.168.1.1'])
    assert not util.check_ip_is_authorized('192.168.1.1', ['127.0.0.1', '192.168.1.0'])
    assert util.check_ip_is_authorized('192.168.1.1', ['12.168.1.*'])
    assert not util.check_ip_is_authorized('192.168.1.1', ['192.168.2.*'])
    assert util.check_ip_is_authorized('192.168.1.1', ['192.168.1.0/24'])
    assert not util.check_ip_is_authorized('192.168.1.1', ['192.168.2.0/24'])
    assert util.check_ip_is_authorized('192.168.1.1', [compile('192\.168\.1\..*')])
    assert not util.check_ip_is_authorized('192.168.1.1', [compile('192\.168\.2\..*')])
