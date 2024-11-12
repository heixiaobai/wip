#!/bin/python3
import argparse
import configparser
import hashlib
import logging
import os
import socket
import subprocess
import sys
from abc import abstractmethod, ABCMeta
from re import match
from time import sleep
from typing import Callable

OS_LIST = ["linux"]


class InitError(Exception):
    def __init__(self, *args: object) -> None:
        super().__init__(*args)


class PasswordError(Exception):
    def __init__(self, *args: object) -> None:
        super().__init__(*args)


class IPError(Exception):
    def __init__(self, *args: object) -> None:
        super().__init__(*args)


class IPAddress:
    def __init__(self, ip_address) -> None:
        self.ip: str = self.set_ip(ip_address)

    @staticmethod
    def set_ip(ip_address: str) -> str:
        IPv4_REX = r"^([0-9]{,3}\.){3}[0-9]{,3}$"
        if match(IPv4_REX, ip_address):
            return ip_address.__str__()
        else:
            raise IPError

    def __str__(self) -> str:
        return self.ip

    def __repr__(self) -> str:
        return self.__repr__()


class FirewallMeta(metaclass=ABCMeta):

    @staticmethod
    @abstractmethod
    def check():
        """check firewall is action"""
        pass

    @staticmethod
    @abstractmethod
    def accept_ip(ip: IPAddress) -> bool:
        """accept ip"""
        pass


class FirewallD(FirewallMeta):
    def __init__(self) -> None:
        super().__init__()

    @staticmethod
    def check():
        status = os.system(f'systemctl is-active firewalld.service')
        if status == 0:
            return True
        return False

    @staticmethod
    def accept_ip(ip: IPAddress):
        firewall_rich = f"rule family='ipv4' source address='{ip}' accept"
        status = os.system(f'firewall-cmd --add-rich-rule="{firewall_rich}"')
        if status != 0:
            return False
        return True


class NFT(FirewallMeta):
    def __init__(self) -> None:
        super().__init__()

    @staticmethod
    def check():
        status, stdout = subprocess.getstatusoutput('iptables -V')
        if status != 0:
            return False
        if 'nf_tables' not in stdout:
            return False
        return True

    @staticmethod
    def accept_ip(ip):
        # TODO
        return False


class IPTables(FirewallMeta):
    def __init__(self) -> None:
        super().__init__()

    @staticmethod
    def check():
        status, stdout = subprocess.getstatusoutput('iptables -V')
        if status != 0:
            return False
        if 'nf_tables' not in stdout:
            return False
        return True

    @staticmethod
    def accept_ip(ip):
        iptables_rule = f"INPUT -s {ip}/32 -j ACCEPT"
        status, _ = subprocess.getstatusoutput(f"iptables -C {iptables_rule}")
        if status == 2:
            # STATUS(2): command option '-C' is no supported (old iptables version)
            status, _ = subprocess.getstatusoutput(
                f'iptables-save | grep -- "-A {iptables_rule}"')
        if status == 0:
            logging.info("rule is exist")
            return True

        status, _ = subprocess.getstatusoutput(f'iptables -A {iptables_rule}')
        if status != 0:
            logging.error("iptables accept ip failed")
            return False
        return True


def check_os():
    _os = sys.platform
    if _os not in OS_LIST:
        raise InitError("the OS is not supported")


def get_firewall_object() -> Callable[[IPAddress], bool]:
    firewall_list: list[FirewallMeta] = [
        FirewallD(),
        IPTables()
    ]
    for f in firewall_list:
        if f.check():
            logging.info(f"use firewall object: {f.__class__.__name__}")
            return f.accept_ip
    raise InitError("all firewall is not supported")


# Config
SECTION = "main"
BIND_IP = "bind_ip"
BIND_PORT = "bind_port"
PASS_HASH = "password_hash_sha256"


def get_config() -> dict:
    CONFIG_PATH_LIST = [
        "/etc/wip.conf",
        "/usr/local/etc/wip.conf"
    ]
    options = [
        BIND_IP,
        BIND_PORT,
        PASS_HASH
    ]
    config_data = {}
    config = configparser.ConfigParser()

    if cmd_args.config is None:
        for path in CONFIG_PATH_LIST:
            if config.read(path):
                break
    else:
        config.read(cmd_args.config)

    if not config.sections():
        raise InitError(f"confile path is not exist or format error")

    for option in options:
        if config.has_option(SECTION, option) is True:
            config_data[option] = config[SECTION][option]
        else:
            raise InitError(f"config {SECTION}.{option} is not exist")
    config_data[BIND_PORT] = int(config_data[BIND_PORT])

    if config_data[BIND_PORT] not in range(1024, 65535):
        raise InitError(f"config {SECTION}.{BIND_PORT} range: 1024~65535")

    if len(config_data[PASS_HASH]) != 64:
        raise InitError(f"config {SECTION}.{PASS_HASH} is not a sha256 value")

    return config_data


def shutdown():
    udp_socket.close()
    logging.info("wip stopped")
    exit(0)


if __name__ == "__main__":
    # init
    try:
        logging.basicConfig(level=logging.INFO)
        parser = argparse.ArgumentParser(description="white IP")
        parser.add_argument('-c', '--config', required=False,
                            type=str, help='config file')
        # TODO
        # parser.add_argument('-f', '--firewall', required=False,
        #                     type=str, help='firewall')
        # get commandline args
        cmd_args = parser.parse_args()
        # check OS
        check_os()
        # get config
        conf = get_config()
        # get firewall function
        allow_ip = get_firewall_object()
        # create a UDP socket
        udp_socket = socket.socket(type=socket.SOCK_DGRAM)
        # bind listen IP and Port
        udp_socket.bind((conf[BIND_IP], int(conf[BIND_PORT])))
    except InitError as e:
        logging.error(e)
        exit(1)

    logging.info("server started")
    while True:
        msg, addr = udp_socket.recvfrom(1024)
        try:
            src_ip = IPAddress(addr[0])
            logging.info(f"source {src_ip}")
            password_text = msg.decode('ascii').replace("\n", "")
            password_hash = hashlib.sha256(password_text.encode('ascii')).hexdigest()
            logging.debug(f"source {src_ip} password sha256: {password_hash}")
            if password_hash != conf[PASS_HASH]:
                logging.warning(f"source {src_ip} password error")
                raise PasswordError
            allow_ip(src_ip)
            logging.info(f"source {src_ip} allow accept")
        except PasswordError:
            logging.warning("password error")
        except IPError:
            logging.warning("Hacker?")
        except KeyboardInterrupt:
            shutdown()
        sleep(0.5)
