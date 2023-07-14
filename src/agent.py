import asyncio
import json
import os
from typing import Set, Dict

from forta_agent import Finding, FindingType, FindingSeverity
from forta_agent import TransactionEvent
from forta_agent import web3Provider
from hexbytes import HexBytes
from web3 import Web3
import web3

from .logger import logger

BLACKLISTED_ORIGIN_FROM_ADDRS: Set[str] = set()

VALUABLE_ERC20_TOKEN_ADDRS: Set[str] = set()

SUS_ORIGIN_FROM_ADDR_TO_ADDRS: Dict[str, Set] = {}

ERC20_TRANSFER_EVENT = '{"name":"Transfer","type":"event","anonymous":false,"inputs":[{"indexed":true,"name":"from","type":"address"},{"indexed":true,"name":"to","type":"address"},{"indexed":false,"name":"value","type":"uint256"}]}'


def filter_log(txn_event: TransactionEvent, abi: str, contract_address: Set[str]):
    web3.
    abi = abi if isinstance(abi, list) else [abi]
    abi = [json.loads(abi_item) for abi_item in abi]
    logs = txn_event.logs
    contract_address = contract_address if isinstance(contract_address, set) else {contract_address}
    contract_address_map = {address.lower(): True for address in contract_address}
    logs = filter(lambda log: log.address.lower() in contract_address_map, logs)
    event_names = []
    for abi_item in abi:
        if abi_item['type'] == "event":
            event_names.append(abi_item['name'])
    results = []
    contract = web3Provider.eth.contract("0x0000000000000000000000000000000000000000", abi=abi)
    for log in logs:
        log.topics = [HexBytes(topic) for topic in log.topics]
        for event_name in event_names:
            try:
                results.append(
                    contract.events[event_name]().process_log(log))
            except Exception as e:
                logger.error(f'filter_log, exception happened: {e}')
                continue
    return results


def is_contract(w3, address) -> bool:
    if address is None:
        return True
    code = w3.eth.get_code(Web3.to_checksum_address(address))
    return code != HexBytes("0x")


def is_zero_addr(addr: str) -> bool:
    return addr.lower() == '0x0000000000000000000000000000000000000000'


def check_if_origin_from_can_be_blacklisted(origin_from: str, token_to: str) -> bool:
    can_be_blacklisted = False
    if origin_from in SUS_ORIGIN_FROM_ADDR_TO_ADDRS.keys():
        s = SUS_ORIGIN_FROM_ADDR_TO_ADDRS.get(origin_from)
        s.add(token_to)
        if len(s) > 1:
            can_be_blacklisted = True
            del SUS_ORIGIN_FROM_ADDR_TO_ADDRS[origin_from]
    else:
        s = set()
        s.add(token_to)
        SUS_ORIGIN_FROM_ADDR_TO_ADDRS[origin_from] = s
    return can_be_blacklisted


async def process_txn(txn: TransactionEvent) -> list:
    findings = []
    event_data_list = filter_log(txn, ERC20_TRANSFER_EVENT, set(VALUABLE_ERC20_TOKEN_ADDRS))
    origin_from = txn.from_
    for txr_event in event_data_list:
        token_to = txr_event['args']['to']
        token_from_ = txr_event['args']['from']
        token_value = txr_event['args']['value']
        if token_value == 0:
            logger.info(f'is_contract(web3Provider, token_to): {is_contract(web3Provider, token_to)}, '
                        f'is_contract(web3Provider, token_from_): {is_contract(web3Provider, token_from_)}, '
                        f'origin_from: {origin_from}, token_from_: {token_from_}, token_to: {token_to}')
        if token_value > 0 or \
                is_contract(web3Provider, token_to) or \
                is_contract(web3Provider, token_from_) or \
                origin_from is None or \
                origin_from == '' or \
                origin_from == token_from_ or \
                is_zero_addr(token_from_) or \
                is_zero_addr(token_to):
            continue
        found = False
        lower_origin_from = origin_from.lower()
        lower_token_to = token_to.lower()
        lower_token_addr = txr_event['address'].lower()
        if token_value == 0 and lower_token_addr in VALUABLE_ERC20_TOKEN_ADDRS:
            if lower_origin_from in BLACKLISTED_ORIGIN_FROM_ADDRS:
                found = True
            else:
                can_be_blacklisted = check_if_origin_from_can_be_blacklisted(lower_origin_from, lower_token_to)
                if can_be_blacklisted:
                    found = True
                    logger.info(f'found new blacklisted addr: {origin_from}')
                    # TODO(ray): save to persisted storage
                    BLACKLISTED_ORIGIN_FROM_ADDRS.add(lower_origin_from)
        if found:
            findings.append(Finding(
                {
                    'name': 'Zero Token Transfer Attack',
                    'description': f'Zero Token Transferred, '
                                   f'attacker: {origin_from}, '
                                   f'victim: {token_from_}, '
                                   f'phising_address: {token_to}',
                    'alert_id': 'FORTA-ZERO-TOKEN-TXR',
                    'severity': FindingSeverity.High,
                    'type': FindingType.Scam,
                    'metadata': {
                        'origin_from': origin_from,
                        'token_to': token_to,
                        'token_from': token_from_,
                        'token_address': txn.to,
                        'attacker:': origin_from,
                        'victim': token_from_,
                        'phising_address': token_to
                    }
                }
            ))
    if len(findings) > 0:
        logger.info(f'found: {len(findings)} findings, '
                    f'txn_hash: {txn.hash}, '
                    f'blacklisted addresses count: {len(BLACKLISTED_ORIGIN_FROM_ADDRS)}')
    return findings


def provide_handle_transaction():
    def wrapped_handle_transaction(txn: TransactionEvent) -> list:
        return [finding for findings in asyncio.run(main(txn)) for finding in findings]

    return wrapped_handle_transaction


async def main(txn: TransactionEvent):
    return await asyncio.gather(process_txn(txn))


real_handle_transaction = provide_handle_transaction()


def handle_transaction(txn: TransactionEvent):
    return real_handle_transaction(txn)


def _load_set_from_file(file: str) -> Set[str]:
    from os.path import join as join_path
    file_path = join_path(os.path.dirname(__file__), file)
    addr_set = set()
    with open(file_path) as f:
        for line in f.readlines():
            addr_set.add(line.strip().lower())
    return addr_set


def initialize():
    global BLACKLISTED_ORIGIN_FROM_ADDRS
    BLACKLISTED_ORIGIN_FROM_ADDRS = _load_set_from_file('blacklisted_origin_from_addrs.csv')
    logger.info(f'successfully loaded {len(BLACKLISTED_ORIGIN_FROM_ADDRS)} blacklisted addresses')
    global VALUABLE_ERC20_TOKEN_ADDRS
    VALUABLE_ERC20_TOKEN_ADDRS = _load_set_from_file('valuable_erc20_tokens.csv')
    logger.info(f'successfully loaded {len(VALUABLE_ERC20_TOKEN_ADDRS)} tokens')
    global SUS_ORIGIN_FROM_ADDR_TO_ADDRS
    SUS_ORIGIN_FROM_ADDR_TO_ADDRS = {}
