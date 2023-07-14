from hexbytes import HexBytes
from web3 import Web3


def is_contract(w3, address) -> bool:
    if address is None:
        return True
    code = w3.eth.get_code(Web3.to_checksum_address(address))
    return code != HexBytes("0x")


def is_zero_addr(addr: str) -> bool:
    return addr.lower() == '0x0000000000000000000000000000000000000000'
