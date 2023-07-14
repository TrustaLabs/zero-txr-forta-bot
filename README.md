# Zero Token Transfer Attack Detect

## Description

This agent detects attacks with zero transfer events

## Supported Chains

- Ethereum

## Alerts

- FORTA-ZERO-TOKEN-TXR
    - Fired when a zero token transfer attack occurs
    - Severity is always set to "High"
    - Type is always set to "scam"
    - origin_from: the transaction originates from which address
    - token_to: the token to which address
    - token_address: the address of the token transferred
    - attacker: the attacker identified, i.e., the origin from address
    - victim: the victim for the token transfer, which could likely be phished
    - phising_address: the phising address which the victim could transfer real token to

## Test Data

The agent behaviour can be verified with the following transactions:

- 0x720b6c867b37db980108947400e2a4ebb6c3fc78a33974ba21c471ad091b3725 (50 findings)

## Test Bot

The bot is deployed at:

- https://explorer.forta.network/bot/0x9da8fdc6fb8e582cdd2be4d36ca861bf9f77652a4db58f7c7449ea359d62a080
