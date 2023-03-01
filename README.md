# Derivative minter contract

This contract enables users to send SHD(or any SNIP-20) and receive a staking derivative token that can later be sent to the contract to unbond the sent amount's value in SHD(SNIP-20).

## Init Message

```ts
interface InitMsg {
  name: string;
  admin: string;
  symbol: string;
  prng_seed: string;
  staking_contract_info: ContractInfo;
  authentication_contract_info: ContractInfo;
  shade_contract_info: ContractInfo;
  fee_info: FeeInfo;
}

interface ContractInfo {
  address: string;
  code_hash: string;
  entropy: string;
}

interface FeeInfo {
  staking_fee: Fee;
  unbonding_fee: Fee;
}

interface Fee {
  collector: string;
  rate: number;
}
```

```json
{
  "name": "contract's name",
  "admin": "optional_admin_address",
  "symbol": "contract's symbol",
  "prng_seed": "base_64_encoded_string",
  "staking_contract_info": {
    "address": "contract_address",
    "code_hash": "contract_code_hash",
    "entropy": "optional_string_used_for_padding_transactions_to_this_contract"
  },
  "authentication_contract_info": {
    "address": "contract_address",
    "code_hash": "contract_code_hash",
    "entropy": "optional_string_used_for_padding_transactions_to_this_contract"
  },
  "shade_contract_info": {
    "address": "contract_address",
    "code_hash": "contract_code_hash",
    "entropy": "optional_string_used_for_padding_transactions_to_this_contract"
  },
  "fee_info": {
    "staking_fee": {
      "collector": "wallet_address_collecting_this_fee",
      "rate": 100000 // rate is 5 decimal places: eg. 1% -> 100000
    },
    "unbonding_fee": {
      "collector": "wallet_address_collecting_this_fee",
      "rate": 100000 // rate is 5 decimal places: eg. 1% -> 100000
    }
  }
}
```
