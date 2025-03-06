Examples
========

Please see the [test suite](https://github.com/past-hypothesis/near-py-tool/blob/main/near_py_tool/tests) for various low-level NEAR API usage examples:
- deploy_contract.py / promise_api.py - building and deploying a dependent contract with promises via promise_batch_action_deploy_contract()
- lowlevel_api.py - minimal storage api usage example
- fungible_token.py - low-level API port of https://github.com/near/near-sdk-rs/tree/master/near-contract-standards/src/fungible_token contract
- non_fungible_token.py - low-level API port of https://github.com/near/near-sdk-rs/tree/master/near-contract-standards/src/non_fungible_token contract

External examples:
- The smart contract that guards 3000 NEAR and gives away 2 NEAR per user and prevents double-spend: https://github.com/frol/1t-agents-fundme-agent
- The smart contract that guards 50 NEAR until it is jailbreaked: https://github.com/frol/neardevnewsletter-issue50-quest/tree/main/contract
- Demo Web4 contract in Python: https://github.com/frol/near-web4-demo-py
