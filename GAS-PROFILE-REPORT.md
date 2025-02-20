## `near-py-tool` test run gas statistics
### deploy_contract({})
- Gas used to execute the receipt (actual contract call): `25.94T`
  - `CREATE_ACCOUNT`: `3.85T`
  - `DEPLOY_CONTRACT_BASE`: `184.77G`
  - `DEPLOY_CONTRACT_BYTE`: `18.19T`
  - `FUNCTION_CALL_BASE`: `200.00G`
  - `FUNCTION_CALL_BYTE`: `1.14G`
  - `NEW_ACTION_RECEIPT`: `108.06G`
  - `TRANSFER`: `115.12G`
  - `BASE`: `1.59G`
  - `CONTRACT_LOADING_BASE`: `0.04G`
  - `CONTRACT_LOADING_BYTES`: `830.44G`
  - `PROMISE_RETURN`: `0.56G`
  - `READ_MEMORY_BASE`: `15.66G`
  - `READ_MEMORY_BYTE`: `1.45T`
  - `UTF8_DECODING_BASE`: `3.11G`
  - `UTF8_DECODING_BYTE`: `11.08G`
  - `WASM_INSTRUCTION`: `86.17G`
### expensive(100)
- Gas used to execute the receipt (actual contract call): `1.48T`
  - `BASE`: `1.06G`
  - `CONTRACT_LOADING_BASE`: `0.04G`
  - `CONTRACT_LOADING_BYTES`: `414.27G`
  - `READ_MEMORY_BASE`: `2.61G`
  - `READ_MEMORY_BYTE`: `0.01G`
  - `READ_REGISTER_BASE`: `2.52G`
  - `READ_REGISTER_BYTE`: `0.00G`
  - `WASM_INSTRUCTION`: `167.42G`
  - `WRITE_MEMORY_BASE`: `2.80G`
  - `WRITE_MEMORY_BYTE`: `0.01G`
  - `WRITE_REGISTER_BASE`: `2.87G`
  - `WRITE_REGISTER_BYTE`: `0.01G`
### expensive(10000)
- Gas used to execute the receipt (actual contract call): `13.49T`
  - `BASE`: `1.06G`
  - `CONTRACT_LOADING_BASE`: `0.04G`
  - `CONTRACT_LOADING_BYTES`: `414.27G`
  - `READ_MEMORY_BASE`: `2.61G`
  - `READ_MEMORY_BYTE`: `0.02G`
  - `READ_REGISTER_BASE`: `2.52G`
  - `READ_REGISTER_BYTE`: `0.00G`
  - `WASM_INSTRUCTION`: `12.18T`
  - `WRITE_MEMORY_BASE`: `2.80G`
  - `WRITE_MEMORY_BYTE`: `0.01G`
  - `WRITE_REGISTER_BASE`: `2.87G`
  - `WRITE_REGISTER_BYTE`: `0.02G`
### expensive(20000)
- Gas used to execute the receipt (actual contract call): `25.62T`
  - `BASE`: `1.06G`
  - `CONTRACT_LOADING_BASE`: `0.04G`
  - `CONTRACT_LOADING_BYTES`: `414.27G`
  - `READ_MEMORY_BASE`: `2.61G`
  - `READ_MEMORY_BYTE`: `0.02G`
  - `READ_REGISTER_BASE`: `2.52G`
  - `READ_REGISTER_BYTE`: `0.00G`
  - `WASM_INSTRUCTION`: `24.31T`
  - `WRITE_MEMORY_BASE`: `2.80G`
  - `WRITE_MEMORY_BYTE`: `0.01G`
  - `WRITE_REGISTER_BASE`: `2.87G`
  - `WRITE_REGISTER_BYTE`: `0.02G`
### lowlevel_storage_write({})
- Gas used to execute the receipt (actual contract call): `1.69T`
  - `BASE`: `0.26G`
  - `CONTRACT_LOADING_BASE`: `0.04G`
  - `CONTRACT_LOADING_BYTES`: `414.40G`
  - `READ_MEMORY_BASE`: `5.22G`
  - `READ_MEMORY_BYTE`: `0.08G`
  - `STORAGE_WRITE_BASE`: `64.20G`
  - `STORAGE_WRITE_KEY_BYTE`: `0.70G`
  - `STORAGE_WRITE_VALUE_BYTE`: `0.31G`
  - `TOUCHING_TRIE_NODE`: `273.73G`
  - `WASM_INSTRUCTION`: `47.68G`
### lowlevel_storage_write_many({})
- Gas used to execute the receipt (actual contract call): `2.50T`
  - `BASE`: `7.94G`
  - `CONTRACT_LOADING_BASE`: `0.04G`
  - `CONTRACT_LOADING_BYTES`: `414.40G`
  - `READ_MEMORY_BASE`: `52.20G`
  - `READ_MEMORY_BYTE`: `0.76G`
  - `READ_REGISTER_BASE`: `25.17G`
  - `READ_REGISTER_BYTE`: `0.01G`
  - `STORAGE_WRITE_BASE`: `641.97G`
  - `STORAGE_WRITE_EVICTED_BYTE`: `3.21G`
  - `STORAGE_WRITE_KEY_BYTE`: `7.05G`
  - `STORAGE_WRITE_VALUE_BYTE`: `3.10G`
  - `TOUCHING_TRIE_NODE`: `322.04G`
  - `WASM_INSTRUCTION`: `72.58G`
  - `WRITE_MEMORY_BASE`: `28.04G`
  - `WRITE_MEMORY_BYTE`: `0.27G`
  - `WRITE_REGISTER_BASE`: `28.66G`
  - `WRITE_REGISTER_BYTE`: `0.38G`
### empty({})
- Gas used to execute the receipt (actual contract call): `1.34T`
  - `CONTRACT_LOADING_BASE`: `0.04G`
  - `CONTRACT_LOADING_BYTES`: `414.02G`
  - `WASM_INSTRUCTION`: `33.57G`
