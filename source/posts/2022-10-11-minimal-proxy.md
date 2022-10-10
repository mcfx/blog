title: "\"Minimal\" Arbitrary Proxy"
tags:
  - Blockchain
#! meta end

薅羊毛用（

#! head end

**Update:** you can use `CALLDATALOAD` instead of `CALLDATACOPY` and `MLOAD`, I forgot about that.

Inspired by https://blog.openzeppelin.com/deep-dive-into-the-minimal-proxy-contract/, we can build a similar one, but allows arbitrary `delegatecall` target.

In order to save gas, we only store the target address in input data (which we can deploy one for each airdrop target), don't allow call data for the `delegatecall`, and ignore the return value.

Here's the main code:

| Code       | Instruction                         | Stack                   | Memory / Comments                                                                         |
| ---------- | ----------------------------------- | ----------------------- | ----------------------------------------------------------------------------------------- |
| 363d3d37   | Similar to part 1 in the link above | -                       | [0, cds] = calldata (target addr)                                                         |
| 3d3d3d3d3d | RETURNDATASIZE \* 5                 | 0 0 0 0 0               | [0, cds] = addr                                                                           |
| 51         | MLOAD                               | addr 0 0 0 0            | (no longer used)                                                                          |
| 5a         | GAS                                 | gas addr 0 0 0 0        |                                                                                           |
| 32         | ORIGIN                              | origin ...              |                                                                                           |
| 73 origin  | PUSH20 `allowed origin`             | allowed origin ...      |                                                                                           |
| 18         | XOR                                 | [zero if allowed] ...   |                                                                                           |
| 3d         | RETURNDATASIZE                      | 0 [zero if allowed] ... |                                                                                           |
| 57         | JUMPI                               | gas addr 0 0 0 0        | If the origin is not allowed, it will jump to zero, which is not a valid jump destination |
| f4         | DELEGATECALL                        | success                 |                                                                                           |
| 3d3d       | RETURNDATASIZE                      | 0 0 success             | The call target should make `rds=0`                                                       |
| f3         | RETURN                              | success                 |                                                                                           |

Then the runtime code is:

```
363d3d373d3d3d3d3d515a3273
[origin]
183d57f43d3df3
```

We can also make a call in the creation code. The analysis is similar, and omitted. Here is the final code:

```
3d60288060263d398180808073
[first delegatecall target]
5af45081f3
363d3d373d3d3d3d3d515a3273
[origin]
183d57f43d3df3
```