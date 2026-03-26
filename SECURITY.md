# Security

This document outlines security best practices and checklist items for Callora vault contracts to improve audit readiness and reviewer confidence.

## 🔐 Vault Security Checklist

### Access Control

- [ ] All privileged functions protected by `require_auth()` or `require_auth_for_args()` via `Address`
- [ ] Admin state stored securely (e.g., using `env.storage().instance()`)
- [ ] Admin rotation/transfer tested and documented

### Arithmetic Safety

- [ ] No integer overflow/underflow possible
- [ ] `checked_add` / `checked_sub` / `checked_mul` / `checked_div` used for all balance operations
- [ ] `overflow-checks = true` explicitly enabled in `[profile.release]` inside `Cargo.toml`

### Initialization / Re-initialization

- [ ] `initialize` function protected against multiple calls (e.g., checking if admin key exists in `instance()` storage)
- [ ] Contract upgrades (`env.deployer().update_current_contract_wasm()`) protected by `require_auth()`
- [ ] No unprotected re-init functions
- [ ] `initialize` validates all input parameters

### Pause / Circuit Breaker

- [ ] Emergency pause mechanism implemented via state flag in `instance()` storage
- [ ] Paused state blocks fund movement (e.g., reverting via `panic_with_error!`)
- [ ] Pause/unpause flows tested

### Admin Transfer

- [ ] Admin transfer is two-step (optional but recommended)
- [ ] Admin transfer emits corresponding events
- [ ] Renouncing admin functionally reviewed and justified

### External Calls

- [ ] Token transfers strictly rely on `soroban_sdk::token::Client`
- [ ] Cross-contract calls handle potential errors/panics gracefully
- [ ] State changes are persisted before making cross-contract calls to mitigate subtle state-caching issues
- [ ] Checks-effects-interactions pattern followed

### Vault-Specific Risks

- [ ] Deposit/withdraw invariants tested
- [ ] Vault balance accounting verified
- [ ] Funds cannot be locked permanently
- [ ] Minimum deposit requirements enforced
- [ ] Maximum deduction limits enforced
- [ ] Revenue pool transfers validated
- [ ] Batch operations respect individual limits

### Input Validation

- [ ] All amounts validated to be > 0
- [ ] Address/parameter validation on all public functions
- [ ] Boundary conditions tested (max values, zero values)
- [ ] Error messages provide clear context for debugging

### Event Logging

- [ ] All state changes emit appropriate events
- [ ] Event schema documented and indexed
- [ ] Critical operations (deposit, withdraw, deduct) logged with full context

### Testing Coverage

- [ ] Unit tests cover all public functions
- [ ] Edge cases and boundary conditions tested
- [ ] Panic scenarios tested with `#[should_panic]`
- [ ] Integration tests for complete user flows
- [ ] Minimum 95% test coverage maintained

## External Audit Recommendation

Before any mainnet deployment:

- **Engage an independent third-party security auditor**
  - Choose auditors with experience in Soroban/Stellar smart contracts
  - Ensure auditor understands vault-specific risk patterns

- **Perform a full smart contract audit**
  - Review all contract code for security vulnerabilities
  - Analyze upgrade patterns and migration paths
  - Validate mathematical correctness of balance operations

- **Address all high and medium severity findings**
  - Create tracking system for audit findings
  - Implement fixes for all H/M severity issues
  - Document rationale for any low severity findings that won't be fixed

- **Publish audit report for transparency**
  - Make audit report publicly available
  - Include summary of findings and remediation steps
  - Provide evidence of test coverage and validation

## Additional Security Considerations

### Soroban-Specific Security

- [ ] WASM compilation verified and reproducible (`stellar contract build` / `cargo build --target wasm32-unknown-unknown --release`)
- [ ] Storage lifespan (`extend_ttl`) implemented to prevent state archiving for critical data
- [ ] Stellar network parameters validated (budget, CPU/RAM limits)
- [ ] Cross-contract call security and generic type usage (`Val`) reviewed
- [ ] Storage patterns optimized and secure (e.g., correct usage of `persistent` vs `instance` vs `temporary` keys)

### Economic Security

- [ ] Fee structures reviewed for economic attacks
- [ ] Revenue pool distribution validated
- [ ] Maximum loss scenarios analyzed
- [ ] Slippage and market impact considered

### Operational Security

- [ ] Deployment process documented and automated
- [ ] Key management procedures established
- [ ] Monitoring and alerting configured
- [ ] Incident response plan prepared

## Security Resources

- [Stellar Security Best Practices](https://developers.stellar.org/docs/security/)
- [Soroban Documentation](https://developers.stellar.org/docs/smart-contracts/)
- [Smart Contract Weakness Classification Registry](https://swcregistry.io/)

---

**Note**: This checklist should be reviewed and updated regularly as new security patterns emerge and the codebase evolves.
