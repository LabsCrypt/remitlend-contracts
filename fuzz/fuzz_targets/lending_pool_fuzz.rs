#![no_main]

use arbitrary::Arbitrary;
use lending_pool::{LendingPool, LendingPoolClient};
use libfuzzer_sys::fuzz_target;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::token::{Client as TokenClient, StellarAssetClient};
use soroban_sdk::{Address, Env, IntoVal, Symbol, Val};
use std::collections::HashMap;

macro_rules! rcall {
    ($env:expr, $client:expr, $func:expr, ($($arg:expr),*)) => {
        $env.try_invoke_contract::<Val, Val>(
            &$client.address,
            &Symbol::new($env, $func),
            ($($arg.clone(),)*).into_val($env)
        )
    };
}

#[derive(Arbitrary, Debug, Clone)]
enum FuzzAction {
    Deposit { user_id: u8, amount: i128 },
    Withdraw { user_id: u8, amount: i128 },
    GetDeposit { user_id: u8 },
    MultipleOperations { operations: Vec<Operation> },
}

#[derive(Arbitrary, Debug, Clone)]
struct Operation {
    user_id: u8,
    amount: i128,
    is_deposit: bool,
}

fn setup_token_contract<'a>(
    env: &Env,
    admin: &Address,
) -> (Address, StellarAssetClient<'a>, TokenClient<'a>) {
    let contract_id = env.register_stellar_asset_contract_v2(admin.clone());
    let stellar_asset_client = StellarAssetClient::new(env, &contract_id.address());
    let token_client = TokenClient::new(env, &contract_id.address());
    (contract_id.address(), stellar_asset_client, token_client)
}

fn assert_no_value_creation(shares: i128, pool_balance: i128, total_shares: i128, redeemable: i128) {
    if total_shares == 0 {
        assert_eq!(redeemable, 0);
        return;
    }
    if let (Some(lhs), Some(rhs)) = (redeemable.checked_mul(total_shares), shares.checked_mul(pool_balance)) {
        assert!(lhs <= rhs, "Value creation from rounding detected");
    } else {
        let q = shares / total_shares;
        let r = shares % total_shares;
        if let Some(term1) = q.checked_mul(pool_balance) {
            if let Some(term2_num) = r.checked_mul(pool_balance) {
                let term2 = term2_num / total_shares;
                if let Some(max_redeemable) = term1.checked_add(term2) {
                    assert!(redeemable <= max_redeemable, "Value creation from rounding detected");
                }
            }
        }
    }
}

macro_rules! safe_call {
    ($expr:expr) => {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| $expr)).unwrap_or_else(|e| {
            panic!("Unexpected contract panic: {:?}", e);
        })
    };
}

pub fn run_fuzz_logic(data: FuzzAction) {
    let env = Env::default();
    env.mock_all_auths();

    // 1. Setup mock asset
    let token_admin = Address::generate(&env);
    let (token_id, stellar_asset_client, token_client) = setup_token_contract(&env, &token_admin);

    // 2. Setup LendingPool
    let pool_id = env.register(LendingPool, ());
    let pool_client = LendingPoolClient::new(&env, &pool_id);

    // 3. Initialize LendingPool with Admin (Contract client wrapper has 1 arg)
    let pool_admin = Address::generate(&env);
    pool_client.initialize(&pool_admin);
    
    // Disable withdrawal cooldown so we can test deposits and withdrawals in the same sequence
    pool_client.set_withdrawal_cooldown(&0);

    match data {
        FuzzAction::Deposit { user_id: _, amount } => {
            let user = Address::generate(&env);

            // Skip invalid amounts
            if amount <= 0 {
                return;
            }

            // Mint tokens to user
            stellar_asset_client.mint(&user, &amount);

            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                rcall!(&env, pool_client, "deposit", (user, token_id, amount))
            }));
            let result = match result {
                Ok(res) => res,
                Err(err) => {
                    panic!("Contract deposit panicked unexpectedly: {:?}", err);
                }
            };

            if result.is_ok() {
                // Verify invariants:
                // 1. Shares minted on deposit must be strictly positive for any positive deposit amount
                let shares = safe_call!(pool_client.get_shares(&user, &token_id));
                assert!(shares > 0, "Shares minted on deposit must be strictly positive");

                // 2. get_deposit's redeemable asset value must never be negative
                let balance = safe_call!(pool_client.get_deposit(&user, &token_id));
                assert!(balance >= 0, "Balance should never be negative");

                // 3. Redeemable value must never exceed what is mathematically possible (no value creation from rounding)
                let cur_total_shares = safe_call!(pool_client.get_total_shares(&token_id));
                let pool_balance = token_client.balance(&pool_id);
                assert_no_value_creation(shares, pool_balance, cur_total_shares, balance);

                // Verify pool token balance
                assert_eq!(
                    token_client.balance(&pool_id),
                    amount,
                    "Pool token balance should match deposit"
                );
            }
        }

        FuzzAction::Withdraw { user_id: _, amount: shares_to_withdraw } => {
            let user = Address::generate(&env);

            // Skip invalid amounts
            if shares_to_withdraw <= 0 {
                return;
            }

            // First deposit some assets to mint shares to allow withdrawal.
            // Since it's a fresh pool, depositing `deposit_amount` of assets will mint `deposit_amount` shares.
            // The minimum initial deposit is 1,000 assets (which mints 1,000 shares).
            // So we need deposit_amount >= 1,000 and deposit_amount >= shares_to_withdraw.
            let deposit_amount = std::cmp::max(shares_to_withdraw, 1_000);
            stellar_asset_client.mint(&user, &deposit_amount);

            let dep_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                pool_client.deposit(&user, &token_id, &deposit_amount)
            }));
            if dep_result.is_err() {
                return;
            }

            let shares_before = safe_call!(pool_client.get_shares(&user, &token_id));

            // withdraw's parameter is a share count, not an asset amount
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                rcall!(&env, pool_client, "withdraw", (user, token_id, shares_to_withdraw))
            }));
            let result = match result {
                Ok(res) => res,
                Err(err) => {
                    panic!("Contract withdraw panicked unexpectedly: {:?}", err);
                }
            };

            if result.is_ok() {
                let shares_after = safe_call!(pool_client.get_shares(&user, &token_id));
                let balance_after = safe_call!(pool_client.get_deposit(&user, &token_id));

                // Verify invariants:
                // 1. shares decreased by shares_to_withdraw
                assert_eq!(
                    shares_before - shares_to_withdraw,
                    shares_after,
                    "Shares should decrease by withdrawal share count"
                );

                // 2. get_deposit's redeemable asset value must never be negative
                assert!(balance_after >= 0, "Balance should never be negative");

                // 3. Redeemable value must never exceed what is mathematically possible (no value creation from rounding)
                let cur_total_shares = safe_call!(pool_client.get_total_shares(&token_id));
                let pool_balance = token_client.balance(&pool_id);
                assert_no_value_creation(shares_after, pool_balance, cur_total_shares, balance_after);
            }
        }

        FuzzAction::GetDeposit { user_id: _ } => {
            let user = Address::generate(&env);
            let balance = safe_call!(pool_client.get_deposit(&user, &token_id));

            // Verify invariant: balance should never be negative
            assert!(balance >= 0, "Balance should never be negative");

            // Verify no value creation from rounding
            let shares = safe_call!(pool_client.get_shares(&user, &token_id));
            let cur_total_shares = safe_call!(pool_client.get_total_shares(&token_id));
            let pool_balance = token_client.balance(&pool_id);
            assert_no_value_creation(shares, pool_balance, cur_total_shares, balance);
        }

        FuzzAction::MultipleOperations { operations } => {
            let mut users = HashMap::new();
            let mut total_expected_deposits = 0i128;

            for op in operations {
                let user_addr = users
                    .entry(op.user_id)
                    .or_insert_with(|| Address::generate(&env))
                    .clone();

                if op.is_deposit {
                    if op.amount <= 0 {
                        continue;
                    }

                    stellar_asset_client.mint(&user_addr, &op.amount);

                    let shares_before = safe_call!(pool_client.get_shares(&user_addr, &token_id));

                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        rcall!(
                            &env,
                            pool_client,
                            "deposit",
                            (user_addr, token_id, op.amount)
                        )
                    }));
                    let result = match result {
                        Ok(res) => res,
                        Err(err) => {
                            panic!("Contract deposit panicked unexpectedly: {:?}", err);
                        }
                    };

                    if result.is_ok() {
                        total_expected_deposits += op.amount;

                        // Verify invariants:
                        // 1. Shares minted on deposit must be strictly positive
                        let shares_after = safe_call!(pool_client.get_shares(&user_addr, &token_id));
                        assert!(shares_after > shares_before, "Shares minted on deposit must be strictly positive");

                        // 2. get_deposit's redeemable asset value must never be negative
                        let balance = safe_call!(pool_client.get_deposit(&user_addr, &token_id));
                        assert!(balance >= 0, "Balance should never be negative");

                        // 3. Redeemable value must never exceed what is mathematically possible (no value creation from rounding)
                        let cur_total_shares = safe_call!(pool_client.get_total_shares(&token_id));
                        let pool_balance = token_client.balance(&pool_id);
                        assert_no_value_creation(shares_after, pool_balance, cur_total_shares, balance);
                    }
                } else {
                    let shares_to_withdraw = op.amount;
                    if shares_to_withdraw <= 0 {
                        continue;
                    }

                    let shares_before = safe_call!(pool_client.get_shares(&user_addr, &token_id));
                    let pool_balance_before = token_client.balance(&pool_id);

                    // withdraw's parameter is a share count, not an asset amount
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        rcall!(&env, pool_client, "withdraw", (user_addr, token_id, shares_to_withdraw))
                    }));
                    let result = match result {
                        Ok(res) => res,
                        Err(err) => {
                            panic!("Contract withdraw panicked unexpectedly: {:?}", err);
                        }
                    };

                    if result.is_ok() {
                        let pool_balance_after = token_client.balance(&pool_id);
                        let assets_withdrawn = pool_balance_before - pool_balance_after;
                        total_expected_deposits -= assets_withdrawn;

                        let shares_after = safe_call!(pool_client.get_shares(&user_addr, &token_id));
                        let balance_after = safe_call!(pool_client.get_deposit(&user_addr, &token_id));

                        // Verify invariants:
                        // 1. shares decreased by shares_to_withdraw
                        assert_eq!(
                            shares_before - shares_to_withdraw,
                            shares_after,
                            "Shares should decrease by withdrawal share count"
                        );

                        // 2. get_deposit's redeemable asset value must never be negative
                        assert!(balance_after >= 0, "Balance should never be negative");

                        // 3. Redeemable value must never exceed what is mathematically possible (no value creation from rounding)
                        let cur_total_shares = safe_call!(pool_client.get_total_shares(&token_id));
                        assert_no_value_creation(shares_after, pool_balance_after, cur_total_shares, balance_after);
                    }
                }
            }

            // Verify invariant: total deposits match pool token balance
            assert_eq!(
                token_client.balance(&pool_id),
                total_expected_deposits,
                "Total deposits should match pool token balance"
            );

            // Verify all individual balances are non-negative and satisfy the no value creation invariant
            for (_, user_addr) in users {
                let shares = safe_call!(pool_client.get_shares(&user_addr, &token_id));
                let balance = safe_call!(pool_client.get_deposit(&user_addr, &token_id));
                assert!(balance >= 0, "Individual balance should never be negative");

                let cur_total_shares = safe_call!(pool_client.get_total_shares(&token_id));
                let pool_balance = token_client.balance(&pool_id);
                assert_no_value_creation(shares, pool_balance, cur_total_shares, balance);
            }
        }
    }
}

fuzz_target!(|data: FuzzAction| {
    run_fuzz_logic(data);
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fuzz_sanity() {
        let test_cases = vec![
            FuzzAction::Deposit { user_id: 1, amount: 500 }, // < MINIMUM_INITIAL_DEPOSIT (should fail)
            FuzzAction::Deposit { user_id: 1, amount: 2000 }, // OK
            FuzzAction::Deposit { user_id: 2, amount: 1500 }, // OK
            FuzzAction::Withdraw { user_id: 1, amount: 500 }, // OK (withdraws 500 shares)
            FuzzAction::Withdraw { user_id: 2, amount: 3000 }, // exceeds shares (should fail)
            FuzzAction::GetDeposit { user_id: 1 },
            FuzzAction::GetDeposit { user_id: 3 }, // new user (0 shares)
            FuzzAction::MultipleOperations {
                operations: vec![
                    Operation { user_id: 1, amount: 1500, is_deposit: true },
                    Operation { user_id: 2, amount: 2500, is_deposit: true },
                    Operation { user_id: 1, amount: 500, is_deposit: false },
                    Operation { user_id: 2, amount: 1000, is_deposit: false },
                    Operation { user_id: 3, amount: 100, is_deposit: false }, // should fail
                ]
            }
        ];

        for case in test_cases {
            run_fuzz_logic(case);
        }
    }
}
