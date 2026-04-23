use crate::*;
use soroban_sdk::{Address, Env};

#[cfg(test)]
mod zero_address_tests {
    use super::*;
    use soroban_sdk::testutils::Address as _;

    fn create_contract() -> AdminContract {
        AdminContract {}
    }

    fn setup_contract(env: &Env) -> (Address, Address) {
        let contract = create_contract();
        let super_admin = Address::generate(env);
        let contract_address = env.register_contract(None, AdminContract);

        env.mock_all_auths();

        env.as_contract(&contract_address, || {
            AdminContract::initialize(env.clone(), super_admin.clone(), 1, 100);
        });

        (contract_address, super_admin)
    }

    #[test]
    fn test_valid_addresses_succeed() {
        let env = Env::default();
        let (contract_address, super_admin) = setup_contract(&env);
        let new_admin = Address::generate(&env);

        env.mock_all_auths();

        env.as_contract(&contract_address, || {
            // This should succeed
            let admin_info = AdminContract::add_admin(
                env.clone(),
                super_admin.clone(),
                new_admin.clone(),
                AdminRole::Admin,
            );
            assert_eq!(admin_info.address, new_admin);
            assert_eq!(admin_info.role, AdminRole::Admin);
        });
    }
}
