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
    fn test_zero_address_format() {
        let env = Env::default();
        let zero_address = Address::from_string(&String::from_str(&env, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
        let zero_str = String::from_str(&env, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        
        // Verify the zero address format
        assert_eq!(zero_address.to_string(), zero_str);
    }

    #[test]
    fn test_valid_addresses_succeed() {
        let env = Env::default();
        let (contract_address, super_admin) = setup_contract(&env);
        let new_admin = Address::generate(&env);
        let new_owner = Address::generate(&env);
        let pause_signer = Address::generate(&env);

        env.mock_all_auths();
        
        env.as_contract(&contract_address, || {
            // These should all succeed
            let admin_info = AdminContract::add_admin(
                env.clone(),
                super_admin.clone(),
                new_admin.clone(),
                AdminRole::Admin,
            );
            assert_eq!(admin_info.address, new_admin);
            assert_eq!(admin_info.role, AdminRole::Admin);

            // Add the new admin as SuperAdmin for ownership transfer
            AdminContract::add_admin(
                env.clone(),
                super_admin.clone(),
                new_owner.clone(),
                AdminRole::SuperAdmin,
            );

            AdminContract::transfer_ownership(
                env.clone(),
                super_admin.clone(),
                new_owner.clone(),
            );

            AdminContract::set_pause_signer(
                env.clone(),
                new_owner.clone(),
                pause_signer.clone(),
                true,
            );
        });
    }
}
