use crate::*;
use soroban_sdk::{Address, Env};

#[cfg(test)]
mod immutable_config_tests {
    use super::*;
    use soroban_sdk::testutils::Address as _;

    fn create_contract() -> AdminContract {
        AdminContract {}
    }

    #[test]
    fn test_config_requires_initialization() {
        let env = Env::default();
        let contract = create_contract();
        let contract_address = env.register_contract(None, AdminContract);

        env.mock_all_auths();
        
        env.as_contract(&contract_address, || {
            let result = std::panic::catch_unwind(|| {
                AdminContract::get_config(env.clone());
            });
            
            assert!(result.is_err());
            let panic_msg = result.unwrap_err().downcast::<String>().unwrap();
            assert!(panic_msg.contains("contract not initialized"));
        });
    }

    #[test]
    fn test_config_returns_correct_values_after_initialization() {
        let env = Env::default();
        let contract = create_contract();
        let super_admin = Address::generate(&env);
        let contract_address = env.register_contract(None, AdminContract);

        env.mock_all_auths();

        env.as_contract(&contract_address, || {
            AdminContract::initialize(env.clone(), super_admin.clone(), 3, 50);
            
            let (min_admins, max_admins) = AdminContract::get_config(env.clone());
            assert_eq!(min_admins, 3);
            assert_eq!(max_admins, 50);
        });
    }

    #[test]
    fn test_admin_config_requires_initialization() {
        let env = Env::default();
        let contract = create_contract();
        let contract_address = env.register_contract(None, AdminContract);
        let admin = Address::generate(&env);

        env.mock_all_auths();
        
        env.as_contract(&contract_address, || {
            let result = std::panic::catch_unwind(|| {
                AdminContract::get_owner(env.clone());
            });
            
            assert!(result.is_err());
            let panic_msg = result.unwrap_err().downcast::<String>().unwrap();
            assert!(panic_msg.contains("owner not found"));
        });
    }

    #[test]
    fn test_admin_config_returns_correct_owner_after_initialization() {
        let env = Env::default();
        let contract = create_contract();
        let super_admin = Address::generate(&env);
        let contract_address = env.register_contract(None, AdminContract);

        env.mock_all_auths();

        env.as_contract(&contract_address, || {
            AdminContract::initialize(env.clone(), super_admin.clone(), 1, 100);
            
            let owner = AdminContract::get_owner(env.clone());
            assert_eq!(owner, super_admin);
        });
    }

    #[test]
    fn test_cannot_reinitialize_admin_contract() {
        let env = Env::default();
        let contract = create_contract();
        let super_admin = Address::generate(&env);
        let contract_address = env.register_contract(None, AdminContract);

        env.mock_all_auths();

        env.as_contract(&contract_address, || {
            AdminContract::initialize(env.clone(), super_admin.clone(), 1, 100);
            
            let result = std::panic::catch_unwind(|| {
                AdminContract::initialize(env.clone(), super_admin.clone(), 2, 200);
            });
            
            assert!(result.is_err());
            let panic_msg = result.unwrap_err().downcast::<String>().unwrap();
            assert!(panic_msg.contains("already initialized"));
        });
    }
}
