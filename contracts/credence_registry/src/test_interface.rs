#![cfg(test)]

use crate::{CredenceRegistry, CredenceRegistryClient};
use soroban_sdk::{testutils::Address as _, Env};

mod compliant {
    use crate::IFACE_CREDENCE_BOND_V1;
    use soroban_sdk::{contract, contractimpl, Env};
    #[contract]
    pub struct CompliantBond;
    #[contractimpl]
    impl CompliantBond {
        pub fn supports_interface(_e: Env, interface_id: u32) -> bool {
            interface_id == IFACE_CREDENCE_BOND_V1
        }
    }
}

mod non_compliant {
    use soroban_sdk::{contract, contractimpl, Env};
    #[contract]
    pub struct NonCompliantBond;
    #[contractimpl]
    impl NonCompliantBond {
        pub fn some_other_fn(_e: Env) -> bool {
            true
        }
    }
}

mod lying {
    use soroban_sdk::{contract, contractimpl, Env};
    #[contract]
    pub struct LyingBond;
    #[contractimpl]
    impl LyingBond {
        pub fn supports_interface(_e: Env, _interface_id: u32) -> bool {
            false
        }
    }
}

fn setup(e: &Env) -> CredenceRegistryClient<'_> {
    let id = e.register(CredenceRegistry, ());
    let client = CredenceRegistryClient::new(e, &id);
    let admin = soroban_sdk::Address::generate(e);
    e.mock_all_auths();
    client.initialize(&admin);
    client
}

#[test]
fn test_compliant_bond_registers() {
    let e = Env::default();
    e.mock_all_auths();
    let client = setup(&e);
    let identity = soroban_sdk::Address::generate(&e);
    let bond_id = e.register(compliant::CompliantBond, ());
    let entry = client.register(&identity, &bond_id, &false);
    assert!(entry.active);
}

#[test]
#[should_panic(expected = "bond contract does not support required interface")]
fn test_non_compliant_bond_reverts() {
    let e = Env::default();
    e.mock_all_auths();
    let client = setup(&e);
    let identity = soroban_sdk::Address::generate(&e);
    let bond_id = e.register(non_compliant::NonCompliantBond, ());
    client.register(&identity, &bond_id, &false);
}

#[test]
#[should_panic(expected = "bond contract does not support required interface")]
fn test_lying_bond_reverts() {
    let e = Env::default();
    e.mock_all_auths();
    let client = setup(&e);
    let identity = soroban_sdk::Address::generate(&e);
    let bond_id = e.register(lying::LyingBond, ());
    client.register(&identity, &bond_id, &false);
}

#[test]
fn test_non_compliant_allowed_when_explicit() {
    let e = Env::default();
    e.mock_all_auths();
    let client = setup(&e);
    let identity = soroban_sdk::Address::generate(&e);
    let bond_id = e.register(non_compliant::NonCompliantBond, ());
    let entry = client.register(&identity, &bond_id, &true);
    assert!(entry.active);
}
