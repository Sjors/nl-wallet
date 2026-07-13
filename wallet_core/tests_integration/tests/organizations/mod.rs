//! Minimal models of the organizations that participate in the privacy scenarios of
//! <https://github.com/MinBZK/nl-wallet/issues/38>, shared between the tests in `privacy.rs`.

use hsm::model::Hsm;
use hsm::service::Pkcs11Hsm;
use sea_orm::ColumnTrait;
use sea_orm::DatabaseConnection;
use sea_orm::EntityTrait;
use sea_orm::QueryFilter;
use wallet_provider_persistence::entity::wallet_user;

/// A stable, pseudonymous identifier derived from a citizen's BSN by the PID issuer.
pub(crate) struct RecoveryCode(String);

/// The PID-issuing organization and its access to the recovery-code HSM operation.
pub(crate) struct PidIssuingOrganization {
    hsm: Pkcs11Hsm,
    recovery_code_hmac_key_identifier: String,
}

impl PidIssuingOrganization {
    pub(crate) fn new(hsm: Pkcs11Hsm, recovery_code_hmac_key_identifier: String) -> Self {
        Self {
            hsm,
            recovery_code_hmac_key_identifier,
        }
    }

    pub(crate) async fn derive_recovery_code(&self, bsn: &str) -> RecoveryCode {
        RecoveryCode(hex::encode(
            self.hsm
                .sign_hmac(&self.recovery_code_hmac_key_identifier, bsn.as_bytes())
                .await
                .expect("recovery-code derivation should succeed"),
        ))
    }

    pub(crate) async fn delete_recovery_code_key(&self) {
        self.hsm
            .delete_key(&self.recovery_code_hmac_key_identifier)
            .await
            .expect("Could not delete recovery-code HSM key");
    }
}

/// The Wallet Provider organization and its access to the wallet database.
pub(crate) struct WalletProviderOrganization {
    database: DatabaseConnection,
}

impl WalletProviderOrganization {
    pub(crate) fn new(database: DatabaseConnection) -> Self {
        Self { database }
    }

    pub(crate) async fn registered_wallet_id(&self) -> String {
        wallet_user::Entity::find()
            .one(&self.database)
            .await
            .expect("Wallet Provider records should be queryable")
            .expect("registration should create a Wallet Provider record")
            .wallet_id
    }

    pub(crate) async fn find_wallet_by_recovery_code(&self, recovery_code: &RecoveryCode) -> wallet_user::Model {
        wallet_user::Entity::find()
            .filter(wallet_user::Column::RecoveryCode.eq(&recovery_code.0))
            .one(&self.database)
            .await
            .expect("Wallet Provider records should be queryable")
            .expect("the recovery code should identify a wallet")
    }
}
