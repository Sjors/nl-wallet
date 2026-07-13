use db_test::DbSetup;
use hsm::model::Hsm;
use serial_test::serial;
use server_utils::settings::SecretKey;
use tests_integration::common::*;
use wallet::Pin;

use crate::organizations::PidIssuingOrganization;
use crate::organizations::WalletProviderOrganization;

mod organizations;

const FROUKE_BSN: &str = "999991772";

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[serial(hsm)]
async fn pid_issuer_and_wallet_provider_can_link_bsn_to_wallet_by_combining_recovery_code_information() {
    // Characterize the BSN-to-wallet link described in
    // https://github.com/MinBZK/nl-wallet/issues/38 by first completing Frouke's
    // normal wallet registration and PID issuance.
    let context = PrivacyTestContext::setup().await;

    // The PID issuer can derive the recovery code for Frouke's BSN through its
    // normal HSM operation, without extracting the HMAC key.
    let recovery_code = context.pid_issuer.derive_recovery_code(FROUKE_BSN).await;

    // The Wallet Provider can use that recovery code to find her wallet record.
    let linked_wallet = context
        .wallet_provider
        .find_wallet_by_recovery_code(&recovery_code)
        .await;

    // Neither organization has the full link by itself, but combining their
    // information produces it. This does not assume which party performs the
    // combination or represent a production endpoint between them.
    assert_eq!(
        linked_wallet.wallet_id, context.registered_wallet_id,
        "the BSN-derived recovery code should identify Frouke's registered wallet"
    );

    context.cleanup().await;
}

/// Shared setup for privacy scenarios involving the PID issuer and Wallet Provider.
struct PrivacyTestContext {
    registered_wallet_id: String,
    pid_issuer: PidIssuingOrganization,
    wallet_provider: WalletProviderOrganization,
}

impl PrivacyTestContext {
    async fn setup() -> Self {
        let db_setup = DbSetup::create_clean().await;
        let pin: Pin = "112233".into();

        let (wp_settings, wp_root_ca) =
            wallet_provider_settings(db_setup.wallet_provider_url(), db_setup.audit_log_url());
        let wp_connection = new_connection(wp_settings.database.url.clone()).await.unwrap();
        let wallet_provider = WalletProviderOrganization::new(wp_connection);

        let recovery_code_hmac_key_identifier = format!("privacy-recovery-code-{}", std::process::id());
        let mut pid_issuer_settings = pid_issuer_settings(db_setup.pid_issuer_url(), None);
        pid_issuer_settings.recovery_code = SecretKey::Hsm {
            secret_key: recovery_code_hmac_key_identifier.clone(),
        };

        let (wallet, _, _, hsm) = setup_wallet_and_env_with_hsm(
            &db_setup,
            WalletDeviceVendor::Apple,
            update_policy_server_settings(),
            (wp_settings, wp_root_ca),
            pid_issuer_settings,
            issuance_server_settings(db_setup.issuance_server_url()),
        )
        .await;

        hsm.generate_generic_secret_key(&recovery_code_hmac_key_identifier)
            .await
            .expect("Could not generate recovery-code HSM key");
        let pid_issuer = PidIssuingOrganization::new(hsm, recovery_code_hmac_key_identifier);

        let wallet = do_wallet_registration(wallet, pin.clone()).await;
        let registered_wallet_id = wallet_provider.registered_wallet_id().await;
        let _wallet = do_pid_issuance(wallet, pin).await;

        Self {
            registered_wallet_id,
            pid_issuer,
            wallet_provider,
        }
    }

    async fn cleanup(&self) {
        self.pid_issuer.delete_recovery_code_key().await;
    }
}
