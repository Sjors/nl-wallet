use std::collections::BTreeSet;

use attestation_data::auth::reader_auth::ReaderRegistration;
use attestation_data::test_credential::nl_pid_credentials_full_name;
use attestation_types::credential_format::Format;
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use crypto::server_keys::generate::Ca;
use crypto::trust_anchor::TrustAnchors;
use db_test::DbSetup;
use hsm::model::Hsm;
use jwe::algorithm::EcdhAlgorithm;
use jwe::decryption::JweEcdhSecretKey;
use openid4vc::disclosure_session::DisclosableAttestations;
use openid4vc::disclosure_session::DisclosureClient;
use openid4vc::disclosure_session::DisclosureSession;
use openid4vc::disclosure_session::DisclosureUriSource;
use openid4vc::disclosure_session::VpDisclosureClient;
use serial_test::serial;
use server_utils::settings::SecretKey;
use tests_integration::common::*;
use utils::generator::mock::MockTimeGenerator;
use wallet::Pin;

use crate::organizations::PidIssuingOrganization;
use crate::organizations::RecordingWalletProviderWscd;
use crate::organizations::RelyingPartyOrganization;
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

/// Characterize the "which website" concern from footnote 5 of
/// <https://github.com/MinBZK/nl-wallet/issues/38>: because the wallet must have the Wallet
/// Provider sign every disclosure, and because the message it hands over identifies the relying
/// party, the Wallet Provider learns which website the user visits.
///
/// Note that this does not require the HSM to be compromised, nor any private key to be extracted.
/// The message is plaintext in the Wallet Provider's own request handling (the `Sign` instruction
/// handler) before it is passed to the HSM to sign; see `wallet_provider_service`'s
/// `HandleInstruction for Sign`. A Wallet Provider operator need only run software that retains it,
/// which users cannot verify against this repository.
///
/// The disclosure is driven through the real `openid4vc` disclosure code path. The only
/// substitution is the signing service: in production this is [`wallet::wscd::RemoteEcdsaWscd`],
/// which forwards each message to that `Sign` instruction. Here it is replaced by
/// [`RecordingWalletProviderWscd`], which records the exact same bytes before signing them, so the
/// test can observe precisely what the Wallet Provider sees. The relying party's `client_id` is not
/// injected by the test but is derived by the production code from the authorization request the
/// relying party itself signed.
///
/// This uses the SD-JWT format, where the message the Wallet Provider signs is a key binding JWT
/// carrying the relying party's `client_id` in its `aud` claim in the clear. (In the mdoc format
/// the `client_id` is instead folded into a hash in the session transcript, so it is not directly
/// readable there.)
#[tokio::test]
async fn wallet_provider_learns_which_relying_party_a_user_discloses_to() {
    // A relying party must register before it can request attributes. That registration is public
    // and materializes as a certificate, from which a stable `client_id` is derived.
    let rp_ca = Ca::generate_mock();

    let issuer_ca = Ca::generate_issuer_mock_ca().unwrap();
    let issuer_keypair = issuer_ca.generate_pid_issuer_mock().unwrap();

    // Frouke wants to disclose her name to this relying party, in SD-JWT format.
    let test_credentials = nl_pid_credentials_full_name();
    let formats = [Format::SdJwt];
    let credential_requests = test_credentials.to_normalized_credential_requests(formats);
    let reader_registration = ReaderRegistration::mock_from_dcql_query(&test_credentials.to_dcql_query(formats));

    // The wallet's response is end-to-end encrypted to the relying party; the relying party
    // publishes the public half in its authorization request.
    let encryption_secret_key = JweEcdhSecretKey::new_random(Some("test-kid".to_string()), EcdhAlgorithm::EcdhEs);

    let relying_party = RelyingPartyOrganization::register(
        &rp_ca,
        &reader_registration,
        credential_requests,
        encryption_secret_key.to_jwe_public_key(),
    );
    let relying_party_client_id = relying_party.client_id();

    // Model the Wallet Provider's signing service so we can record what it is asked to sign.
    let wallet_provider = RecordingWalletProviderWscd::default();

    // The wallet prepares its SD-JWT presentation, using disclosure keys held by the Wallet Provider.
    let presentations = test_credentials.to_unsigned_sd_jwt_presentations(&issuer_keypair, &wallet_provider);
    let attestations = DisclosableAttestations::SdJwt(presentations).try_into().unwrap();

    // Perform the actual disclosure. `disclose` is the production code that constructs the key
    // binding JWT and asks the (mocked) Wallet Provider to sign it.
    let client = VpDisclosureClient::new(relying_party.clone());
    let session = client
        .start(
            &relying_party.request_uri_query(),
            DisclosureUriSource::Link,
            &TrustAnchors::from(&rp_ca),
        )
        .await
        .expect("wallet should start the disclosure session");

    session
        .disclose(attestations, &wallet_provider, &MockTimeGenerator::default())
        .await
        .unwrap_or_else(|(_, error)| panic!("wallet should complete the disclosure: {error:?}"));

    // Inspect exactly what the Wallet Provider was asked to sign. One SD-JWT presentation is
    // disclosed, hence one key binding JWT.
    let signed_messages = wallet_provider.signed_messages();
    assert_eq!(signed_messages.len(), 1);

    // The message is the key binding JWT signing input: `base64url(header).base64url(payload)`.
    let signing_input = std::str::from_utf8(&signed_messages[0]).expect("signing input should be ASCII");
    let payload_segment = signing_input
        .split('.')
        .nth(1)
        .expect("key binding JWT should have a payload");
    let payload = BASE64_URL_SAFE_NO_PAD
        .decode(payload_segment)
        .expect("key binding JWT payload should be base64url");
    let claims: serde_json::Value = serde_json::from_slice(&payload).expect("key binding JWT payload should be JSON");

    // The audience of the key binding JWT is the relying party's `client_id`. By signing this
    // message the Wallet Provider necessarily learns which relying party (website) the user is
    // disclosing to.
    assert_eq!(
        claims.get("aud").and_then(|aud| aud.as_str()),
        Some(relying_party_client_id.to_string().as_str()),
        "the Wallet Provider sees the relying party's client_id in the message it signs"
    );

    // The Wallet Provider does not, on the other hand, see the disclosed attribute values: the key
    // binding JWT carries only a hash (`sd_hash`) of the presentation. So it learns *which* relying
    // party, but not *what* was disclosed.
    let claim_names: BTreeSet<&str> = claims
        .as_object()
        .expect("key binding JWT payload should be a JSON object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        claim_names,
        BTreeSet::from(["aud", "iat", "nonce", "sd_hash"]),
        "the signed message carries only a hash of the disclosure, not the attribute values"
    );
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
