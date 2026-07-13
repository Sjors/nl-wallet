//! Minimal models of the organizations that participate in the privacy scenarios of
//! <https://github.com/MinBZK/nl-wallet/issues/38>, shared between the tests in `privacy.rs`.

use std::sync::Mutex;

use attestation_data::auth::reader_auth::ReaderRegistration;
use attestation_data::x509::generate::mock::generate_reader_mock_with_registration;
use crypto::mock_remote::MockRemoteEcdsaKey;
use crypto::mock_remote::MockRemoteWscd as CryptoDisclosureWscd;
use crypto::mock_remote::MockRemoteWscdError;
use crypto::server_keys::KeyPair;
use crypto::server_keys::generate::Ca;
use crypto::wscd::DisclosureResult;
use crypto::wscd::DisclosureWscd;
use crypto::wscd::WscdPoa;
use dcql::normalized::NormalizedCredentialRequests;
use hsm::model::Hsm;
use hsm::service::Pkcs11Hsm;
use http_utils::urls::BaseUrl;
use jwe::encryption::JwePublicKey;
use jwt::SignedJwt;
use jwt::UnverifiedJwt;
use jwt::headers::HeaderWithX5c;
use jwt::nonce::Nonce;
use openid4vc::disclosure_session::VpMessageClient;
use openid4vc::disclosure_session::VpMessageClientError;
use openid4vc::errors::AuthorizationErrorResponse;
use openid4vc::errors::VpAuthorizationErrorCode;
use openid4vc::openid4vp::ClientId;
use openid4vc::openid4vp::NormalizedVpAuthorizationRequest;
use openid4vc::openid4vp::VpAuthorizationRequest;
use openid4vc::openid4vp::VpRequestUri;
use openid4vc::openid4vp::VpRequestUriObject;
use openid4vc::verifier::EphemeralIdParameters;
use openid4vc::verifier::SessionType;
use openid4vc::verifier::VerifierUrlParameters;
use p256::ecdsa::VerifyingKey;
use sea_orm::ColumnTrait;
use sea_orm::DatabaseConnection;
use sea_orm::EntityTrait;
use sea_orm::QueryFilter;
use url::Url;
use wallet_provider_persistence::entity::wallet_user;
use wscd::Poa;
use wscd::mock_remote::MockRemoteWscd;

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

/// A relying party that has registered publicly and is therefore identified by a stable `client_id`
/// derived from its certificate. In the disclosure scenario it is passive: it only needs to exist
/// and be identifiable, since the point is what the *Wallet Provider* observes about it.
#[derive(Clone)]
pub(crate) struct RelyingPartyOrganization {
    keypair: KeyPair,
    auth_request: NormalizedVpAuthorizationRequest,
    request_uri: BaseUrl,
    response_uri: BaseUrl,
}

impl RelyingPartyOrganization {
    pub(crate) fn register(
        rp_ca: &Ca,
        reader_registration: &ReaderRegistration,
        credential_requests: NormalizedCredentialRequests,
        encryption_pubkey: JwePublicKey,
    ) -> Self {
        let keypair = generate_reader_mock_with_registration(rp_ca, reader_registration)
            .expect("relying party should obtain a certificate from the RP CA");

        let response_uri: BaseUrl = "https://cert.rp.example.com/response_uri".parse().unwrap();
        let query = serde_qs::to_string(&VerifierUrlParameters {
            session_type: SessionType::SameDevice,
            ephemeral_id_params: Some(EphemeralIdParameters {
                ephemeral_id: vec![42],
                time: None,
            }),
        })
        .unwrap();
        let request_uri: BaseUrl = format!("https://cert.rp.example.com/request_uri?{query}")
            .parse()
            .unwrap();

        let auth_request = NormalizedVpAuthorizationRequest::new_from_certificate(
            credential_requests,
            keypair.certificate(),
            Nonce::from("nonce".to_string()),
            encryption_pubkey,
            response_uri.clone(),
            None,
        );

        Self {
            keypair,
            auth_request,
            request_uri,
            response_uri,
        }
    }

    pub(crate) fn client_id(&self) -> ClientId {
        ClientId::x509_hash_from_certificate(self.keypair.certificate())
    }

    pub(crate) fn request_uri_query(&self) -> String {
        serde_qs::to_string(&VpRequestUri {
            client_id: self.auth_request.client_id.clone(),
            object: VpRequestUriObject::AsReference {
                request_uri: self.request_uri.clone(),
                request_uri_method: None,
            },
        })
        .unwrap()
    }
}

impl VpMessageClient for RelyingPartyOrganization {
    async fn get_authorization_request(
        &self,
        url: BaseUrl,
        _wallet_nonce: Option<String>,
    ) -> Result<UnverifiedJwt<VpAuthorizationRequest, HeaderWithX5c>, VpMessageClientError> {
        assert_eq!(url, self.request_uri);

        let jws = SignedJwt::sign_with_certificate(&self.auth_request.clone().into(), &self.keypair)
            .await
            .unwrap()
            .into();

        Ok(jws)
    }

    async fn send_authorization_response(
        &self,
        url: BaseUrl,
        _jwe: String,
    ) -> Result<Option<Url>, VpMessageClientError> {
        assert_eq!(url, self.response_uri);

        // The contents of the response are irrelevant here: by the time it is sent, the Wallet
        // Provider has already signed (and thus seen) the message identifying this relying party.
        Ok(None)
    }

    async fn send_error(
        &self,
        _url: BaseUrl,
        error: AuthorizationErrorResponse<VpAuthorizationErrorCode>,
    ) -> Result<Option<Url>, VpMessageClientError> {
        panic!("disclosure should not error: {error:?}")
    }
}

/// Stand-in for the Wallet Provider's signing service, which in production is
/// [`wallet::wscd::RemoteEcdsaWscd`] backed by the `Sign` instruction and the HSM. It signs exactly
/// like the real service (by delegating to an inner mock), but first records the messages it is
/// asked to sign so the test can inspect what the Wallet Provider observes.
#[derive(Default)]
pub(crate) struct RecordingWalletProviderWscd {
    inner: MockRemoteWscd,
    signed_messages: Mutex<Vec<Vec<u8>>>,
}

impl RecordingWalletProviderWscd {
    pub(crate) fn signed_messages(&self) -> Vec<Vec<u8>> {
        self.signed_messages.lock().unwrap().clone()
    }
}

impl DisclosureWscd for RecordingWalletProviderWscd {
    type Key = MockRemoteEcdsaKey;
    type Error = MockRemoteWscdError;
    type Poa = Poa;

    fn new_key<I: Into<String>>(&self, identifier: I, public_key: VerifyingKey) -> Self::Key {
        self.inner.new_key(identifier, public_key)
    }

    async fn sign(
        &self,
        messages_and_keys: Vec<(Vec<u8>, Vec<&Self::Key>)>,
        poa_input: <Self::Poa as WscdPoa>::Input,
    ) -> Result<DisclosureResult<Self::Poa>, Self::Error> {
        self.signed_messages
            .lock()
            .unwrap()
            .extend(messages_and_keys.iter().map(|(message, _keys)| message.clone()));

        self.inner.sign(messages_and_keys, poa_input).await
    }
}

impl AsRef<CryptoDisclosureWscd> for RecordingWalletProviderWscd {
    fn as_ref(&self) -> &CryptoDisclosureWscd {
        self.inner.as_ref()
    }
}
