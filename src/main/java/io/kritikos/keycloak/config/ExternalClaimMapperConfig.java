package io.kritikos.keycloak.config;

/**
 * Centralized configuration constants for the External Claim Mapper.
 * <p>
 * These keys correspond to the configurable properties exposed in the
 * Keycloak Admin Console when the mapper is added to a client scope or client.
 */
public final class ExternalClaimMapperConfig {

  private ExternalClaimMapperConfig() {
  }

  /** Unique SPI provider identifier for the mapper. */
  public static final String PROVIDER_ID = "external-claim-mapper";

  /** Human-readable name shown in the Keycloak Admin Console mapper type list. */
  public static final String DISPLAY_TYPE = "External Claim Mapper";

  /** Admin Console category under which this mapper appears. */
  public static final String DISPLAY_CATEGORY = "Token mapper";

  /** Short help text shown in the Admin Console. */
  public static final String HELP_TEXT = "Fetches claims from an external API "
      + "and adds them to the token.";

  /** Base URL of the external API (e.g. https://api.example.com). */
  public static final String CONFIG_API_BASE_URL = "external.api.base_url";

  /**
   * Path template appended to the base URL.
   * Supports {@code {userId}}, {@code {username}}, {@code {email}},
   * and {@code {clientId}} placeholders.
   * Example: {@code /api/v1/users/{userId}/claims?clientId={clientId}}
   */
  public static final String CONFIG_API_PATH_TEMPLATE = "external.api.path_template";

  /** The token claim name where the extracted value will be written. */
  public static final String CONFIG_CLAIM_NAME = "external.claim.name";

  /**
   * JSONPath expression applied to the API response body to extract
   * the claim value. Examples:
   * <ul>
   * <li>{@code $.privileges[*].name} – list of privilege name strings</li>
   * <li>{@code $.roles} – a top-level array</li>
   * <li>{@code $.data.permissions} – nested array</li>
   * <li>{@code $.isAdmin} – a single boolean value</li>
   * </ul>
   */
  public static final String CONFIG_RESPONSE_JSONPATH = "external.api.response_jsonpath";

  /** Authentication mode: none, api_key, or client_credentials. */
  public static final String CONFIG_AUTH_MODE = "external.api.auth_method";

  /** Optional static API key sent as a header. */
  public static final String CONFIG_API_KEY = "external.api.api_key";

  /**
   * Custom header name used when sending the API key.
   * Defaults to {@code X-API-Key} when left blank.
   */
  public static final String CONFIG_API_KEY_HEADER = "external.api.api_key_header";

  /**
   * OAuth2 token endpoint for client_credentials grant.
   * When blank the mapper auto-resolves the local Keycloak instance's
   * token endpoint from the current realm.
   */
  public static final String CONFIG_TOKEN_ENDPOINT = "external.api.token_endpoint_url";

  /** OAuth2 client_id for the client_credentials grant. */
  public static final String CONFIG_CC_CLIENT_ID = "external.api.client_id";

  /** OAuth2 client_secret for the client_credentials grant. */
  public static final String CONFIG_CC_CLIENT_SECRET = "external.api.client_secret";

  /** HTTP connect timeout in milliseconds. */
  public static final String CONFIG_CONNECT_TIMEOUT = "external.api.connect_timeout_ms";

  /** HTTP read timeout in milliseconds. */
  public static final String CONFIG_READ_TIMEOUT = "external.api.read_timeout_ms";

  /** Whether to skip TLS certificate validation (development only). */
  public static final String CONFIG_TLS_SKIP_VERIFY = "external.api.tls_skip_verify";

  /**
   * When {@code true}, a failed API call or JSONPath extraction will block
   * token issuance (fail-closed). When {@code false} (default), the mapper
   * silently continues with an empty claim (fail-open).
   */
  public static final String CONFIG_FAIL_ON_ERROR = "external.api.fail_on_error";

  /** Authentication mode: no authentication header. */
  public static final String AUTH_MODE_NONE = "none";

  /** Authentication mode: static API key sent via a configurable header. */
  public static final String AUTH_MODE_API_KEY = "api_key";

  /** Authentication mode: forwards the user's own session JWT as a Bearer token. */
  public static final String AUTH_MODE_USER_TOKEN = "user_token";

  /** Authentication mode: OAuth2 client-credentials grant. */
  public static final String AUTH_MODE_CLIENT_CREDENTIALS = "client_credentials";

  /**
   * Used internally when the mapper mints a token via Keycloak's signing keys.
   */
  public static final String AUTH_MODE_BEARER = "bearer";

  /** Default value for the token claim name. */
  public static final String DEFAULT_CLAIM_NAME = "app_privileges";

  /** Default JSONPath expression applied to the API response. */
  public static final String DEFAULT_RESPONSE_JSONPATH = "$.privileges[*].name";

  /** Default API path template with user and client placeholders. */
  public static final String DEFAULT_PATH_TEMPLATE = "/privileges?userId={userId}&clientId={clientId}";

  /** Default HTTP connect timeout in milliseconds. */
  public static final String DEFAULT_CONNECT_TIMEOUT = "5000";

  /** Default HTTP read timeout in milliseconds. */
  public static final String DEFAULT_READ_TIMEOUT = "10000";

  /** Default authentication mode. */
  public static final String DEFAULT_AUTH_MODE = AUTH_MODE_CLIENT_CREDENTIALS;

  /** Default header name for the API key authentication mode. */
  public static final String DEFAULT_API_KEY_HEADER = "X-API-Key";
}
