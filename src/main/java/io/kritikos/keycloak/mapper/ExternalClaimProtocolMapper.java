package io.kritikos.keycloak.mapper;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.jboss.logging.Logger;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.protocol.oidc.mappers.UserInfoTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;

import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.PathNotFoundException;

import io.kritikos.keycloak.config.ExternalClaimMapperConfig;
import io.kritikos.keycloak.service.ExternalClaimApiClient;

/**
 * Custom OIDC Protocol Mapper that enriches tokens with claims
 * fetched from an external REST API.
 * <p>
 * Configurable properties (exposed in the Keycloak Admin Console):
 * <ul>
 * <li><b>API Base URL</b> – root URL of the external service</li>
 * <li><b>Claim Name</b> – the JSON path where the value appears in the
 * token</li>
 * <li><b>API Key</b> – optional static key sent via a configurable
 * header</li>
 * <li><b>Connect / Read Timeout</b> – HTTP timeouts in ms</li>
 * </ul>
 * <p>
 * The mapper implements all three OIDC token types so claims can land in
 * the access token, ID token, and/or userinfo depending on the toggle in the
 * console.
 */
public class ExternalClaimProtocolMapper extends AbstractOIDCProtocolMapper
    implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

  private static final Logger LOG = Logger.getLogger(ExternalClaimProtocolMapper.class);

  private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

  private final ExternalClaimApiClient apiClient;

  static {
    ProviderConfigProperty apiUrl = new ProviderConfigProperty();
    apiUrl.setName(ExternalClaimMapperConfig.CONFIG_API_BASE_URL);
    apiUrl.setLabel("API Base URL");
    apiUrl.setHelpText("The base URL of the external API (e.g. https://api.example.com). "
        + "When blank, falls back to the client URL selected below.");
    apiUrl.setType(ProviderConfigProperty.STRING_TYPE);
    apiUrl.setDefaultValue("");
    CONFIG_PROPERTIES.add(apiUrl);

    ProviderConfigProperty urlFallback = new ProviderConfigProperty();
    urlFallback.setName(ExternalClaimMapperConfig.CONFIG_URL_FALLBACK);
    urlFallback.setLabel("URL Fallback Source");
    urlFallback.setHelpText(
        "Which client URL field to use when the API Base URL is left blank. "
            + "'root_url' uses the client's Root URL; 'home_url' uses the Home URL.");
    urlFallback.setType(ProviderConfigProperty.LIST_TYPE);
    urlFallback.setDefaultValue(ExternalClaimMapperConfig.DEFAULT_URL_FALLBACK);
    urlFallback.setOptions(List.of(
        ExternalClaimMapperConfig.URL_FALLBACK_ROOT,
        ExternalClaimMapperConfig.URL_FALLBACK_HOME));
    CONFIG_PROPERTIES.add(urlFallback);

    ProviderConfigProperty pathTemplate = new ProviderConfigProperty();
    pathTemplate.setName(ExternalClaimMapperConfig.CONFIG_API_PATH_TEMPLATE);
    pathTemplate.setLabel("API Path Template");
    pathTemplate.setHelpText(
        "Path appended to the base URL. Use {userId}, {username}, {email}, "
            + "and {clientId} as placeholders. "
            + "Examples: /privileges?userId={userId}&clientId={clientId}  or  "
            + "/api/v1/users/{userId}/claims?clientId={clientId}");
    pathTemplate.setType(ProviderConfigProperty.STRING_TYPE);
    pathTemplate.setDefaultValue(ExternalClaimMapperConfig.DEFAULT_PATH_TEMPLATE);
    CONFIG_PROPERTIES.add(pathTemplate);

    ProviderConfigProperty claimName = new ProviderConfigProperty();
    claimName.setName(ExternalClaimMapperConfig.CONFIG_CLAIM_NAME);
    claimName.setLabel("Token Claim Name");
    claimName.setHelpText("Name of the claim added to the token (supports nested paths like 'app.privileges').");
    claimName.setType(ProviderConfigProperty.STRING_TYPE);
    claimName.setDefaultValue(ExternalClaimMapperConfig.DEFAULT_CLAIM_NAME);
    CONFIG_PROPERTIES.add(claimName);

    ProviderConfigProperty jsonPath = new ProviderConfigProperty();
    jsonPath.setName(ExternalClaimMapperConfig.CONFIG_RESPONSE_JSONPATH);
    jsonPath.setLabel("Response JSONPath");
    jsonPath.setHelpText(
        "JSONPath expression to extract the claim value from the API response. "
            + "Examples: $.privileges[*].name  |  $.roles  |  $.data.permissions  |  $.isAdmin");
    jsonPath.setType(ProviderConfigProperty.STRING_TYPE);
    jsonPath.setDefaultValue(ExternalClaimMapperConfig.DEFAULT_RESPONSE_JSONPATH);
    CONFIG_PROPERTIES.add(jsonPath);

    ProviderConfigProperty authMode = new ProviderConfigProperty();
    authMode.setName(ExternalClaimMapperConfig.CONFIG_AUTH_MODE);
    authMode.setLabel("Authentication Mode");
    authMode.setHelpText("How the mapper authenticates to the external API.");
    authMode.setType(ProviderConfigProperty.LIST_TYPE);
    authMode.setDefaultValue(ExternalClaimMapperConfig.DEFAULT_AUTH_MODE);
    authMode.setOptions(List.of(
        ExternalClaimMapperConfig.AUTH_MODE_NONE,
        ExternalClaimMapperConfig.AUTH_MODE_API_KEY,
        ExternalClaimMapperConfig.AUTH_MODE_USER_TOKEN,
        ExternalClaimMapperConfig.AUTH_MODE_CLIENT_CREDENTIALS));
    CONFIG_PROPERTIES.add(authMode);

    ProviderConfigProperty apiKey = new ProviderConfigProperty();
    apiKey.setName(ExternalClaimMapperConfig.CONFIG_API_KEY);
    apiKey.setLabel("API Key");
    apiKey.setHelpText("Static API key value (auth mode = api_key).");
    apiKey.setType(ProviderConfigProperty.STRING_TYPE);
    apiKey.setSecret(true);
    CONFIG_PROPERTIES.add(apiKey);

    ProviderConfigProperty apiKeyHeader = new ProviderConfigProperty();
    apiKeyHeader.setName(ExternalClaimMapperConfig.CONFIG_API_KEY_HEADER);
    apiKeyHeader.setLabel("API Key Header Name");
    apiKeyHeader.setHelpText("HTTP header name used to send the API key. Defaults to X-API-Key when blank.");
    apiKeyHeader.setType(ProviderConfigProperty.STRING_TYPE);
    apiKeyHeader.setDefaultValue(ExternalClaimMapperConfig.DEFAULT_API_KEY_HEADER);
    CONFIG_PROPERTIES.add(apiKeyHeader);

    ProviderConfigProperty tokenEndpoint = new ProviderConfigProperty();
    tokenEndpoint.setName(ExternalClaimMapperConfig.CONFIG_TOKEN_ENDPOINT);
    tokenEndpoint.setLabel("Token Endpoint URL");
    tokenEndpoint.setHelpText(
        "OAuth2 token endpoint URL for the client_credentials grant. "
            + "Leave blank to auto-resolve from the current Keycloak realm.");
    tokenEndpoint.setType(ProviderConfigProperty.STRING_TYPE);
    CONFIG_PROPERTIES.add(tokenEndpoint);

    ProviderConfigProperty ccClientId = new ProviderConfigProperty();
    ccClientId.setName(ExternalClaimMapperConfig.CONFIG_CC_CLIENT_ID);
    ccClientId.setLabel("Client ID");
    ccClientId.setHelpText("OAuth2 client_id used for the client_credentials grant.");
    ccClientId.setType(ProviderConfigProperty.STRING_TYPE);
    CONFIG_PROPERTIES.add(ccClientId);

    ProviderConfigProperty ccClientSecret = new ProviderConfigProperty();
    ccClientSecret.setName(ExternalClaimMapperConfig.CONFIG_CC_CLIENT_SECRET);
    ccClientSecret.setLabel("Client Secret");
    ccClientSecret.setHelpText("OAuth2 client_secret used for the client_credentials grant.");
    ccClientSecret.setType(ProviderConfigProperty.STRING_TYPE);
    ccClientSecret.setSecret(true);
    CONFIG_PROPERTIES.add(ccClientSecret);

    ProviderConfigProperty connectTimeout = new ProviderConfigProperty();
    connectTimeout.setName(ExternalClaimMapperConfig.CONFIG_CONNECT_TIMEOUT);
    connectTimeout.setLabel("Connect Timeout (ms)");
    connectTimeout.setHelpText("HTTP connection timeout in milliseconds.");
    connectTimeout.setType(ProviderConfigProperty.STRING_TYPE);
    connectTimeout.setDefaultValue(ExternalClaimMapperConfig.DEFAULT_CONNECT_TIMEOUT);
    CONFIG_PROPERTIES.add(connectTimeout);

    ProviderConfigProperty readTimeout = new ProviderConfigProperty();
    readTimeout.setName(ExternalClaimMapperConfig.CONFIG_READ_TIMEOUT);
    readTimeout.setLabel("Read Timeout (ms)");
    readTimeout.setHelpText("HTTP read timeout in milliseconds.");
    readTimeout.setType(ProviderConfigProperty.STRING_TYPE);
    readTimeout.setDefaultValue(ExternalClaimMapperConfig.DEFAULT_READ_TIMEOUT);
    CONFIG_PROPERTIES.add(readTimeout);

    ProviderConfigProperty tlsSkipVerify = new ProviderConfigProperty();
    tlsSkipVerify.setName(ExternalClaimMapperConfig.CONFIG_TLS_SKIP_VERIFY);
    tlsSkipVerify.setLabel("Disable TLS Validation");
    tlsSkipVerify.setHelpText(
        "Skip TLS certificate verification when calling the external API. "
            + "WARNING: use only for development/testing — never in production.");
    tlsSkipVerify.setType(ProviderConfigProperty.BOOLEAN_TYPE);
    tlsSkipVerify.setDefaultValue("false");
    CONFIG_PROPERTIES.add(tlsSkipVerify);

    ProviderConfigProperty failOnError = new ProviderConfigProperty();
    failOnError.setName(ExternalClaimMapperConfig.CONFIG_FAIL_ON_ERROR);
    failOnError.setLabel("Fail on Error");
    failOnError.setHelpText(
        "When enabled, a failed API call or JSONPath error will block token issuance "
            + "instead of silently returning an empty claim. "
            + "Use this in production to ensure tokens always carry accurate claims.");
    failOnError.setType(ProviderConfigProperty.BOOLEAN_TYPE);
    failOnError.setDefaultValue("false");
    CONFIG_PROPERTIES.add(failOnError);

    OIDCAttributeMapperHelper.addIncludeInTokensConfig(CONFIG_PROPERTIES, ExternalClaimProtocolMapper.class);
  }

  /** Default constructor used by the Keycloak SPI loader. */
  public ExternalClaimProtocolMapper() {
    this(new ExternalClaimApiClient());
  }

  /** Constructor for unit testing – allows injecting a mock API client. */
  ExternalClaimProtocolMapper(ExternalClaimApiClient apiClient) {
    this.apiClient = apiClient;
  }

  @Override
  public String getId() {
    return ExternalClaimMapperConfig.PROVIDER_ID;
  }

  @Override
  public String getDisplayType() {
    return ExternalClaimMapperConfig.DISPLAY_TYPE;
  }

  @Override
  public String getDisplayCategory() {
    return ExternalClaimMapperConfig.DISPLAY_CATEGORY;
  }

  @Override
  public String getHelpText() {
    return ExternalClaimMapperConfig.HELP_TEXT;
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return CONFIG_PROPERTIES;
  }

  /**
   * Enriches the token with claims fetched from an external REST API.
   * <p>
   * If no explicit API base URL is configured, the client's Root URL is used
   * as a fallback. When {@code client_credentials} authentication is selected
   * with no explicit token endpoint, an internal service-account token is minted
   * using Keycloak's signing keys to avoid HTTP self-call deadlocks. The API
   * response is parsed with the configured JSONPath expression and written
   * directly into the token under the configured claim name.
   * <p>
   * Behaviour on failure is controlled by the {@code fail_on_error} flag:
   * when enabled, errors block token issuance; otherwise, an empty claim is
   * set silently.
   */
  @Override
  protected void setClaim(
      IDToken token,
      ProtocolMapperModel mappingModel,
      UserSessionModel userSession,
      KeycloakSession keycloakSession,
      ClientSessionContext clientSessionCtx) {

    Map<String, String> config = mappingModel.getConfig();
    String baseUrl = config.get(ExternalClaimMapperConfig.CONFIG_API_BASE_URL);

    if (baseUrl == null || baseUrl.isBlank()) {
      String fallbackSource = config.getOrDefault(
          ExternalClaimMapperConfig.CONFIG_URL_FALLBACK,
          ExternalClaimMapperConfig.DEFAULT_URL_FALLBACK);
      ClientModel client = clientSessionCtx.getClientSession().getClient();
      String fallbackUrl = ExternalClaimMapperConfig.URL_FALLBACK_HOME.equals(fallbackSource)
          ? client.getBaseUrl()
          : client.getRootUrl();
      if (fallbackUrl != null && !fallbackUrl.isBlank()) {
        baseUrl = fallbackUrl;
        LOG.debugf("API Base URL not configured – falling back to client %s: %s", fallbackSource, baseUrl);
      } else {
        LOG.warnf("External API base URL is not configured and client has no %s – skipping mapper.", fallbackSource);
        return;
      }
    }

    String userId = userSession.getUser().getId();
    String username = userSession.getUser().getUsername();
    String email = userSession.getUser().getEmail();
    String clientId = clientSessionCtx.getClientSession()
        .getClient().getClientId();
    String pathTemplate = config.getOrDefault(
        ExternalClaimMapperConfig.CONFIG_API_PATH_TEMPLATE,
        ExternalClaimMapperConfig.DEFAULT_PATH_TEMPLATE);

    String authMode = config.getOrDefault(
        ExternalClaimMapperConfig.CONFIG_AUTH_MODE,
        ExternalClaimMapperConfig.DEFAULT_AUTH_MODE);
    String apiKey = config.get(ExternalClaimMapperConfig.CONFIG_API_KEY);
    String apiKeyHeader = config.getOrDefault(
        ExternalClaimMapperConfig.CONFIG_API_KEY_HEADER,
        ExternalClaimMapperConfig.DEFAULT_API_KEY_HEADER);
    String tokenEndpoint = config.get(ExternalClaimMapperConfig.CONFIG_TOKEN_ENDPOINT);
    String ccClientId = config.get(ExternalClaimMapperConfig.CONFIG_CC_CLIENT_ID);
    String ccClientSecret = config.get(ExternalClaimMapperConfig.CONFIG_CC_CLIENT_SECRET);

    if (ExternalClaimMapperConfig.AUTH_MODE_USER_TOKEN.equals(authMode)) {
      apiKey = mintUserSessionToken(keycloakSession, userSession, clientId);
      if (apiKey == null) {
        LOG.warn("Failed to build user session token for user_token auth mode.");
      }
    }

    if (ExternalClaimMapperConfig.AUTH_MODE_CLIENT_CREDENTIALS.equals(authMode)
        && (tokenEndpoint == null || tokenEndpoint.isBlank())) {
      String internalToken = createInternalServiceAccountToken(
          keycloakSession, ccClientId);
      if (internalToken != null) {
        authMode = ExternalClaimMapperConfig.AUTH_MODE_BEARER;
        apiKey = internalToken;
        LOG.debug("Created internal service-account token (no HTTP self-call)");
      } else {
        tokenEndpoint = resolveRealmTokenEndpoint(keycloakSession);
        LOG.debugf("Fallback: auto-resolved token endpoint %s", tokenEndpoint);
      }
    }

    int connectTimeout = parseIntOrDefault(
        config.get(ExternalClaimMapperConfig.CONFIG_CONNECT_TIMEOUT),
        Integer.parseInt(ExternalClaimMapperConfig.DEFAULT_CONNECT_TIMEOUT));
    int readTimeout = parseIntOrDefault(
        config.get(ExternalClaimMapperConfig.CONFIG_READ_TIMEOUT),
        Integer.parseInt(ExternalClaimMapperConfig.DEFAULT_READ_TIMEOUT));
    boolean tlsSkipVerify = Boolean.parseBoolean(
        config.getOrDefault(ExternalClaimMapperConfig.CONFIG_TLS_SKIP_VERIFY, "false"));
    boolean failOnError = Boolean.parseBoolean(
        config.getOrDefault(ExternalClaimMapperConfig.CONFIG_FAIL_ON_ERROR, "false"));

    String responseBody = apiClient.fetchClaims(
        baseUrl, pathTemplate, userId, username, email, clientId,
        authMode, apiKey, apiKeyHeader,
        tokenEndpoint, ccClientId, ccClientSecret,
        connectTimeout, readTimeout, tlsSkipVerify);

    if (responseBody == null && failOnError) {
      throw new RuntimeException(
          String.format("External API call failed for user=%s client=%s "
              + "and fail_on_error is enabled — blocking token issuance.",
              userId, clientId));
    }

    String jsonPathExpr = config.getOrDefault(
        ExternalClaimMapperConfig.CONFIG_RESPONSE_JSONPATH,
        ExternalClaimMapperConfig.DEFAULT_RESPONSE_JSONPATH);

    Object claimValue;
    if (responseBody != null && !responseBody.isBlank()) {
      try {
        claimValue = JsonPath.read(responseBody, jsonPathExpr);
      } catch (PathNotFoundException e) {
        LOG.warnf("JSONPath '%s' not found in API response for user=%s client=%s",
            jsonPathExpr, userId, clientId);
        if (failOnError) {
          throw new RuntimeException(
              String.format("JSONPath '%s' not found and fail_on_error is enabled.",
                  jsonPathExpr),
              e);
        }
        claimValue = Collections.emptyList();
      } catch (Exception e) {
        LOG.errorf(e, "Error evaluating JSONPath '%s' for user=%s client=%s",
            jsonPathExpr, userId, clientId);
        if (failOnError) {
          throw new RuntimeException(
              String.format("JSONPath evaluation error and fail_on_error is enabled."), e);
        }
        claimValue = Collections.emptyList();
      }
    } else {
      claimValue = Collections.emptyList();
    }

    String claimName = config.getOrDefault(
        ExternalClaimMapperConfig.CONFIG_CLAIM_NAME,
        ExternalClaimMapperConfig.DEFAULT_CLAIM_NAME);

    int claimSize = (claimValue instanceof List) ? ((List<?>) claimValue).size() : 1;
    LOG.debugf("Setting claim '%s' (%d element(s)) for user=%s client=%s",
        claimName, claimSize, userId, clientId);

    token.getOtherClaims().put(claimName, claimValue);
  }

  /**
   * Builds the token endpoint URL from the current Keycloak realm context.
   * Uses the internal listener URL (http://localhost:8080 by default) so
   * the call works inside the container without hitting the host-mapped port.
   * Format: {serverUrl}/realms/{realmName}/protocol/openid-connect/token
   */
  private static String resolveRealmTokenEndpoint(KeycloakSession session) {
    String serverUrl;
    try {
      serverUrl = session.getContext().getUri()
          .getBaseUri().toString().replaceAll("/+$", "");
      java.net.URI base = java.net.URI.create(serverUrl);
      if (base.getPort() != 8080 && base.getPort() != -1) {
        serverUrl = "http://localhost:8080";
      }
    } catch (Exception e) {
      serverUrl = "http://localhost:8080";
    }
    String realmName = session.getContext().getRealm().getName();
    return serverUrl + "/realms/" + realmName + "/protocol/openid-connect/token";
  }

  private static int parseIntOrDefault(String value, int defaultValue) {
    if (value == null || value.isBlank()) {
      return defaultValue;
    }
    try {
      return Integer.parseInt(value.trim());
    } catch (NumberFormatException e) {
      return defaultValue;
    }
  }

  /**
   * Builds a short-lived JWT representing the current user's session,
   * signed with the realm's own keys. This allows the external API to
   * validate the token against Keycloak's JWKS endpoint without needing
   * the user's original access token (which is still being built).
   *
   * @param session     the current Keycloak session
   * @param userSession the active user session
   * @param clientId    the requesting client's ID (set as audience and azp)
   * @return a signed JWT string, or {@code null} on any failure
   */
  private static String mintUserSessionToken(
      KeycloakSession session, UserSessionModel userSession, String clientId) {
    try {
      RealmModel realm = session.getContext().getRealm();
      UserModel user = userSession.getUser();

      String issuer = session.getContext().getUri()
          .getBaseUri().toString().replaceAll("/+$", "")
          + "/realms/" + realm.getName();

      AccessToken accessToken = new AccessToken();
      accessToken.id(UUID.randomUUID().toString());
      accessToken.issuer(issuer);
      accessToken.subject(user.getId());
      accessToken.issuedNow();
      accessToken.exp((long) (Time.currentTime() + 60));
      accessToken.type("Bearer");
      accessToken.issuedFor(clientId);
      accessToken.addAudience(clientId);
      accessToken.setPreferredUsername(user.getUsername());
      accessToken.setEmail(user.getEmail());

      String algorithm = realm.getDefaultSignatureAlgorithm();
      if (algorithm == null || algorithm.isBlank()) {
        algorithm = "RS256";
      }

      SignatureSignerContext signer =
          session.getProvider(SignatureProvider.class, algorithm).signer();
      return new JWSBuilder().type("JWT").jsonContent(accessToken).sign(signer);

    } catch (Exception e) {
      LOG.errorf(e, "Failed to mint user session token for user '%s'",
          userSession.getUser().getId());
      return null;
    }
  }

  /**
   * Mints a service-account access token using Keycloak's own signing keys.
   * <p>
   * This avoids an HTTP round-trip to the token endpoint which would deadlock
   * when the mapper runs inside the same Keycloak instance that owns the
   * realm (the outer request holds resources the inner request needs).
   * <p>
   * The issuer is derived from the current request URI so external APIs can
   * validate the token. The token has a 60-second lifetime and is signed with
   * the realm's default signature algorithm (RS256 fallback).
   *
   * @param session    the current Keycloak session
   * @param ccClientId the client ID whose service account is used
   * @return a signed JWT string, or {@code null} on any failure
   */
  private static String createInternalServiceAccountToken(
      KeycloakSession session, String ccClientId) {
    try {
      RealmModel realm = session.getContext().getRealm();

      ClientModel client = session.clients().getClientByClientId(realm, ccClientId);
      if (client == null || !client.isEnabled()) {
        LOG.warnf("Service-account client '%s' not found or disabled", ccClientId);
        return null;
      }

      UserModel serviceAccount = session.users().getServiceAccount(client);
      if (serviceAccount == null) {
        LOG.warnf("No service-account user for client '%s'", ccClientId);
        return null;
      }

      String issuer = session.getContext().getUri()
          .getBaseUri().toString().replaceAll("/+$", "")
          + "/realms/" + realm.getName();

      AccessToken accessToken = new AccessToken();
      accessToken.id(UUID.randomUUID().toString());
      accessToken.issuer(issuer);
      accessToken.subject(serviceAccount.getId());
      accessToken.issuedNow();
      accessToken.exp((long) (Time.currentTime() + 60));
      accessToken.type("Bearer");
      accessToken.issuedFor(ccClientId);
      accessToken.addAudience(ccClientId);
      accessToken.setPreferredUsername(
          serviceAccount.getUsername());

      String algorithm = realm.getDefaultSignatureAlgorithm();
      if (algorithm == null || algorithm.isBlank()) {
        algorithm = "RS256";
      }

      SignatureSignerContext signer = session.getProvider(SignatureProvider.class, algorithm).signer();
      return new JWSBuilder().type("JWT").jsonContent(accessToken).sign(signer);

    } catch (Exception e) {
      LOG.errorf(e, "Failed to mint internal service-account token for '%s'", ccClientId);
      return null;
    }
  }
}
