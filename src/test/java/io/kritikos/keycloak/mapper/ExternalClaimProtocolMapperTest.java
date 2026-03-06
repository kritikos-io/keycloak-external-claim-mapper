package io.kritikos.keycloak.mapper;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.representations.IDToken;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import io.kritikos.keycloak.config.ExternalClaimMapperConfig;
import io.kritikos.keycloak.service.ExternalClaimApiClient;

@ExtendWith(MockitoExtension.class)
class ExternalClaimProtocolMapperTest {

  @Mock
  private ExternalClaimApiClient apiClient;
  @Mock
  private KeycloakSession keycloakSession;
  @Mock
  private KeycloakContext keycloakContext;
  @Mock
  private RealmModel realmModel;
  @Mock
  private UserSessionModel userSession;
  @Mock
  private ClientSessionContext clientSessionCtx;
  @Mock
  private AuthenticatedClientSessionModel clientSession;
  @Mock
  private ClientModel clientModel;
  @Mock
  private UserModel userModel;

  private ExternalClaimProtocolMapper mapper;
  private ProtocolMapperModel mappingModel;

  @BeforeEach
  void setUp() {
    mapper = new ExternalClaimProtocolMapper(apiClient);

    mappingModel = new ProtocolMapperModel();
    mappingModel.setName("test-mapper");

    Map<String, String> config = new HashMap<>();
    config.put(ExternalClaimMapperConfig.CONFIG_API_BASE_URL, "https://api.example.com");
    config.put(ExternalClaimMapperConfig.CONFIG_CLAIM_NAME, "app_privileges");
    config.put(ExternalClaimMapperConfig.CONFIG_AUTH_MODE, "none");
    config.put(ExternalClaimMapperConfig.CONFIG_CONNECT_TIMEOUT, "5000");
    config.put(ExternalClaimMapperConfig.CONFIG_READ_TIMEOUT, "10000");
    config.put("access.token.claim", "true");
    config.put("claim.name", "app_privileges");
    config.put("jsonType.label", "String");
    mappingModel.setConfig(config);
  }

  @Test
  @DisplayName("Provider ID matches the configured constant")
  void providerIdIsCorrect() {
    assertEquals(ExternalClaimMapperConfig.PROVIDER_ID, mapper.getId());
  }

  @Test
  @DisplayName("getConfigProperties returns non-empty list")
  void configPropertiesAreExposed() {
    assertFalse(mapper.getConfigProperties().isEmpty());
  }

  @Test
  @DisplayName("Mapper sets claim when API returns data")
  void setsClaimFromApiResponse() {
    when(userSession.getUser()).thenReturn(userModel);
    when(userModel.getId()).thenReturn("user-123");
    when(userModel.getUsername()).thenReturn("testuser");
    when(userModel.getEmail()).thenReturn("test@example.com");
    when(clientSessionCtx.getClientSession()).thenReturn(clientSession);
    when(clientSession.getClient()).thenReturn(clientModel);
    when(clientModel.getClientId()).thenReturn("my-app");

    String apiResponseJson = """
        {
          "userId": "user-123",
          "clientId": "my-app",
          "privileges": [
            { "name": "read:reports", "description": "Can read reports" },
            { "name": "write:orders", "description": "Can create orders" }
          ]
        }
        """;

    when(apiClient.fetchClaims(
        eq("https://api.example.com"),
        eq("/privileges?userId={userId}&clientId={clientId}"),
        eq("user-123"),
        eq("testuser"),
        eq("test@example.com"),
        eq("my-app"),
        eq("none"),
        isNull(),
        eq("X-API-Key"),
        isNull(),
        isNull(),
        isNull(),
        eq(5000),
        eq(10000),
        eq(false))).thenReturn(apiResponseJson);

    IDToken token = new IDToken();

    mapper.setClaim(token, mappingModel, userSession, keycloakSession, clientSessionCtx);

    Object claim = token.getOtherClaims().get("app_privileges");
    assertNotNull(claim, "Claim should be present");
    @SuppressWarnings("unchecked")
    List<String> privileges = (List<String>) claim;
    assertEquals(2, privileges.size());
    assertEquals("read:reports", privileges.get(0));
    assertEquals("write:orders", privileges.get(1));
  }

  @Test
  @DisplayName("Mapper handles API returning null gracefully")
  void handlesNullApiResponse() {
    when(userSession.getUser()).thenReturn(userModel);
    when(userModel.getId()).thenReturn("user-456");
    when(userModel.getUsername()).thenReturn("nulluser");
    when(userModel.getEmail()).thenReturn(null);
    when(clientSessionCtx.getClientSession()).thenReturn(clientSession);
    when(clientSession.getClient()).thenReturn(clientModel);
    when(clientModel.getClientId()).thenReturn("other-app");

    when(apiClient.fetchClaims(
        anyString(), anyString(), anyString(), anyString(), any(), anyString(),
        any(), any(), any(), any(), any(), any(),
        anyInt(), anyInt(), anyBoolean()))
        .thenReturn(null);

    IDToken token = new IDToken();

    assertDoesNotThrow(() -> mapper.setClaim(token, mappingModel, userSession, keycloakSession, clientSessionCtx));
  }

  @Test
  @DisplayName("Mapper skips when base URL is blank and Root URL fallback returns null")
  void skipsWhenBaseUrlBlankAndRootUrlNull() {
    mappingModel.getConfig().put(ExternalClaimMapperConfig.CONFIG_API_BASE_URL, "");

    when(clientSessionCtx.getClientSession()).thenReturn(clientSession);
    when(clientSession.getClient()).thenReturn(clientModel);
    when(clientModel.getRootUrl()).thenReturn(null);

    IDToken token = new IDToken();

    mapper.setClaim(token, mappingModel, userSession, keycloakSession, clientSessionCtx);

    verifyNoInteractions(apiClient);
  }

  @Test
  @DisplayName("Mapper falls back to Home URL when configured")
  void fallsBackToHomeUrl() {
    mappingModel.getConfig().put(ExternalClaimMapperConfig.CONFIG_API_BASE_URL, "");
    mappingModel.getConfig().put(ExternalClaimMapperConfig.CONFIG_URL_FALLBACK,
        ExternalClaimMapperConfig.FALLBACK_HOME_URL);

    when(userSession.getUser()).thenReturn(userModel);
    when(userModel.getId()).thenReturn("user-home");
    when(userModel.getUsername()).thenReturn("homeuser");
    when(userModel.getEmail()).thenReturn("home@example.com");
    when(clientSessionCtx.getClientSession()).thenReturn(clientSession);
    when(clientSession.getClient()).thenReturn(clientModel);
    when(clientModel.getBaseUrl()).thenReturn("https://home.example.com");
    when(clientModel.getClientId()).thenReturn("home-app");

    when(apiClient.fetchClaims(
        eq("https://home.example.com"),
        anyString(), anyString(), anyString(), any(), anyString(),
        any(), any(), any(), any(), any(), any(),
        anyInt(), anyInt(), anyBoolean()))
        .thenReturn(null);

    IDToken token = new IDToken();
    mapper.setClaim(token, mappingModel, userSession, keycloakSession, clientSessionCtx);

    verify(apiClient).fetchClaims(
        eq("https://home.example.com"),
        anyString(), anyString(), anyString(), any(), anyString(),
        any(), any(), any(), any(), any(), any(),
        anyInt(), anyInt(), anyBoolean());
  }

  @Test
  @DisplayName("Mapper skips when Home URL fallback is blank")
  void skipsWhenHomeUrlFallbackBlank() {
    mappingModel.getConfig().put(ExternalClaimMapperConfig.CONFIG_API_BASE_URL, "");
    mappingModel.getConfig().put(ExternalClaimMapperConfig.CONFIG_URL_FALLBACK,
        ExternalClaimMapperConfig.FALLBACK_HOME_URL);

    when(clientSessionCtx.getClientSession()).thenReturn(clientSession);
    when(clientSession.getClient()).thenReturn(clientModel);
    when(clientModel.getBaseUrl()).thenReturn(null);

    IDToken token = new IDToken();

    mapper.setClaim(token, mappingModel, userSession, keycloakSession, clientSessionCtx);

    verifyNoInteractions(apiClient);
  }

  @Test
  @DisplayName("Mapper passes client_credentials config to API client")
  void passesClientCredentialsConfig() {
    Map<String, String> config = mappingModel.getConfig();
    config.put(ExternalClaimMapperConfig.CONFIG_AUTH_MODE, "client_credentials");
    config.put(ExternalClaimMapperConfig.CONFIG_TOKEN_ENDPOINT, "https://auth.example.com/token");
    config.put(ExternalClaimMapperConfig.CONFIG_CC_CLIENT_ID, "service-account");
    config.put(ExternalClaimMapperConfig.CONFIG_CC_CLIENT_SECRET, "s3cret");

    when(userSession.getUser()).thenReturn(userModel);
    when(userModel.getId()).thenReturn("user-789");
    when(userModel.getUsername()).thenReturn("ccuser");
    when(userModel.getEmail()).thenReturn("cc@example.com");
    when(clientSessionCtx.getClientSession()).thenReturn(clientSession);
    when(clientSession.getClient()).thenReturn(clientModel);
    when(clientModel.getClientId()).thenReturn("cc-app");

    when(apiClient.fetchClaims(
        eq("https://api.example.com"),
        eq("/privileges?userId={userId}&clientId={clientId}"),
        eq("user-789"),
        eq("ccuser"),
        eq("cc@example.com"),
        eq("cc-app"),
        eq("client_credentials"),
        isNull(),
        eq("X-API-Key"),
        eq("https://auth.example.com/token"),
        eq("service-account"),
        eq("s3cret"),
        eq(5000),
        eq(10000),
        eq(false))).thenReturn(null);

    IDToken token = new IDToken();
    mapper.setClaim(token, mappingModel, userSession, keycloakSession, clientSessionCtx);

    verify(apiClient).fetchClaims(
        eq("https://api.example.com"),
        eq("/privileges?userId={userId}&clientId={clientId}"),
        eq("user-789"),
        eq("ccuser"),
        eq("cc@example.com"),
        eq("cc-app"),
        eq("client_credentials"),
        isNull(),
        eq("X-API-Key"),
        eq("https://auth.example.com/token"),
        eq("service-account"),
        eq("s3cret"),
        eq(5000),
        eq(10000),
        eq(false));
  }

  @Test
  @DisplayName("Mapper auto-resolves Keycloak token endpoint when left blank")
  void autoResolvesTokenEndpoint() {
    Map<String, String> config = mappingModel.getConfig();
    config.put(ExternalClaimMapperConfig.CONFIG_AUTH_MODE, "client_credentials");
    config.put(ExternalClaimMapperConfig.CONFIG_CC_CLIENT_ID, "svc");
    config.put(ExternalClaimMapperConfig.CONFIG_CC_CLIENT_SECRET, "secret");

    when(userSession.getUser()).thenReturn(userModel);
    when(userModel.getId()).thenReturn("user-auto");
    when(userModel.getUsername()).thenReturn("autouser");
    when(userModel.getEmail()).thenReturn("auto@example.com");
    when(clientSessionCtx.getClientSession()).thenReturn(clientSession);
    when(clientSession.getClient()).thenReturn(clientModel);
    when(clientModel.getClientId()).thenReturn("auto-app");

    when(keycloakSession.getContext()).thenReturn(keycloakContext);
    org.keycloak.models.KeycloakUriInfo uriInfo = mock(org.keycloak.models.KeycloakUriInfo.class);
    when(keycloakContext.getUri()).thenReturn(uriInfo);
    when(uriInfo.getBaseUri()).thenReturn(URI.create("http://localhost:8080/"));
    when(keycloakContext.getRealm()).thenReturn(realmModel);
    when(realmModel.getName()).thenReturn("myrealm");

    when(apiClient.fetchClaims(
        eq("https://api.example.com"),
        eq("/privileges?userId={userId}&clientId={clientId}"),
        eq("user-auto"),
        eq("autouser"),
        eq("auto@example.com"),
        eq("auto-app"),
        eq("client_credentials"),
        isNull(),
        eq("X-API-Key"),
        eq("http://localhost:8080/realms/myrealm/protocol/openid-connect/token"),
        eq("svc"),
        eq("secret"),
        eq(5000),
        eq(10000),
        eq(false))).thenReturn(null);

    IDToken token = new IDToken();
    mapper.setClaim(token, mappingModel, userSession, keycloakSession, clientSessionCtx);

    verify(apiClient).fetchClaims(
        anyString(), anyString(), anyString(), anyString(), any(), anyString(),
        eq("client_credentials"),
        any(),
        anyString(),
        eq("http://localhost:8080/realms/myrealm/protocol/openid-connect/token"),
        anyString(), anyString(),
        anyInt(), anyInt(), anyBoolean());
  }
}
