package io.kritikos.keycloak.service;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Map;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.jboss.logging.Logger;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.kritikos.keycloak.config.ExternalClaimMapperConfig;

/**
 * HTTP client that calls the external claim API.
 * <p>
 * Returns the raw JSON response body so the caller can apply a JSONPath
 * expression to extract the desired claim value.
 * <p>
 * Supports four authentication modes:
 * <ul>
 * <li><b>none</b> – no authentication header</li>
 * <li><b>api_key</b> – static key sent via a configurable header
 * (defaults to {@code X-API-Key})</li>
 * <li><b>user_token</b> – forwards the authenticating user's own session
 * JWT as a {@code Bearer} token</li>
 * <li><b>client_credentials</b> – OAuth2 client-credentials grant;
 * an access token is obtained from the configured token endpoint
 * and sent as a {@code Bearer} token</li>
 * </ul>
 */
public class ExternalClaimApiClient {

  private static final Logger LOG = Logger.getLogger(ExternalClaimApiClient.class);
  private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper()
      .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

  /**
   * Fetch claims for a given user + client combination.
   *
   * @param baseUrl        the API base URL (no trailing slash)
   * @param pathTemplate   path template with {userId}, {username}, {email},
   *                       and {clientId} placeholders
   * @param userId         the Keycloak user ID (sub)
   * @param username       the Keycloak username
   * @param email          the Keycloak user email (may be {@code null})
   * @param clientId       the OAuth2 client_id of the requesting application
   * @param authMode       authentication mode (none / api_key / user_token /
   *                       client_credentials)
   * @param apiKey         API key (used when authMode is api_key)
   * @param apiKeyHeader   custom header name for the API key (defaults to
   *                       {@code X-API-Key})
   * @param tokenEndpoint  OAuth2 token endpoint (used when authMode is
   *                       client_credentials)
   * @param ccClientId     client ID for the credentials grant
   * @param ccClientSecret client secret for the credentials grant
   * @param connectTimeout connection timeout in milliseconds
   * @param readTimeout    read/response timeout in milliseconds
   * @param tlsSkipVerify  if {@code true}, skip TLS certificate validation (dev
   *                       only)
   * @return raw JSON response body, or {@code null} on failure
   */
  public String fetchClaims(
      String baseUrl,
      String pathTemplate,
      String userId,
      String username,
      String email,
      String clientId,
      String authMode,
      String apiKey,
      String apiKeyHeader,
      String tokenEndpoint,
      String ccClientId,
      String ccClientSecret,
      int connectTimeout,
      int readTimeout,
      boolean tlsSkipVerify) {

    String safeEmail = email != null ? email : "";
    String resolvedPath = pathTemplate
        .replace("{userId}", userId)
        .replace("{username}", username)
        .replace("{email}", URLEncoder.encode(safeEmail, StandardCharsets.UTF_8))
        .replace("{clientId}", clientId);
    String url = baseUrl.replaceAll("/+$", "") + resolvedPath;

    LOG.debugf("Fetching claims from %s", url);

    try {
      HttpClient.Builder httpClientBuilder = HttpClient.newBuilder()
          .connectTimeout(Duration.ofMillis(connectTimeout));

      if (tlsSkipVerify) {
        httpClientBuilder.sslContext(createTrustAllSslContext());
      }

      HttpClient httpClient = httpClientBuilder.build();

      HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
          .uri(URI.create(url))
          .timeout(Duration.ofMillis(readTimeout))
          .header("Accept", "application/json")
          .GET();

      applyAuth(requestBuilder, httpClient, authMode, apiKey, apiKeyHeader,
          tokenEndpoint, ccClientId, ccClientSecret, readTimeout);

      HttpResponse<String> response = httpClient.send(
          requestBuilder.build(),
          HttpResponse.BodyHandlers.ofString());

      if (response.statusCode() >= 200 && response.statusCode() < 300) {
        return response.body();
      }

      LOG.warnf("External API returned HTTP %d for user=%s client=%s",
          response.statusCode(), userId, clientId);

    } catch (IOException | InterruptedException e) {
      LOG.errorf(e, "Error calling external API for user=%s client=%s", userId, clientId);
      if (e instanceof InterruptedException) {
        Thread.currentThread().interrupt();
      }
    }

    return null;
  }

  /**
   * Applies the configured authentication to the outgoing HTTP request.
   * <p>
   * For {@code api_key} mode, the API key is sent using the configured header
   * name (defaults to {@code X-API-Key}). For {@code user_token} mode, the
   * user's own session JWT (passed via the {@code apiKey} parameter) is sent
   * as a {@code Bearer} token. For {@code client_credentials} mode, an OAuth2
   * token is obtained and sent as a {@code Bearer} header. For {@code bearer}
   * mode, a pre-obtained token (e.g. minted internally by the mapper) is sent
   * directly.
   */
  private void applyAuth(
      HttpRequest.Builder requestBuilder,
      HttpClient httpClient,
      String authMode,
      String apiKey,
      String apiKeyHeader,
      String tokenEndpoint,
      String ccClientId,
      String ccClientSecret,
      int readTimeout) throws IOException, InterruptedException {

    if (authMode == null) {
      return;
    }

    switch (authMode) {
      case ExternalClaimMapperConfig.AUTH_MODE_API_KEY:
        if (apiKey != null && !apiKey.isBlank()) {
          String headerName = (apiKeyHeader != null && !apiKeyHeader.isBlank())
              ? apiKeyHeader
              : ExternalClaimMapperConfig.DEFAULT_API_KEY_HEADER;
          requestBuilder.header(headerName, apiKey);
        }
        break;

      case ExternalClaimMapperConfig.AUTH_MODE_USER_TOKEN:
        if (apiKey != null && !apiKey.isBlank()) {
          requestBuilder.header("Authorization", "Bearer " + apiKey);
        }
        break;

      case ExternalClaimMapperConfig.AUTH_MODE_CLIENT_CREDENTIALS:
        String bearerToken = obtainClientCredentialsToken(
            httpClient, tokenEndpoint, ccClientId, ccClientSecret, readTimeout);
        if (bearerToken != null) {
          requestBuilder.header("Authorization", "Bearer " + bearerToken);
        } else {
          LOG.warn("Failed to obtain client_credentials token – proceeding without auth.");
        }
        break;

      case ExternalClaimMapperConfig.AUTH_MODE_BEARER:
        if (apiKey != null && !apiKey.isBlank()) {
          requestBuilder.header("Authorization", "Bearer " + apiKey);
        }
        break;

      case ExternalClaimMapperConfig.AUTH_MODE_NONE:
      default:
        break;
    }
  }

  /**
   * Performs an OAuth2 client_credentials grant and returns the access token.
   */
  String obtainClientCredentialsToken(
      HttpClient httpClient,
      String tokenEndpoint,
      String ccClientId,
      String ccClientSecret,
      int readTimeout) throws IOException, InterruptedException {

    if (tokenEndpoint == null || tokenEndpoint.isBlank()) {
      LOG.warn("Token endpoint is not configured for client_credentials auth.");
      return null;
    }

    StringBuilder body = new StringBuilder()
        .append("grant_type=client_credentials")
        .append("&client_id=").append(urlEncode(ccClientId))
        .append("&client_secret=").append(urlEncode(ccClientSecret));

    HttpRequest tokenRequest = HttpRequest.newBuilder()
        .uri(URI.create(tokenEndpoint))
        .timeout(Duration.ofMillis(readTimeout))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Accept", "application/json")
        .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
        .build();

    LOG.debugf("Requesting client_credentials token from %s", tokenEndpoint);

    HttpResponse<String> tokenResponse = httpClient.send(
        tokenRequest, HttpResponse.BodyHandlers.ofString());

    if (tokenResponse.statusCode() >= 200 && tokenResponse.statusCode() < 300) {
      @SuppressWarnings("unchecked")
      Map<String, Object> parsed = OBJECT_MAPPER.readValue(
          tokenResponse.body(), Map.class);
      Object accessToken = parsed.get("access_token");
      if (accessToken != null) {
        return accessToken.toString();
      }
      LOG.warn("Token endpoint response did not contain 'access_token'.");
    } else {
      LOG.warnf("Token endpoint returned HTTP %d", tokenResponse.statusCode());
    }

    return null;
  }

  private static String urlEncode(String value) {
    return value == null ? "" : URLEncoder.encode(value, StandardCharsets.UTF_8);
  }

  /**
   * Creates an {@link SSLContext} that trusts all certificates.
   * <p>
   * <b>WARNING:</b> this disables all TLS verification and must
   * only be used in development / testing environments.
   * </p>
   */
  private static SSLContext createTrustAllSslContext() {
    try {
      TrustManager[] trustAll = new TrustManager[] {
          new X509TrustManager() {
            @Override
            public X509Certificate[] getAcceptedIssuers() {
              return new X509Certificate[0];
            }

            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) {
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) {
            }
          }
      };
      SSLContext sslContext = SSLContext.getInstance("TLS");
      sslContext.init(null, trustAll, new SecureRandom());
      return sslContext;
    } catch (NoSuchAlgorithmException | KeyManagementException e) {
      throw new RuntimeException("Failed to create trust-all SSLContext", e);
    }
  }
}
