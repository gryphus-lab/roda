/**
 * The contents of this file are subject to the license and copyright
 * detailed in the LICENSE file at the root of the source
 * tree and available online at
 *
 * https://github.com/keeps/roda
 */
package org.roda.core.common;

import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.Date;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.roda.core.data.common.RodaConstants;
import org.roda.core.data.exceptions.AuthenticationDeniedException;
import org.roda.core.data.exceptions.GenericException;
import org.roda.core.data.exceptions.RODAException;
import org.roda.core.data.utils.JsonUtils;
import org.roda.core.data.v2.accessToken.AccessToken;
import org.roda.core.data.v2.synchronization.local.LocalInstance;

/**
 * @author Gabriel Barros <gbarros@keep.pt>
 */
public class TokenManager {
  private static TokenManager instance;
  private AccessToken currentToken;
  private Date expirationTime;

  private TokenManager() {
    // do nothing
  }

  public static TokenManager getInstance() {
    if (instance == null) {
      instance = new TokenManager();
    }
    return instance;
  }

  public AccessToken getAccessToken(LocalInstance localInstance)
    throws AuthenticationDeniedException, GenericException {
    try {
      if (currentToken != null) {
        if (!tokenExpired()) {
          return currentToken;
        }
      }
      currentToken = grantToken(localInstance);
      setExpirationTime();
      return currentToken;
    } catch (RODAException e) {
      currentToken = null;
      throw e;
    }
  }

  public AccessToken grantToken(LocalInstance localInstance) throws GenericException, AuthenticationDeniedException {
    String centralInstanceUrl = localInstance.getCentralInstanceURL();
    validateCentralInstanceUrl(centralInstanceUrl);

    CloseableHttpClient httpClient = HttpClientBuilder.create().build();
    String url = centralInstanceUrl + RodaConstants.API_SEP + RodaConstants.API_REST_V2_MEMBERS
      + RodaConstants.API_PATH_PARAM_AUTH_TOKEN;
    HttpPost httpPost = new HttpPost(url);
    httpPost.addHeader("Authorization", "Bearer " + localInstance.getAccessKey());
    httpPost.addHeader("content-type", "application/json");

    try {
      httpPost.setEntity(new StringEntity(localInstance.getAccessKey()));
      HttpResponse response = httpClient.execute(httpPost);
      HttpEntity responseEntity = response.getEntity();
      int responseStatusCode = response.getStatusLine().getStatusCode();

      if (responseStatusCode == 200) {
        return JsonUtils.getObjectFromJson(responseEntity.getContent(), AccessToken.class);
      } else if (responseStatusCode == 401) {
        throw new AuthenticationDeniedException("Cannot authenticate on central instance with current configuration");
      } else {
        throw new GenericException("url: " + url + ", response code; " + responseStatusCode);
      }
    } catch (IOException e) {
      throw new GenericException("Error sending POST request", e);
    }
  }

  private void setExpirationTime() {
    long today = new Date().getTime();
    expirationTime = new Date(today + currentToken.getExpiresIn());
  }

  private boolean tokenExpired() {
    return new Date().after(expirationTime);
  }

  public void removeToken() {
    this.currentToken = null;

  private void validateCentralInstanceUrl(String url) throws GenericException {
    try {
      if (url == null || url.isEmpty()) {
        throw new GenericException("Central instance URL must not be empty");
      }
      URI uri = new URI(url);
      String scheme = uri.getScheme();
      if (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme)) {
        throw new GenericException("Central instance URL must use http or https scheme");
      }
      String host = uri.getHost();
      if (host == null || host.isEmpty()) {
        throw new GenericException("Central instance URL must contain a host");
      }
      InetAddress address = InetAddress.getByName(host);
      if (address.isAnyLocalAddress() || address.isLoopbackAddress() || address.isLinkLocalAddress()
        || address.isSiteLocalAddress()) {
        throw new GenericException("Central instance URL host is not allowed");
      }
    } catch (UnknownHostException e) {
      throw new GenericException("Cannot resolve central instance URL host", e);
    } catch (URISyntaxException e) {
      throw new GenericException("Invalid central instance URL", e);
    }
  }
  }
}
