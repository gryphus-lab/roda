/**
 * The contents of this file are subject to the license and copyright
 * detailed in the LICENSE file at the root of the source
 * tree and available online at
 *
 * https://github.com/keeps/roda
 */
package org.roda.core.common;

import java.io.IOException;
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

import static org.roda.core.RodaCoreFactory.validateCentralInstanceUrl;

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
      if (currentToken != null && !tokenExpired()) {
          return currentToken;
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

      try (CloseableHttpClient httpClient = HttpClientBuilder.create().build()) {
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

              return switch (responseStatusCode) {
                  case 200 -> JsonUtils.getObjectFromJson(responseEntity.getContent(), AccessToken.class);
                  case 401 -> throw new AuthenticationDeniedException("Cannot authenticate on central instance with current configuration");
                  default -> throw new GenericException("url: " + url + ", response code; " + responseStatusCode);
              };
          } catch (IOException e) {
              throw new GenericException("Error sending POST request", e);
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
  }
}
