/*
 * Copyright 2019 ForgeRock AS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.forgerock.iot.oauth2;

import com.hivemq.extension.sdk.api.annotations.NotNull;
import com.hivemq.extension.sdk.api.async.Async;
import org.apache.http.Consts;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.forgerock.iot.auth.TokenAuthenticator;
import org.forgerock.iot.config.Configuration;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


/**
 * Runnable abstract class for verifying an OAuth 2 token
 * @param <T> The output type for the authenticator\authorizer
 */
public abstract class OAuth2Validator<T> implements Runnable {

    final Configuration configuration;
    final private String token;
    final Async<T> async;
    protected static final Logger log = LoggerFactory.getLogger(TokenAuthenticator.class);
    static protected final Pattern pattern = Pattern.compile("(?<=mqtt:)[/\\w]+");

    OAuth2Validator(@NotNull Configuration configuration, @NotNull Async<T> async, @NotNull String token){
        this.configuration = configuration;
        this.token = token;
        this.async = async;
    }

    /**
     * Returns true if the introspection indicates that the token is active
     * @param response
     * @return
     */
    protected static boolean isTokenActive(String response) {
        try {
            JSONObject obj = new JSONObject(response);
            Object active = obj.get("active");
            if(!(active instanceof Boolean)){
                log.error("Introspection doesn't contain a Boolean \"active\"");
                return false;
            }
            log.info("Introspection has active value of " + active);
            return (Boolean) active;
        } catch (JSONException e) {
            log.error("Failed to parse introspection data", e);
            return false;
        }
    }

    /**
     * Return the MQTT specific scope from the token, if any
     * @param response
     * @return
     */
    protected static Optional<String> getMQTTScope(String response) {
        try {
            JSONObject obj = new JSONObject(response);
            Object scope = obj.get("scope");
            if(!(scope instanceof String)){
                log.error("Introspection doesn't contain a String \"scope\"");
                return Optional.empty();
            }
            Matcher m = pattern.matcher((String)scope);
            if( !m.find() ){
                return Optional.empty();
            }
            return Optional.of(m.group());
        } catch (JSONException e) {
            log.error("Failed to parse introspection data", e);
            return Optional.empty();
        }
    }

    /**
     * Packages the token into an URL encoded form entity
     * @return
     */
    private UrlEncodedFormEntity introspectionFormEntity() {
        List<NameValuePair> form = new ArrayList<>();
        form.add(new BasicNameValuePair("token", token));
        return new UrlEncodedFormEntity(form, Consts.UTF_8);
    }

    @Override
    public void run() {
        Optional<String> responseBody = Optional.empty();
        CloseableHttpClient httpclient = HttpClients.createDefault();
        HttpPost httpPost = new HttpPost(configuration.introspectEndpoint());
        httpPost.setEntity(this.introspectionFormEntity());

        try (CloseableHttpResponse response = httpclient.execute(httpPost)) {
            if(response.getStatusLine().getStatusCode() != HttpStatus.SC_OK){
                log.error(response.getStatusLine().toString());
            } else {
                responseBody = Optional.of(EntityUtils.toString(response.getEntity()));
            }
        } catch (IOException e) {
            log.error(e.getMessage());
        } finally {
            try {
                httpclient.close();
            } catch (IOException e) {
                log.error(e.getMessage());
            }
        }

        // process the response and tell HiveMQ that auth was successful\failed
        processResponse(responseBody);

        //resume output to tell HiveMQ auth is complete
        async.resume();
    }

    /**
     * Process the introspection response, authenticating or authorising depending on the context
     * @param response
     */
    abstract void processResponse(Optional<String> response);
}

