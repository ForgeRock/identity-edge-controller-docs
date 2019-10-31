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
import org.forgerock.iot.auth.TokenAuthenticator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Runnable abstract class for verifying an OAuth 2 token
 * @param <T> The output type for the authenticator\authorizer
 */
public abstract class OAuth2Validator<T> implements Runnable {

    final private String token;
    final protected Async<T> async;
    private static final Logger log = LoggerFactory.getLogger(TokenAuthenticator.class);

    OAuth2Validator(@NotNull Async<T> async, @NotNull String token){
        this.token = token;
        this.async = async;
    }


    @Override
    public void run() {
        log.info("running oauth 2 validator");

        // allow everything for the moment
        // tell HiveMQ that auth was successful\failed
        enforce(true);

        //resume output to tell HiveMQ auth is complete
        async.resume();
    }

    abstract void enforce(Boolean result);
}

