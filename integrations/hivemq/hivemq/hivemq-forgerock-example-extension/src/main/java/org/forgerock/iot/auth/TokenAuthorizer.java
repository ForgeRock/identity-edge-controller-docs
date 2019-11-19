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

package org.forgerock.iot.auth;

import com.hivemq.extension.sdk.api.annotations.NotNull;
import com.hivemq.extension.sdk.api.async.Async;
import com.hivemq.extension.sdk.api.async.TimeoutFallback;
import com.hivemq.extension.sdk.api.auth.PublishAuthorizer;
import com.hivemq.extension.sdk.api.auth.SubscriptionAuthorizer;
import com.hivemq.extension.sdk.api.auth.parameter.PublishAuthorizerInput;
import com.hivemq.extension.sdk.api.auth.parameter.PublishAuthorizerOutput;
import com.hivemq.extension.sdk.api.auth.parameter.SubscriptionAuthorizerInput;
import com.hivemq.extension.sdk.api.auth.parameter.SubscriptionAuthorizerOutput;
import com.hivemq.extension.sdk.api.packets.disconnect.DisconnectReasonCode;
import com.hivemq.extension.sdk.api.services.ManagedExtensionExecutorService;
import com.hivemq.extension.sdk.api.services.Services;
import org.forgerock.iot.config.Configuration;
import org.forgerock.iot.oauth2.OAuth2PublishAuthorizer;
import org.forgerock.iot.oauth2.OAuth2SubscriptionAuthorizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.Optional;

import static java.time.temporal.ChronoUnit.SECONDS;
import static org.forgerock.iot.auth.TokenAuthenticator.TOKEN_KEY;

/**
 * A subscribe and publish authorizer that uses an OAuth 2 Token for authorisation
 * It is assumed that the token has already been store in the connection attribute store
 */
public class TokenAuthorizer implements SubscriptionAuthorizer, PublishAuthorizer {

    private static final Logger log = LoggerFactory.getLogger(TokenAuthorizer.class);

    final Configuration configuration;
    public TokenAuthorizer(Configuration configuration){
        this.configuration = configuration;
    }

    @Override
    public void authorizeSubscribe(@NotNull final SubscriptionAuthorizerInput input, @NotNull final SubscriptionAuthorizerOutput output) {

        final Optional<String> token = input.getConnectionInformation()
                .getConnectionAttributeStore()
                .getAsString(TOKEN_KEY);

        //disconnect client if the token is not present
        if (!token.isPresent()) {
            log.info("Token is not present");
            output.disconnectClient(DisconnectReasonCode.NOT_AUTHORIZED);
            return;
        }


//        log.info("Subscribe Token is {}", token.get());

        //access managed extension executor service
        final ManagedExtensionExecutorService extensionExecutorService = Services.extensionExecutorService();

        //make output async with timeout of 10 seconds and when operation timed out, auth will fail
        final Async<SubscriptionAuthorizerOutput> asyncOutput = output.async(Duration.of(10, SECONDS), TimeoutFallback.FAILURE);

        //submit external task to managed extension executor service
        extensionExecutorService.submit( new OAuth2SubscriptionAuthorizer(configuration, asyncOutput, token.get()) );
    }

    @Override
    public void authorizePublish(@NotNull PublishAuthorizerInput input, @NotNull PublishAuthorizerOutput output) {

        final Optional<String> token = input.getConnectionInformation()
                .getConnectionAttributeStore()
                .getAsString(TOKEN_KEY);

        //disconnect client if the token is not present
        if (!token.isPresent()) {
            log.info("Token is not present");
            output.disconnectClient(DisconnectReasonCode.NOT_AUTHORIZED);
            return;
        }


//        log.info("Publish Token is {}", token.get());

        //access managed extension executor service
        final ManagedExtensionExecutorService extensionExecutorService = Services.extensionExecutorService();

        //make output async with timeout of 10 seconds and when operation timed out, auth will fail
        final Async<PublishAuthorizerOutput> asyncOutput = output.async(Duration.of(10, SECONDS), TimeoutFallback.FAILURE);

        //submit external task to managed extension executor service
        extensionExecutorService.submit( new OAuth2PublishAuthorizer(configuration, asyncOutput, token.get()) );
    }
}
