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
import com.hivemq.extension.sdk.api.auth.parameter.SubscriptionAuthorizerOutput;
import com.hivemq.extension.sdk.api.packets.disconnect.DisconnectReasonCode;
import org.forgerock.iot.config.Configuration;

import java.util.Optional;

/**
 * Runnable OAuth 2 Subscribe Authorizer
 */
public class OAuth2SubscriptionAuthorizer extends OAuth2Authorizer<SubscriptionAuthorizerOutput> {

    public OAuth2SubscriptionAuthorizer(@NotNull Configuration configuration, @NotNull Async<SubscriptionAuthorizerOutput> async, @NotNull String token){
        super(configuration, async, token);
    }

    @Override
    void processResponse(Optional<String> response) {
        final SubscriptionAuthorizerOutput output = super.async.getOutput();
        if(response.isPresent() && isTokenActive(response.get())) {
            output.nextExtensionOrDefault();
        } else {
            output.disconnectClient(DisconnectReasonCode.NOT_AUTHORIZED);
        }
    }
}
