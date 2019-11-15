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
import com.hivemq.extension.sdk.api.auth.parameter.SimpleAuthOutput;
import com.hivemq.extension.sdk.api.auth.parameter.TopicPermission;
import com.hivemq.extension.sdk.api.packets.auth.ModifiableDefaultPermissions;
import com.hivemq.extension.sdk.api.packets.connect.ConnackReasonCode;
import com.hivemq.extension.sdk.api.services.builder.Builders;
import org.forgerock.iot.config.Configuration;

import java.util.Optional;

/**
 * Runnable OAuth 2 Authenticator
 */
public class OAuth2Authenticator extends OAuth2Validator<SimpleAuthOutput> {

    public OAuth2Authenticator(@NotNull Configuration configuration, @NotNull Async<SimpleAuthOutput> async, @NotNull String token){
        super(configuration, async, token);
    }

    @Override
    void processResponse(Optional<String> response) {
        log.info("Processing response for authentication");
        final SimpleAuthOutput output = super.async.getOutput();
        boolean allow = false;
        if(response.isPresent() && isTokenActive(response.get())) {
            log.info("authentication: token is active");

            Optional<String> mqttScope = getMQTTScope(response.get());
            if(mqttScope.isPresent()) {
                log.info("authentication: MQTT scope is %s", mqttScope.get());
                //Get the default permissions from the output
                final ModifiableDefaultPermissions defaultPermissions = output.getDefaultPermissions();

                //create a permission for topic base on scope in token
                final TopicPermission permission = Builders.topicPermission()
                        .topicFilter(mqttScope.get())
                        .qos(TopicPermission.Qos.ALL)
                        .activity(TopicPermission.MqttActivity.ALL)
                        .type(TopicPermission.PermissionType.ALLOW)
                        .retain(TopicPermission.Retain.ALL)
                        .build();

                //add the permission to the default permissions for this client
                defaultPermissions.add(permission);

                allow = true;
            } else {
                log.info("authentication: no mqtt scope");
            }

        }
        if( allow ){
            log.info("authentication: successful");
            output.authenticateSuccessfully();
        } else {
            output.failAuthentication(ConnackReasonCode.NOT_AUTHORIZED, "OAuth2 verification failed");
        }
    }

    @Override
    public void run(){
        log.info("Running OAuth 2 Authenticator");
        super.run();
    }
}
