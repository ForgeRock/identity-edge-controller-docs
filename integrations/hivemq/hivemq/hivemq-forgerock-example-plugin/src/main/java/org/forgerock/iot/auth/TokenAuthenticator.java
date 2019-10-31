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

import com.hivemq.extension.sdk.api.async.Async;
import com.hivemq.extension.sdk.api.async.TimeoutFallback;
import com.hivemq.extension.sdk.api.services.ManagedExtensionExecutorService;
import com.hivemq.extension.sdk.api.services.Services;
import org.forgerock.iot.oauth2.OAuth2Authenticator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.hivemq.extension.sdk.api.annotations.NotNull;
import com.hivemq.extension.sdk.api.auth.SimpleAuthenticator;
import com.hivemq.extension.sdk.api.auth.parameter.SimpleAuthInput;
import com.hivemq.extension.sdk.api.auth.parameter.SimpleAuthOutput;
import com.hivemq.extension.sdk.api.packets.connect.ConnectPacket;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Optional;

import static com.hivemq.extension.sdk.api.packets.connect.ConnackReasonCode.BAD_USER_NAME_OR_PASSWORD;
import static java.time.temporal.ChronoUnit.SECONDS;

/**
 * A simple authenticator class that expects the client to present an OAuth 2 token as its password on connection
 */
public class TokenAuthenticator implements SimpleAuthenticator {

    public static final String TOKEN_KEY = "token";
    private static final Logger log = LoggerFactory.getLogger(TokenAuthenticator.class);

    public TokenAuthenticator() {
    }

    @Override
    public void onConnect(final @NotNull SimpleAuthInput input, final @NotNull SimpleAuthOutput output) {

        //get connect packet from input object and retrieve password
        final ConnectPacket connectPacket = input.getConnectPacket();
        Optional<ByteBuffer> password = connectPacket.getPassword();

        if( !password.isPresent() ){
            //require password for authentication
            log.info("missing password");
            output.failAuthentication(BAD_USER_NAME_OR_PASSWORD, "missing password");
            return;
        }

        final String token = getStringFromBuffer(password.get());
//        log.info("password is {}", token);

        //store token in the attribute store for the connection so that is can be used by the authorisation service
        //during publish and subscribe requests
        input.getConnectionInformation().getConnectionAttributeStore().putAsString(TOKEN_KEY, token);

        //access managed extension executor service
        final ManagedExtensionExecutorService extensionExecutorService = Services.extensionExecutorService();

        //make output async with timeout of 10 seconds and when operation timed out, auth will fail
        final Async<SimpleAuthOutput> asyncOutput = output.async(Duration.of(10, SECONDS), TimeoutFallback.FAILURE);

        //submit external task to managed extension executor service
        extensionExecutorService.submit( new OAuth2Authenticator(asyncOutput, token) );
    }

    /**
     * Read string from byte buffer
     * @param byteBuffer
     * @return
     */
    private String getStringFromBuffer(final ByteBuffer byteBuffer) {
        final byte[] bytes = new byte[byteBuffer.remaining()];
        byteBuffer.get(bytes);
        return new String(bytes, StandardCharsets.UTF_8);
    }

}
