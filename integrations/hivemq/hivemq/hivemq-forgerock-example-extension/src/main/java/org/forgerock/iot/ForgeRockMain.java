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

package org.forgerock.iot;

import com.hivemq.extension.sdk.api.ExtensionMain;
import com.hivemq.extension.sdk.api.annotations.NotNull;
import com.hivemq.extension.sdk.api.annotations.Nullable;
import com.hivemq.extension.sdk.api.auth.Authorizer;
import com.hivemq.extension.sdk.api.auth.SimpleAuthenticator;
import com.hivemq.extension.sdk.api.auth.parameter.AuthenticatorProviderInput;
import com.hivemq.extension.sdk.api.auth.parameter.AuthorizerProviderInput;
import com.hivemq.extension.sdk.api.parameter.*;
import com.hivemq.extension.sdk.api.services.Services;
import com.hivemq.extension.sdk.api.services.auth.SecurityRegistry;
import com.hivemq.extension.sdk.api.services.auth.provider.AuthorizerProvider;
import org.forgerock.iot.auth.TokenAuthorizer;
import org.forgerock.iot.auth.TokenAuthenticator;
import org.forgerock.iot.config.Configuration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * This is the main class of the extension,
 * which is instantiated either during the HiveMQ start up process (if extension is enabled)
 * or when HiveMQ is already started by enabling the extension.
 *
 * @author Florian Limpöck
 * @since 4.0.0
 */
public class ForgeRockMain implements ExtensionMain {

    private static final @NotNull Logger log = LoggerFactory.getLogger(ForgeRockMain.class);
    private static final String PROPERTIES_FILE_NAME = "forgerockExample.properties";

    @Override
    public void extensionStart(final @NotNull ExtensionStartInput extensionStartInput, final @NotNull ExtensionStartOutput extensionStartOutput) {

        try {
            //get properties file
            final File propertiesFile = new File(
                    extensionStartInput.getExtensionInformation().getExtensionHomeFolder(),
                    PROPERTIES_FILE_NAME);


            //load properties into configuration and check that the required properties have been set
            final Configuration configuration = new Configuration();
            configuration.load(propertiesFile).check();

            //access security registry
            final SecurityRegistry securityRegistry = Services.securityRegistry();

            //set authentication auth
            securityRegistry.setAuthenticatorProvider(new AuthNProvider(new TokenAuthenticator(configuration)));

            //set authorisation auth
            securityRegistry.setAuthorizerProvider(new AuthZProvider(new TokenAuthorizer(configuration)));

            //set client listener
            Services.eventRegistry().setClientLifecycleEventListener(input -> new HelloWorldListener());

            final ExtensionInformation extensionInformation = extensionStartInput.getExtensionInformation();
            log.info("Started " + extensionInformation.getName() + ":" + extensionInformation.getVersion());


        } catch (Exception e) {
            log.error("Exception thrown at extension start: ", e);
        }

    }

    @Override
    public void extensionStop(final @NotNull ExtensionStopInput extensionStopInput, final @NotNull ExtensionStopOutput extensionStopOutput) {

        final ExtensionInformation extensionInformation = extensionStopInput.getExtensionInformation();
        log.info("Stopped " + extensionInformation.getName() + ":" + extensionInformation.getVersion());

    }

    private class AuthNProvider implements com.hivemq.extension.sdk.api.services.auth.provider.AuthenticatorProvider {

        final @NotNull SimpleAuthenticator authenticator;

        public AuthNProvider(final @NotNull SimpleAuthenticator authenticator) {
            this.authenticator = authenticator;
        }

        @Nullable
        @Override
        public com.hivemq.extension.sdk.api.auth.Authenticator getAuthenticator(final @NotNull AuthenticatorProviderInput authenticatorProviderInput) {
            //return a shareable authenticator which must be thread-safe / stateless
            return authenticator;
        }
    }

    private class AuthZProvider implements AuthorizerProvider {

        final @NotNull Authorizer authorizer;

        public AuthZProvider(final @NotNull Authorizer authorizer) {
            this.authorizer = authorizer;
        }

        @Override
        public @Nullable Authorizer getAuthorizer(@NotNull final AuthorizerProviderInput authorizerProviderInput) {
            //return a shareable authorizer which must be thread-safe / stateless
            return authorizer;
        }

    }

}
