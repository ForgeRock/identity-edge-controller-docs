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

package org.forgerock.iot.config;

import com.hivemq.extension.sdk.api.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

/**
 * Shared configuration for the ForgeRock Example Extension
 */
public class Configuration {
    private static final @NotNull Logger log = LoggerFactory.getLogger(Configuration.class);

    private final static String INTROSPECT_ENDPOINT = "introspect-endpoint";
    private final static String REQUIRED_PROPERTIES[] = {INTROSPECT_ENDPOINT};

    @NotNull
    private final Properties properties;

    public Configuration(){
        this.properties = new Properties();
    }
    public Configuration(Properties properties){
        this.properties = properties;
    }

    /**
     * Load the properties file into the configuration
     * @param propertiesFile
     * @return
     * @throws IOException
     */
    public Configuration load(File propertiesFile) throws IOException {
        log.info("Properties {} {}", propertiesFile.getPath(), propertiesFile.canRead());
        if( !propertiesFile.canRead() ){
            throw new IOException("unable to read " + propertiesFile.getName());
        }

        //load properties
        properties.load(new FileInputStream(propertiesFile));
        return this;
    }

    /**
     * Check that the configuration has all the properties required to run the extension
     * @throws IOException
     */
    public void check() throws IOException {
        for (String key : REQUIRED_PROPERTIES) {
            if( properties.getProperty(key) == null){
                throw new IOException("Missing required property: " + key);
            }

        }
    }

    /**
     * Return the introspection endpoint
     * @return
     */
    public String introspectEndpoint() {
        return properties.getProperty(INTROSPECT_ENDPOINT);
    }
}
