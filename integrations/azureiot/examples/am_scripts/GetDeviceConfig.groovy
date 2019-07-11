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

import org.forgerock.am.iec.identity.IotIdentity

logger.info("Running Edge Device configuration command handler script")

// Pre-defined variables passed to the script
IotIdentity identity = identity as IotIdentity

// If this is not a device then return
if (!identity.isDevice()) {
    response = "{}"
    return
}

response = identity.userConfiguration.orElse("{}")
