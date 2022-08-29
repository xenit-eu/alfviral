/*
 * Copyright 2015 Fernando González (fegor@fegor.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package com.fegorsoft.alfresco.security.antivirus;

import com.fegorsoft.alfresco.model.AlfviralModel;
import java.io.IOException;
import java.io.Serializable;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import org.alfresco.service.cmr.repository.NodeRef;
import org.alfresco.service.cmr.repository.NodeService;
import org.alfresco.service.namespace.QName;
import org.apache.log4j.Logger;

public abstract class VirusScanMode {

    public static final String ScanModeCommand = "COMMAND";
    public static final String ScanModeInStream = "INSTREAM";
    public static final String ScanModeVirusTotal = "VIRUSTOTAL";
    public static final String ScanModeICap = "ICAP";
    private final Logger logger = Logger.getLogger(VirusScanMode.class);
    protected NodeService nodeService;

    public abstract int scan(NodeRef nodeRef) throws IOException;

    public abstract int scan() throws IOException;

    public int rescan() throws IOException {
        return this.scan();
    }

    public abstract int report() throws IOException;

    protected void addScanDate(NodeRef nodeRef) {
        logger.debug("Updating scan date of nodeRef=" + nodeRef);
        if (nodeService == null) {
            logger.warn("NodeService is null. Aborting");
            return;
        }
        Map<QName, Serializable> aspectProperties = new HashMap<>();
        aspectProperties.put(AlfviralModel.PROP_SCANNED_DATE, new Date());
        nodeService.addAspect(nodeRef, AlfviralModel.ASPECT_SCANNED, aspectProperties);
    }
}
