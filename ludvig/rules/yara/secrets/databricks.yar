rule DatabricksApiToken : databricks secret {
    meta:
        description = "Detects a Databricks API token"
        severity = "CRITICAL"
        id = "LS0005"
        
    strings:
        $ = /dapi[a-h0-9]{32}/
    condition:
        all of them
}
