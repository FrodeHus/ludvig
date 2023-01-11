rule DatabricksAPIToken : databricks secret {
    meta:
        description = "Detects a Databricks API token"
        severity = "CRITICAL"
        
    strings:
        $ = /dapi[a-h0-9]{32}/
    condition:
        all of them
}
