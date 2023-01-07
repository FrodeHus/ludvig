rule databricks_api_token : databricks secret {
    meta:
        description = "Detects a Databricks API token"
    strings:
        $ = /dapi[a-h0-9]{32}/
    condition:
        all of them
}
