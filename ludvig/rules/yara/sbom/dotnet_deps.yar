rule DotnetDependencyManifest : dotnet sbom {
    meta:
        description = "Detects .NET dependency manifest for use with SBOM"
        type = "SBOM"
    strings:
        $json = { 7b 0a 20 20 } 
        $s0 = "runtimeTarget"
        $s1 = "compilationOptions"
        $s2 = "targets"
        $s3 = "libraries"
    condition:
        ($json at 0) and all of ($s*)
}
