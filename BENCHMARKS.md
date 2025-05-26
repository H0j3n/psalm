## Benchmarks

## Prompt

```
You are Wordpress security expert. By using all MCP and your idea, please look into XXXX wordpress plugins where the is a vulnerable codes with CVE-XXXXX and can be triggered using command "curl XXXX" but the psalm can't identify the vulnerabilities. Improvise psalm and make wordpress plugins easily can be detect with LFI vulnerablities.
```

### Local File Inclusion

| Plugin Name | Version | CVE | Download Link | Status |
|-------------|---------|-----|----------------|---------|
| **Web Directory Free** | < 1.7.0   | CVE-2024-3673 | `https://downloads.wordpress.org/plugin/web-directory-free.1.7.2.zip`|  ✅ |
| **Geo My Wordpress**   | < 4.5.0.2 | CVE-2024-3673 | `https://downloads.wordpress.org/plugin/geo-my-wp.4.5.0.1.zip`|  ✅ |
| **Essential Blocks**   | < 4.4.3   | CVE-2023-6623 | `https://downloads.wordpress.org/plugin/essential-blocks.4.4.2.zip` |  ✅ |
| **Kubio AI Page Builder** | ≤ 2.5.1 | CVE-2025-2294 | `https://downloads.wordpress.org/plugin/kubio.2.5.1.zip` | ✅ |
| **Axeptio Plugin** | ≤ 2.5.1 | CVE-2024-54270 | `https://downloads.wordpress.org/plugin/axeptio-sdk-integration.2.5.1.zip` | ✅ |