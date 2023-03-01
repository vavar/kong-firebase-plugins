# Kong Plugins

## General Installation

all plugins need to declare as configmap and mapping into `deployment` or using `helm charts` method

### 1. Create Config Map

```cli
kubectl create configmap kong-plugin-<plugin-folder> --from-file=<plugin-folder> -n kong -o yaml --dry-run=client | kubectl apply -f -
```

### 2. Edit Helm Charts

```yaml
# values.yaml
plugins:
  configMaps:       # change this to 'secrets' if you created a secret
  - name: kong-plugin-<plugin-folder>
    pluginName: <plugin-folder>
```
  
---

## Kong Remote JWT Auth

### Usage

```cli
kubectl create configmap kong-plugin-remote-jwt-auth --from-file=remote-jwt-auth -n kong -o yaml --dry-run=client | kubectl apply -f -
```

### Plugins Config

```yaml
apiVersion: configuration.konghq.com/v1
kind: KongPlugin
plugin: remote-jwt-auth
metadata:
  name: remote-jwt-auth
config:
  anonymous: true
  authenticated_consumer: authenticated-firebase
  cache_namespace: <cache-namespace>
  cache_type: <local|redis>
  redis_host: <redis_host>
  signing_urls:
    - "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"
  claims_to_verify:
    - name: iss
      allowed_values:
        - "https://securetoken.google.com/google-project-id-here"
    - name: aud
      allowed_values:
        - "google-project-id-here"
```

## References

- [Setting up Custom Plugins](https://docs.konghq.com/kubernetes-ingress-controller/latest/guides/setting-up-custom-plugins/)
