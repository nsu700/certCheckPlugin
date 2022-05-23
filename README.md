# certCheckPlugin

As a oc command plugin to list certificate validity

## How to use
- go build main.go
- mv main /usr/local/bin/oc-cert_check
- oc cert_check

## Example Output
```bash
❯ oc cert-check
!!WARN: The cert pprof-cert of project openshift-operator-lifecycle-manager is expring in 30 days
 2022-05-23 04:30:02 +0000 UTC
❯ oc cert-check -h
Usage of /usr/local/bin/oc-cert_check:
  -days int
    	Number of days certificates will expiring (default 30)
  -kubeconfig string
    	(optional) absolute path to the kubeconfig file (default "/Users/nicksu/.kube/config")
  -nonexpiring
    	Display non-expiring certs or not
❯ oc cert-check -nonexpiring
openshift-apiserver-operator-serving-cert openshift-apiserver-operator 2024-05-20 08:26:45 +0000 UTC
openshift-apiserver-operator-serving-cert openshift-apiserver-operator 2024-07-19 08:26:23 +0000 UTC
etcd-client openshift-apiserver 2032-05-18 08:22:22 +0000 UTC
serving-cert openshift-apiserver 2024-05-20 08:26:32 +0000 UTC
serving-cert openshift-apiserver 2024-07-19 08:26:23 +0000 UTC
serving-cert openshift-authentication-operator 2024-05-20 08:26:37 +0000 UTC
serving-cert openshift-authentication-operator 2024-07-19 08:26:23 +0000 UTC
v4-0-config-system-serving-cert openshift-authentication 2024-05-20 08:26:45 +0000 UTC
v4-0-config-system-serving-cert openshift-authentication 2024-07-19 08:26:23 +0000 UTC
```
