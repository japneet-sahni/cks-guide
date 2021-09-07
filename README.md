# cks-guide
Guide to study for Certified Kubernetes Specialist

## 4 C's of cloud native security
- Cloud
- Cluster
- Container
- Code

# 1. Cluster Setup and Hardening
## 1.1. CIS Benchmarks
- CIS : Center of Internet Security

```sh
# sh ./Assessor-CLI.sh -rd "/var/www/html/" -rp "index" -i -nts
--------------------------------------------------------------------------------------
         Welcome to CIS-CAT Pro Assessor; built on 08/09/2021 02:04 AM
--------------------------------------------------------------------------------------
  This is the Center for Internet Security Configuration Assessment Tool, v4.8.2
          At any time during the selection process, enter 'q!' to exit.
--------------------------------------------------------------------------------------

Verifying application

Configured report output directory to '/var/www/html/'
Configured report naming prefix to 'index.html'
Attempting to load the default sessions.properties, bundled with the application.
Started Assessment 1/1

Loading Benchmarks/Data-Stream Collections
CIS Ubuntu Linux 18.04 LTS Benchmark v2.1.0

Available Benchmarks/Data-Stream Collections:
 1. CIS Controls Assessment Module - Implementation Group 1 for Windows 10 v1.0.3
 2. CIS Controls Assessment Module - Implementation Group 1 for Windows Server v1.0.0
 3. CIS Google Chrome Benchmark v2.0.0
 4. CIS Microsoft Windows 10 Enterprise Release 21H1 Benchmark v1.11.0
 5. CIS Ubuntu Linux 18.04 LTS Benchmark v2.1.0
 > Select Content # (max 5): 5

Selected 'CIS Ubuntu Linux 18.04 LTS Benchmark'

Assessment File CIS_Ubuntu_Linux_18.04_LTS_Benchmark_v2.1.0-xccdf.xml has a valid Signature.
Profiles:
1. Level 1 - Server
2. Level 2 - Server
3. Level 1 - Workstation
4. Level 2 - Workstation
 > Select Profile # (max 4): 1

Selected Profile 'Level 1 - Server'

Obtaining session connection --> Local
Connection established.  
Selected Checklist 'CIS Ubuntu Linux 18.04 LTS Benchmark'
Selected Profile 'Level 1 - Server'
Starting Assessment
----------------------- ASSESSMENT TARGET -----------------------------------
       Hostname: controlplane
        OS Name: linux
     OS Version: 5.4.0-1051-gcp
OS Architecture: x86_64
.
.
.
.
 ***** Assessment Results Summary *****
-----------------------------------------------------------------------------
   Total # of Results: 242
 Total Scored Results: 184
           Total Pass: 96
           Total Fail: 88
          Total Error: 0
        Total Unknown: 0
 Total Not Applicable: 0
    Total Not Checked: 19
   Total Not Selected: 37
  Total Informational: 2
-----------------------------------------------------------------------------
 ***** Assessment Scoring *****
-----------------------------------------------------------------------------
         Score Earned: 96.0
    Maximum Available: 184.0
                Total: 52.17%
-----------------------------------------------------------------------------

- Generating Checklist Results...

Ending Assessment - Date & Time: 09-06-2021 16:39:48
Total Assessment Time: 4 minutes
- Generating Asset Reporting Format.
  - Generating Report Request.
- Generating Data-Stream Collection.
- Data-Stream Collection Generated.
  - Collecting Checklist Results.
  - Combining Results.
  - Saving Results.
- Asset Reporting Format Generated.

 ***** Writing Assessment Results ***** 
 - Reports saving to /var/www/html
 -- index.html-20210906T163948Z.html
Assessment Complete for Checklist: CIS Ubuntu Linux 18.04 LTS Benchmark
-----------------------------------------------------------
Disconnecting Session.
Finished Assessment 1/1
Exiting; Exit Code: 0
```

```sh
# cat /etc/ssh/sshd_config
Change PermitRootLogin to No

# cat /etc/issue
The contents of the /etc/issue file are displayed to users prior to login for local terminals.

# apt install rsyslog
The rsyslog software is a recommended replacement to the original syslogd daemon

# chown root:root /etc/crontab
# chmod og-rwx /etc/crontab
Make sure that root is the user and group owner of the file and that only the owner can access the file.
```

- Kube-bench is tool that checks whether Kubernetes is deployed securely by running the checks documented in the CIS Kubernetes Benchmark. https://github.com/aquasecurity/kube-bench

```sh
# curl -L https://github.com/aquasecurity/kube-bench/releases/download/v0.4.0/kube-bench_0.4.0_linux_amd64.tar.gz -o kube-bench_0.4.0_linux_amd64.tar.gz
# tar -xvf kube-bench_0.4.0_linux_amd64.tar.gz
# ./kube-bench --config-dir `pwd`/cfg --config `pwd`/cfg/config.yaml 
```

## 1.2 Security Primitives
### 1.2.1 Authentication for Human Users

1) Static Password file
- Put password,user,uid,group_name in a password.csv. Mount this file on a volume to be used by api-server
- In API server yml file, put --basic-auth-file=password.csv
- curl -kv https://master-node-ip:6443/api/v1/pods -u "user1:password123"
- This approach is deprecated in Kubernetes version 1.19 and is no longer available in later releases

2) Static Token file
- Put token,user,uid,group_name in a token.csv
- In API server yml file, put --token-auth-file=token.csv
- curl -kv --header "Authorization: Bearer <token> " https://master-node-ip:6443/api/v1/pods

3) Certificates
```sh
# Generate private key for admin user
openssl genrsa -out admin.key 2048

# Generate CSR for admin user. Note the OU.
openssl req -new -key admin.key -subj "/CN=admin/O=system:masters" -out admin.csr

# Sign certificate for admin user using CA servers private key
openssl x509 -req -in admin.csr -CA ca.crt -CAkey ca.key -CAcreateserial  -out admin.crt -days 1000

# Curl using certificates now
curl -kv https://master-node-ip:6443/api/v1/pods --key admin.crt --cert admin.crt --cacert ca.crt

# Or move these details to kubeconfig.yaml
apiversion: v1
kind: Config
clusters:
- cluster:
    certificate-authority: ca.crt
#   certificate-authority-data: encoded ca.crt value    
    server: https://master-node-ip:6443
  name: kubernetes
contexts:
- context:
    cluster: kubernetes
    user: kubernetes-admin
    namespace: default
  name: kubernetes-admin@kubernetes
users:
- name: kubernetes-admin
  user:
    client-certificate: admin.crt
    client-key: admin.key

# Decoding certificates
openssl x509 -in admin.crt -text -noout
```

4) LDAP Groups
- Authenticate using LDAP group. The LDAP group can be given authorization to specific namespaces

### 1.2.2 Authentication for Machine Users
- Create service account
- Create role and role binding for the service account
- Add service account to pod specification (serviceAccountName: abc)
- Default token is mounted on /var/run/secrets/kubernetes.io/serviceaccount/token

### 1.2.3 Certificates API
- All certificate related operations are handled by controller manager
    - CSR-APPROVING
    - CSR-SIGNING
```sh
# To be used by a new admin user,

cat <<EOF | kubectl apply -f -
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: japneet
spec:
  request: $(cat japneet.csr | base64 | tr -d '\n')
  signerName: kubernetes.io/kubelet-serving
  usages:
  - digital signature
  - key encipherment
  - server auth
EOF

# kubectl get csr
# kubectl certificate approve/deny japneet
# kubectl get csr japneet -o jsonpath='{.status.certificate}' | base64 --decode
# Send this to japneet (new admin user)
```

### 1.2.4 Authorization
1) Node
- In order to be authorized by the Node authorizer, kubelets must use a credential that identifies them as being in the system:nodes group, with a username of system:node:<nodeName>. This group and user name format match the identity created for each kubelet as part of kubelet TLS bootstrapping. The value of <nodeName> must match precisely the name of the node as registered by the kubelet. By default, this is the host name as provided by hostname, or overridden via the kubelet option --hostname-override
2) ABAC (Attribute-based)
```sh
# Bob can just read pods in namespace "projectCaribou"
{"apiVersion": "abac.authorization.kubernetes.io/v1beta1", "kind": "Policy", "spec": {"user": "bob", "namespace": "projectCaribou", "resource": "pods", "readonly": true}}

# Restart of API server is required, hence not that useful
```
3) RBAC (Role-based)
4) Webhook (Open policy Agenet - OPA)
- The agent decides whether the user should be permitted or not with the API request.
5) AlwaysAllow (default)
6) AlwaysDeny

- The authorization mode is set in kube-apiserver.yaml
    - --authorization-mode=Node,RBAC,Webhook (If node denies, it goes to RBAC, if RBAC denies, it goes to webhook)

### 1.2.5 RBAC
```sh
# Role
cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: default
  name: developer
rules:
- apiGroups: [""] # "" indicates the core API group
  resources: ["pods"]
  verbs: ["create", "list", "get"]
EOF

# Role Binding
cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: dev-user-binding
  namespace: default
subjects:
- kind: User
  name: dev-user
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: developer
  apiGroup: rbac.authorization.k8s.io
EOF

# kubectl api-resources --namespaced=true
# kubectl api-resources --namespaced=false (cluster scoped resources)
```