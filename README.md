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

## 1.3 Certificates API
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

## 1.4 Authorization
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

## 1.5 RBAC
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
## 1.6 Kubelet Security

```sh
# To know where is kubelet configuration stored | (ps -ef | grep kubelet)
/usr/bin/kubelet --bootstrap-kubeconfig=/etc/kubernetes/bootstrap-kubelet.conf --kubeconfig=/etc/kubernetes/kubelet.conf --config=/var/lib/kubelet/config.yaml --network-plugin=cni --pod-infra-container-image=k8s.gcr.io/pause:3.2
```
- Port 10250 : Serves API that allow full access (anonymous requests) Eg: curl -sk https://localhost:10250/pods/
- Port 10255 : Serves API that allows unauthenticated read-only access. Eg : curl -sk http://localhost:10255/metrics

#### Disable anonymous authentication in 2 ways
  - By deafult, allows anonymous access on port 10250
  - Add --anonymous-auth=false in kubelet.service
  - Add authentication.anonymous.enabled: false in kubelet-config.yaml
```sh
# curl -sk https://localhost:10250/pods/
Unauthorized
```

#### Enabling Authentication using certificates.
- API server acts as a client when connecting to Kubelet which behaves as a server now.
  - In kube-apiserver-config.yml
    - set --kubelet-client-certificate=path/to/kubelet.crt
    - set --kubelet-client-key=path/to/kubelet.key
  - In kubelet-config.yaml
    - Add authentication.x509.clientCAFile: /path/to/ca.crt

#### Enabling authorization in kubelet
- Default authorization mode is alwaysAllow
- Add authorization.mode: Webhook in kubelet-config.yaml (goes to API server to see if the user is able to access kubelet)
```sh
# IF authentication is enabled and authorization mode is set to Webhook (W caps)
# curl -sk https://localhost:10250/pods/
Forbidden (user=system:anonymous, verb=get, resource=nodes, subresource=proxy)
```

#### Disabling read only port 10255
- Add readOnlyPort: 0 to disable this service.

```sh
# Final kubelet configuration file

apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
authentication:
  anonymous:
    enabled: false
  x509:
    clientCAFile: /etc/kubernetes/pki/ca.crt
authorization:
  mode: Webhook
readOnlyPort: 0
```

## 1.7 Kubectl proxy & kubectl port-forward
- Uses your local kubeconfig file to access api server. Now, you don't need to specify api server in your curl command.
```sh
# start kubectl proxy on your local laptop
kubectl proxy
Starting to serve on 127.0.0.1:8001

# curl api server through proxy
curl http://localhost:8001 -k

# access nginx cluster-ip service in default namespace
curl http://localhost:8001/api/v1/namespaces/default/services/nginx/proxy

# forward your request to local port of your laptop to service port
kubectl port-forward service nginx 28080:80 (where 28080 is your local port and 80 is service port)
```

## 1.8 Securing Kubernetes Dashboard

```sh
kubectl apply -f https://raw.githubusercontent.com/kubernetes/dashboard/v2.3.1/aio/deploy/recommended.yaml
kubectl proxy &
http://localhost:8001/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/

# Create SA and give "view" cluster role
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ServiceAccount
metadata:
  name: readonly-user
  namespace: kubernetes-dashboard
EOF

cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: readonly-user-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: view
subjects:
- kind: ServiceAccount
  name: readonly-user
  namespace: kubernetes-dashboard
EOF

kubectl -n kubernetes-dashboard get secret $(kubectl -n kubernetes-dashboard get sa/readonly-user -o jsonpath="{.secrets[0].name}") -o go-template="{{.data.token | base64decode}}"
Paste this token on Dashboard
```

## 1.9 Verifying K8S Platform binaries
```sh
https://github.com/kubernetes/kubernetes/releases/tag/v1.20.0

# curl https://github.com/kubernetes/kubernetes/releases/download/v1.20.0/kubernetes.tar.gz -L -o /opt/kubernetes.tar.gz

# sha512sum kubernetes.tar.gz  
ebfe49552bbda02807034488967b3b62bf9e3e507d56245e298c4c19090387136572c1fca789e772a5e8a19535531d01dcedb61980e42ca7b0461d3864df2c14  kubernetes.tar.gz
```

## 1.10 Upgrade process

```sh
# On master
kubeadm upgrade plan
apt update
kubectl drain master --ignore-daemonsets
apt install kubeadm=1.20.0-00
kubeadm upgrade apply v1.20.0
apt install kubelet=1.20.0-00
systemctl restart kubelet
kubectl uncordon master

# Before moving to worker
kubectl drain node01 --ignore-daemonsets --force
ssh node01

# On worker
apt install kubeadm=1.20.0-00
kubeadm upgrade node
apt install kubelet=1.20.0-00
systemctl restart kubelet
exit

kubectl uncordon node01
```

## 1.11 Network Policies
```sh
# A single to/from entry that specifies both namespaceSelector and podSelector selects particular Pods within particular namespaces. 
# Below example contains two elements in the from array, and allows connections from Pods in the local Namespace with the label role=api, or from any Pod in any namespace with the label project=prod.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: db-policy
  namespace: prod
spec:
  podSelector:
    matchLabels:
      role: db
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - ipBlock:
        cidr: 172.17.0.0/16
        except:
        - 172.17.1.0/24
    - namespaceSelector:
        matchLabels:
          project: prod
    - podSelector:
        matchLabels:
          role: api
    ports:
    - protocol: TCP
      port: 3306
  egress:
  - to:
    - ipBlock:
        cidr: 10.0.0.0/24
    ports:
    - protocol: TCP
      port: 5978
```

## 1.12 Ingress
- Ingress Controllers have extra intelligence built into them to monitor the cluster for ingress resources and configure the underlying nginx configuration when something is chnaged. For doing this, it needs a SA with extra privileges.
- Ingress controller is deployed as a simple deployment. All the configuration is stored in a config map.
- Example : GCE, Nginx ( supported by K8S ), traefik, istio, contour.

```sh
# kubectl create ingress ingress-wear-watch \
--rule="foo.com/wear=wear-service:8080" \
--rule="foo.com/stream=video-service:8080"

# or 

apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
    nginx.ingress.kubernetes.io/ssl-redirect: "false"
  name: ingress-wear-watch
spec:
  rules:
  - host: foo.com
    http:
      paths:
      - backend:
          service:
            name: wear-service
            port:
              number: 8080
        path: /wear
        pathType: Prefix
      - backend:
          service:
            name: video-service
            port:
              number: 8080
        path: /stream
        pathType: Prefix
```

## 1.13 Securing the docker daemon
- If somebody gains access to docker daemon, he/she can delete/read/update/run the existing containers, delete volumes, gain access to host using priveliged container.
- You can start docker daemon using dockerd command.
- By default, docker daemon listens on a unix socket, /var/run/docker.sock

### Securing docker daemon
1) Secure host itself first using SSH authentication.

```sh
# docker daemon config file : /etc/docker/daemon.json
# 2375 : unencrypted traffic, 2376 : encrypted traffic
# Using hosts, anybody can target docker daemon from outside the host (tcp socket). For inside the host, you can access using unix socket.

{
  "hosts": ["tcp://192.168.1.0:2376"],
  "tls": true, # this will encrypt traffic but still any docker client can reach server.
  "tlscert": "/var/docker/server.pem",
  "tlskey": "/var/docker/server.key",
  "tlsverify": true, #this is what enables authentication and clients with proper keys will be able to communicate.
  "tlscacert" "/var/docker/cacert.pem"
}

On docker client now, set below envt variables
# export DOCKER_HOST="tcp://192.168.1.0:2376"
# export DOCKER_TLS=true
# export DOCKER_TLS_VERIFY=true

Create client key using same CA and drop keys along with CA key in ~/.docker (users .docker folder)
docker cli/client will now start communicating in an encrypted manner with the docker server and would need certifcate signed by the same CA.
```