# cks-guide
Guide to study for Certified Kubernetes Specialist

# K8S Cluster Setup
```sh
# cks-master
sudo -i
bash <(curl -s https://raw.githubusercontent.com/killer-sh/cks-course-environment/master/cluster-setup/latest/install_master.sh)
# cks-worker
sudo -i
bash <(curl -s https://raw.githubusercontent.com/killer-sh/cks-course-environment/master/cluster-setup/latest/install_worker.sh)
# run the printed kubeadm-join-command from the master on the worker
# kubectl get nodes -o wide
NAME            STATUS   ROLES                  AGE     VERSION 
k8s-master-01   Ready    control-plane,master   2m38s   v1.21.0
k8s-worker-01   Ready    <none>                 40s     v1.21.0

# k get pods -A
NAMESPACE     NAME                                    READY   STATUS    RESTARTS   AGE
kube-system   coredns-558bd4d5db-6gczq                1/1     Running   0          66m
kube-system   coredns-558bd4d5db-v2bhz                1/1     Running   0          66m
kube-system   etcd-k8s-master-01                      1/1     Running   0          67m
kube-system   kube-apiserver-k8s-master-01            1/1     Running   0          67m
kube-system   kube-controller-manager-k8s-master-01   1/1     Running   0          67m
kube-system   kube-proxy-8fwfb                        1/1     Running   0          66m
kube-system   kube-proxy-rk7kg                        1/1     Running   0          65m
kube-system   kube-scheduler-k8s-master-01            1/1     Running   0          67m
kube-system   weave-net-dtjk5                         2/2     Running   1          65m
kube-system   weave-net-shfxd                         2/2     Running   1          66m
```

## 4 C's of cloud native security
- Cloud
- Cluster
- Container
- Code

# 1. Cluster Setup and Hardening
## 1.1. CIS Benchmarks
- CIS : Center of Internet Security

```sh
# sh ./Assessor-CLI.sh -rd "/var/www/html/" -rp "index" -i -nts (nts means no timestamp in the file name)
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
 -- index.html
Assessment Complete for Checklist: CIS Ubuntu Linux 18.04 LTS Benchmark
-----------------------------------------------------------
Disconnecting Session.
Finished Assessment 1/1
Exiting; Exit Code: 0
```

```sh
# cat /etc/ssh/sshd_config 
PermitRootLogin no
PasswordAuthentication no

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
- curl -kv --header "Authorization: Bearer token_value " https://master-node-ip:6443/api/v1/pods

3) Certificates
```sh
# Generate CA key
openssl genrsa -out ca.key 2048
# Generate CA CSR
openssl req -new -key ca.key -subj "/CN=kubernetes-ca" -out ca.csr
# Generate CA CRT
openssl x509 -req -in ca.csr -out ca.crt
# Generate private key for admin user
openssl genrsa -out admin.key 2048
# Generate CSR for admin user. Note the OU.
openssl req -new -key admin.key -subj "/CN=admin/O=system:masters" -out admin.csr
# Sign certificate for admin user using CA servers private key
openssl x509 -req -in admin.csr -out admin.crt -CA ca.crt -CAkey ca.key -CAcreateserial -days 1000

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
# openssl genrsa 2048 -out japneet.key
# openssl req -new -key japneet.key -subj "/CN=japneet" -out japneet.csr
# Create CertificateSigningRequest

cat <<EOF | kubectl apply -f -
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: japneet
spec:
  request: $(cat japneet.csr | base64 -w 0)
  signerName: kubernetes.io/kubelet-serving
  usages:
  - digital signature
  - key encipherment
  - server auth
EOF

# kubectl get csr
# kubectl certificate approve/deny japneet
# kubectl get csr japneet -o jsonpath='{.status.certificate}' | base64 --decode > japneet.crt
# Send this to japneet (new admin user)
# k config set-credentials japneet --client-key=japneet.key --client-certificate=japneet.crt --embed-certs
# k config set-context japneet --user=japneet --cluster=kubernetes
# k config use-context japneet
# k auth can-i delete deployments -A
yes or no depending on RBAC permissions.
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
  - By default, allows anonymous access on port 10250
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
# If authentication is enabled and authorization mode is set to Webhook (W caps)
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

# or make following changes to deplo and svc
# deploy
- Remove --auto-generate-certificates
- Add --insecure-port=9090
- Change liveliness probe and container port to 9090
# svc
- Make it NodePort
- Change target and port to 9090

# Final changes
containers:
      - args:
        - --insecure-port=9090
        - --authentication-mode=token
        # enable-insecure-login does not say that you will be allowed to log in over HTTP. It only says that when Dashboard is not served over HTTPS the login screen will still be enabled. Sign-in will always be restricted to HTTP(S) + localhost or HTTPS and external domains as described in the error message that you see on the login screen.
        - --enable-insecure-login=true
        - --namespace=kubernetes-dashboard
        image: kubernetesui/dashboard:v2.3.1

# The Kubernetes dashboard will be available on NodePort. But you will still get permission issues with service account kubernetes-dashboard. So bind below clusterrole to the service account. If you create a rolebinding instead of clusterolebinding, then you kubernetes-dashboard SA will get access to only kubernetes-dashboard namespace.

# Give "view" cluster role permissions to already existing kubernetes-dashboard service account

cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: kubernetes-dashboard-sa-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: view
subjects:
- kind: ServiceAccount
  name: kubernetes-dashboard
  namespace: kubernetes-dashboard
EOF

kubectl -n kubernetes-dashboard get secret $(kubectl -n kubernetes-dashboard get sa/kubernetes-dashboard -o jsonpath="{.secrets[0].name}") -o go-template="{{.data.token | base64decode}}"
Paste this token on Dashboard
```

## 1.9 Verifying K8S Platform binaries
```sh
https://github.com/kubernetes/kubernetes/releases/tag/v1.20.0

# curl https://github.com/kubernetes/kubernetes/releases/download/v1.20.0/kubernetes.tar.gz -L -o /opt/kubernetes.tar.gz

# sha512sum kubernetes.tar.gz  
ebfe49552bbda02807034488967b3b62bf9e3e507d56245e298c4c19090387136572c1fca789e772a5e8a19535531d01dcedb61980e42ca7b0461d3864df2c14  kubernetes.tar.gz

# Comparing specific components of K8S 
kubeadm upgrade plan (get the version)
cd /tmp
wget https://dl.k8s.io/v1.21.0/kubernetes-server-linux-amd64.tar.gz
tar xzf kubernetes-server-linux-amd64.tar.gz
sha512sum kubernetes/server/bin/kube-apiserver > compare
docker ps | grep apiserver
docker cp 1bce2ce51d4f:/ apiserver-fs
sha512sum apiserver-fs/usr/local/bin/kube-apiserver >> compare
vi compare (Removing file names)
cat compare | uniq
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

# If you apply default deny policy, make sure you add egress rules for DNS port 53 with tcp/udp protocols. This would be required to work with K8S services.
# For using namespaceSelector, make sure you add labels to the namespace.
```

## 1.12 Ingress

- Ingress Controllers have extra intelligence built into them to monitor the cluster (using ValidatingWebhookConfiguration) for ingress resources and configure the underlying nginx configuration when something is changed. For doing this, it needs a SA with extra privileges.
- Ingress controller is deployed as a simple deployment. All the configuration is stored in a config map.
- Example : GCE, Nginx ( both of them supported by K8S ), traefik, istio, contour.

### 1.12.1 Configuring Ingress
```sh
# Create Ingress Controller
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.0.0/deploy/static/provider/baremetal/deploy.yaml

# kubectl describe validatingwebhookconfiguration ingress-nginx-admission
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
### 1.12.2 Securing Ingress
- Ingress service is exposed both on 80 and 443 ports
- To use https, we need to create a TLS secret and add TLS section in Ingress spec
- Make sure to now add host in the rules section because the tls certs will be bounded only to this host.

```sh
# k get svc -n ingress-nginx
NAME                                 TYPE        CLUSTER-IP       EXTERNAL-IP   PORT(S)                      AGE
ingress-nginx-controller             NodePort    10.108.191.58    <none>        80:32436/TCP,443:30852/TCP   23m

# kubectl create secret tls ingress-tls-secret \
  --cert=path/to/cert/file \
  --key=path/to/key/file

# Edit Ingress configuration to 
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
  name: tls-example-ingress
spec:
  tls:
  - hosts:
      - https-example.foo.com
    secretName: ingress-tls-secret 
  rules:
  - host: https-example.foo.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: service1
            port:
              number: 80
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

## 1.14 Securing Node Metadata service
- Any pod can access metadat service of the VM using curl command. 
- Restrict access to metadata service using Network policies. Metadata service for GCP runs on 169.254.169.254
- Deny access to this IP for all pods. Then allow access to this IP for only seleted pods

```sh
# all pods in namespace cannot access metadata endpoint
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: cloud-metadata-deny
  namespace: default
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - to:
    - ipBlock:
        cidr: 0.0.0.0/0
        except:
        - 169.254.169.254/32

# kubectl exec -it nginx -- sh
# curl -H 'Metadata-Flavor: Google' 'http://metadata.google.internal/computeMetadata/v1/instance/name'
........

# only pods with label are allowed to access metadata endpoint
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: cloud-metadata-allow
  namespace: default
spec:
  podSelector:
    matchLabels:
      role: metadata-accessor
  policyTypes:
  - Egress
  egress:
  - to:
    - ipBlock:
        cidr: 169.254.169.254/32

# k label pod/nginx role=metadata-accessor
pod/nginx labeled

# kubectl exec -it nginx -- sh
# curl -H 'Metadata-Flavor: Google' 'http://metadata.google.internal/computeMetadata/v1/instance/name'
k8s-worker-01
```

## 1.15 Kube-Apiserver Security
- --anonymous-auth=false (This would bring API server to unstable state as liveliness probes will fail)
- --insecure-port=8080 (should be 0-disabled). This will bypass authentication and authorization on HTTP mode. This has now been deprecated as part of 1.20. (curl http://localhost:8080/)

## 1.16 ETCD Security
- By default there is no encryption of secrets in ETCD

```sh
# k create secret generic mysecret --from-literal=user=admin
secret/mysecret created
# ETCDCTL_API=3 etcdctl endpoint health
127.0.0.1:2379 is unhealthy: failed to connect: context deadline exceeded
Error:  unhealthy cluster
# cat /etc/kubernetes/manifests/kube-apiserver.yaml | grep -i etcd
    - --etcd-cafile=/etc/kubernetes/pki/etcd/ca.crt
    - --etcd-certfile=/etc/kubernetes/pki/apiserver-etcd-client.crt
    - --etcd-keyfile=/etc/kubernetes/pki/apiserver-etcd-client.key
    - --etcd-servers=https://127.0.0.1:2379
# ETCDCTL_API=3 etcdctl --cert /etc/kubernetes/pki/apiserver-etcd-client.crt --key /etc/kubernetes/pki/apiserver-etcd-client.key --cacert /etc/kubernetes/pki/etcd/ca.crt endpoint health
127.0.0.1:2379 is healthy: successfully committed proposal: took = 1.756006ms
# ETCDCTL_API=3 etcdctl --cert /etc/kubernetes/pki/apiserver-etcd-client.crt --key /etc/kubernetes/pki/apiserver-etcd-client.key --cacert /etc/kubernetes/pki/etcd/ca.crt get /registry/secrets/default/mysecret

mysecret ?default"*$c7cb9d6f-3fa7-4b89-84ec-4639699aa2e92񵞊z�_
kubectl-createUpdate  ?v1񵞊FieldsV1:-
+{"f:data":{".":{},"f:user":{}},"f:type":{}}
user  admin?Opaque ?"
```

## 1.16.1 Encrypting Secret Data at Rest (ETCD)
- The kube-apiserver process accepts an argument --encryption-provider-config that controls how API data is encrypted in etcd.
- The providers array is an ordered list of the possible encryption providers.
- The first provider in the list is used to encrypt resources going into storage. When reading resources from storage each provider that matches the stored data attempts to decrypt the data in order.

- Steps

```sh
# 1) Create base64 encoded secret
head -c 32 /dev/urandom | base64

# 2) Create EncryptionConfiguration file and copy the encoded secret. Will place the file in /etc/kubernetes/pki/etcd folder as this is already mounted on api-server
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
    - secrets
    providers:
    - aescbc:
        keys:
        - name: key1
          secret: <base 64 encoded secret>
    # Identity provider : Resources written as-is without encryption. When set as the first provider, the resource will be decrypted as new values are written.
    - identity: {}

# 3) Add --encryption-provider-config=/etc/kubernetes/pki/etcd/ec.yml

# 4) After this step, any new secret created would be encrypted at rest.
# kubectl create secret generic secure-secret --from-literal=user=admin
secret/secure-secret created
# ETCDCTL_API=3 etcdctl --cert /etc/kubernetes/pki/apiserver-etcd-client.crt --key /etc/kubernetes/pki/apiserver-etcd-client.key --cacert /etc/kubernetes/pki/etcd/ca.crt get /registry/secrets/default/secure-secret
k8s:enc:aescbc:v1:key1:��zFRR���2(�w�&u?�zK����    Y@�z����MV��

# 5) Replace all secrets using this new encryption
kubectl get secrets --all-namespaces -o json | kubectl replace -f -
# 6) Remove identity provider from encryption configuration.
```

# 2. Cluster Hardening
## 2.1 Limit Node Access
```sh
adduser japneet
adduser japneet --home /opt/japneet --shell /bin/bash
# japneet is the primary group for user japneet
# To add japneet to admin group
usermod japneet -G admin
cat /etc/group | grep admin
# admin:x:1000:rob,japneet
id japneet
# uid=1002(japneet) gid=1002(japneet) groups=1002(japneet),1000(admin)
usermod -s /usr/sbin/nologin japneet
# To remove japneet from admin group
deluser japneet admin
deluser japneet (remove both user and group japneet)
```
## 2.2 SSH Access
```sh
# ssh node01
# adduser japneet
# exit
# ssh-copy-id -i ~/.ssh/id_rsa.pub japneet@node01
Enter japneet password to copy public key to /home/japneet/.ssh/authorized_keys
# ssh jim@node01
```
```sh
vi /etc/sudoers
japneet ALL=(ALL:ALL) ALL
%japneet ALL=(ALL:ALL) ALL (if japneet is a group, prefix % before group name)

# Now japneet will have sudo privileges but he still needs to enter his password
japneet@node01:~$ sudo su
[sudo] password for japneet: 
root@node01:~#

# If japneet wants to run sudo command without password being asked, edit sudoers file with
japneet ALL=(ALL) NOPASSWD:ALL

japneet@node01:~$ sudo su
root@node01:~#
```
```sh
# cat /etc/ssh/sshd_config 
PermitRootLogin no
PasswordAuthentication no

#systemctl restart sshd
```

## 2.3 Restrict Kernel Modules
```sh
# To blacklist modules
vi /etc/modprobe.d/blacklist.conf
blacklist sctp
blacklist dccp

# shutdowm -r now
# To list all kernel modules
lsmod 
```

```sh
# List all installed packages
apt list --installed
# List all systemd services
systemctl list-units --type=service
```

## 2.4 Uncomplicated Firewall (UFW)
```sh
ufw status
ufw default allow outgoing
ufw default deny incoming
ufw allow from <ip> to any port 22 proto tcp
ufw allow 6000:6007/tcp
ufw deny 8080
ufw show added
ufw enable
ufw status numbered
ufw delete <line number>
ufw delete deny 8080
ufw reset
ufw disable
```
## 2.5 Restricting sys calls

```sh
# strace is the utility to trace system calls between user space and kernel space (The applications/processes in user space talk to hardawre through linux kernel which is in kernel space)
starce -c touch /tmp/dummy.txt

# Examples of system calls (https://man7.org/linux/man-pages/man2/syscalls.2.html)
open(),read(),write(),close(),wait(),execve(),sleep(),clock_settime(),mkdir()

# Aquasec tracee is a tool to trace system calls
docker run --name tracee --rm --privileged -v /lib/modules/:/lib/modules/:ro -v /usr/src:/usr/src:ro -v /tmp/tracee:/tmp/tracee -it aquasec/tracee:0.4.0 --trace container=new

# Restricting system calls using seccomp (introduced in 2.6.12 of linux kernel version)
# seccomp stands for secure computing mode
cat /boot/config-$(uname -r) | grep -i seccomp
CONFIG_SECCOMP=y


# grep process/pid running in docker container (by default main process runs with pid=1)
# grep Seccomp /proc/<pid>/status
Seccomp: 2
# By default, docker runs with filtered eccomp mode (above output)

# There are 3 Seccomp modes:
0: Disabled, 1: Strict, 2: Filtered

# You can configure either whitelist or blacklist policies to allow/deny different system calls.
# Docker’s default seccomp profile is an allowlist which specifies the calls that are allowed. 
# To run a docker container without default seccomp profile, add 
--security-opt seccomp=unconfined
```

```sh
# Restricting seccomp in Kubernetes

# amicontained is a container introspection tool that lets you find out what container runtime is being used as well as the features available.
docker run --rm -it r.j3ss.co/amicontained
# seccomp will be in filtered status and will block around ~64 sys calls
#
# or
kubectl run amicontained --image r.j3ss.co/amicontained amicontained -- amicontained
# seccomp is in disabled mode by default in kubernetes 1.20 version (seccomp=unconfined). You will see less blocked sys calls.

# If seccomp is enabled (like below), the kubelet will use the RuntimeDefault seccomp profile by default, which is defined by the container runtime, instead of using the Unconfined (seccomp disabled) mode.

apiVersion: v1
kind: Pod
metadata:
  name: audit-pod
  labels:
    app: audit-pod
spec:
  securityContext:
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: amicontained
    image: r.j3ss.co/amicontained
    args:
    - amicontained
    securityContext:
      allowPrivilegeEscalation: false

# It is not possible to apply a seccomp profile to a container running with privileged: true set in the container's securityContext. Privileged containers always run as Unconfined.

# To apply custom seccomp profile instead of dafault container runtime's profile
apiVersion: v1
kind: Pod
metadata:
  name: fine-pod
  labels:
    app: fine-pod
spec:
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: profiles/whitelist.json
      # Path is relative to /var/lib/kubelet/seccomp/
  containers:
  - name: test-container
    image: hashicorp/http-echo:0.2.3
    args:
    - "-text=just made some syscalls!"
    securityContext:
      allowPrivilegeEscalation: false
```

## 2.6 Restricting through AppArmor
- AppArmor is a Linux kernel security module that supplements the standard Linux user and group based permissions to confine programs to a limited set of resources.
- AppArmor is applied to a Pod by specifying an AppArmor profile that each container should be run with. If any of the specified profiles is not already loaded in the kernel, the Kubelet will reject the Pod. You can view which profiles are loaded on a node by checking the /sys/kernel/security/apparmor/profiles file
- Apparmor has two types of profile modes, enforcement and complain. Profiles in enforcement mode enforce that profiles rules and report violation attempts in syslog or auditd. Profiles in complain mode dont enforce any profile rules, just log violation attempts.
```sh

# https://askubuntu.com/questions/236381/what-is-apparmor

# cat /sys/module/apparmor/parameters/enabled
Y

# Installing apparmour
apt install -y apparmor-utils

# Profiles path
ls -la /etc/apparmor.d/

# To check status of apparmor
apparmor_status/aa-status

# To a add a new apparmor profile
# The actual profile name is mentioned in the file and should preferrably match the fie name.
apparmor_parser /etc/apparmor.d/profile.name

# To reload/replace a profile
apparmor_parser -r /etc/apparmor.d/usr.sbin.nginx

# Annotation to be added to the pod for enabling apparmor profile.
container.apparmor.security.beta.kubernetes.io/<container_name>: <profile_ref>

- <container_name> is the name of the container to apply the profile to
- <profile_ref> specifies the profile to apply. The profile_ref can be one of:
  - runtime/default to apply the runtimes default profile
  - localhost/<profile_name> to apply the profile loaded on the host with the name <profile_name>
  - unconfined to indicate that no profiles will be loaded
```

# 3. Minimizing Microservices Vulnerabilities
## 3.1 Linux Capabilities and Security Contexts
- Even after disabling seccomp using --security-opt seccomp=unconfined in a docker container, you will notice that still you won't be able to run some commands like changing systime. This is because of another security gate which is called linux capabilities
- Before 2.2, we only had the binary system of privileged (uid=0) and non-privileged processes; either your process could do everything or it was restricted to the subset of a standard user. Certain executables like ping, which needed to be run by standard users, also make privileged kernel calls
- After kernel version 2.2, with introduction of capabilities, all the possible privileged kernel calls were split up into groups of related functionality, then we can assign processes only to the subset they need.

```sh
# To get capabilities of an executable
getcap /usr/bin/touch

# To get capabilities of a process
getpcaps <pid>

# Security context can be added both at pod and container level (container overrides pod)
# Capabilities can only be added at pod level.
apiVersion: v1
kind: Pod
metadata:
  name: multi-pod
spec:
  securityContext:
    runAsUser: 1001
  containers:
  -  image: ubuntu
     name: web
     command: ["sleep", "5000"]
     securityContext:
      runAsUser: 1002
      capabilities:
        add: 
          - SYS_TIME
#       drop: 
#         - SYS_TIME
  -  image: ubuntu
     name: sidecar
     command: ["sleep", "5000"]
```

## 3.2 Admission Controllers
- You want to control
  - Not public registry can be used
  - Latest tag cannot be used
  - Labels should be specified in metadata
  - Only add certain capabilities
- These things cannot be controleld through RBAC authorization, hence admission controllers came into picture
- kubectl -> Authentication -> Authorization -> Admission Controller -> Create Pod

- Default Controllers
  - AlwaysPullImages
  - NamespaceExists (checks if the namespace exist or not) - deprecated
  - NamespaceAutoProvision (creates NS if non-existent) - deprecated
  - NaespaceLifeCycle - will make sure that requests to a non-existent namespace is rejected and that the default namespaces such as default, kube-system and kube-public cannot be deleted.
  - DefaultStorageClass
  - NodeRestriction - This admission controller limits the Node and Pod objects a kubelet can modify. Such kubelets will only be allowed to modify their own Node API object, and only modify Pod API objects that are bound to their node. Prevents kubelets from adding/removing/updating labels with a node-restriction.kubernetes.io/ prefix. This label prefix is reserved for administrators to label their Node objects for workload isolation purposes

- 2 types of admission controllers:
  - Validating (validates request) Eg : NamespaceExists
  - mutating (adds something to request) Eg : DefaultStorageClass,NamespaceAutoProvision
- Mutating controller is invoked first followed by validating
```sh
# To check what all admission plugins are enabled/disabled
kubectl exec <api-server-pod> -n kube-system -- kube-apiserver -h | grep admission-plugins
# or
ps -ef | grep kube-apiserver | grep admission-plugins
```

- Steps for admission controllers
  - Deploy webhook server (python/go application with validate and mutate functions) as an external service or as a K8S deployment & service.
  - Configure admission webhook in k8s with kind: ValidatingWebhookConfiguration or MutatingWebhookConfiguration
  - Whenever a request is made, kind: AdmissionReview object (json) is sent to the controller for validation

```sh
apiVersion: admissionregistration.k8s.io/v1beta1
kind: MutatingWebhookConfiguration
metadata:
  name: demo-webhook
webhooks:
  - name: webhook-server.webhook-demo.svc
    clientConfig:
      service:
        name: webhook-server
        namespace: webhook-demo
        path: "/mutate"
      caBundle: <ca bundle>
    rules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: [ "CREATE" ]
        resources: ["pods"]
```

## 3.3 Pod Security policies (PSP)
- By default, PodSecurityPolicy is disabled as an admission controller.
- It needs to be enabed in --enable-admission-plugins
- PSP can act as both validating as well as mutating admission controller.
```sh
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: example-psp
spec:
  privileged: false # Don't allow privileged pods( which gain access to host)!
  # The empty/no set of capabilities means that no additional capabilities may be added
  seLinux:
    rule: RunAsAny
  runAsUser:
    rule: RunAsAny
  supplementalGroups:
    rule: RunAsAny
  fsGroup:
    rule: RunAsAny
  AllowedCapabilities:
  DefaultAddCapabilities:
  RequiredDropCapabilities: 
  # list of allowed volume types
  volumes:
  - configMap
  - secret
  - emptyDir
  - hostPath
```

- PodSecurityPolicies are enforced by enabling the admission controller, but doing so without authorizing any policies will prevent any pods from being created in the cluster.
- When a PodSecurityPolicy resource is created, it does nothing. In order to use it, the requesting user or target pod's service account (default sa in most cases) must be authorized to use the policy, by allowing the use verb on the policy.

```sh
# PSP role
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: psp-role
rules:
- apiGroups: ['policy']
  resources: ['podsecuritypolicies']
  verbs:     ['use']

# PSP role-binding
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: psp-role-binding
roleRef:
  kind: ClusterRole
  name: psp-role
  apiGroup: rbac.authorization.k8s.io
subjects:
# Authorize all service accounts in a namespace (recommended):
- kind: Group
  apiGroup: rbac.authorization.k8s.io
  name: system:serviceaccounts:<authorized namespace>
# Authorize specific service accounts (not recommended):
- kind: ServiceAccount
  name: <authorized service account name>
  namespace: <authorized pod namespace>
```

## 3.4 Open Policy Agent (OPA)

### 3.4.1 OPA in general

- https://www.youtube.com/watch?v=4mBJSIhs2xQ
- https://www.openpolicyagent.org/docs/latest/
- OPA provides a high-level declarative language that lets you specify policy as code and simple APIs to offload policy decision-making from your software. You can use OPA to enforce policies in microservices, Kubernetes, CI/CD pipelines, API gateways, and more.
- OPA decouples policy decision-making from policy enforcement. When your software needs to make policy decisions it queries OPA and supplies structured data (e.g., JSON) as input. 
- OPA policies are expressed in a high-level declarative language called Rego. Rego (pronounced “ray-go”) is purpose-built for expressing policies over complex hierarchical data structures.
- By default runs on 8181 port as http server.
- The REGO Playground - https://play.openpolicyagent.org/ 

```sh
# Test OPA policy
./opa test sample.rego

# Load sample policy to OPA
curl -X PUT --data-binary @sample.rego http://localhost:8181/v1/policies/samplepolicy
```

### 3.4.2 OPA in K8S

- Instead of creating your own validating admission controller, you can assign this to OPA.
- Deploy OPA as K8S deployment and service in a separate namespace.
- Just set url(if external)/service (if in K8S) of OPA in clientconfig section of ValidatingWebhookConfiguration
- Validating webhook will only send request (AdmissionReview Request) for a new resource
- *But what if you want the new request to be compared/validated with data of existing resources which are not part of the current admissionreview request?*
- In this, we leverage *kube-mgmt* service which runs as a side car with OPA which
  - Replicates/Caches all details about all resources of existing cluster in OPA. This info can be used using *import data.kubernetes.<resource>
  - Helps in loading policies in OPA through a config map with an annotation as *openpolicyagent.org/policy=rego*

- *So this is Gatekeeper v1.0 - Uses OPA as the admission controller with the kube-mgmt sidecar enforcing configmap-based policies. It provides validating and mutating admission control.*

```sh
# Example of REGO policy for pods
# vi untrusted-registry.rego
package kubernetes.admission
import data.kubernetes.pods

deny[msg] {
  input.request.kind.kind == "Pod"
  image := input.request.object.spec.containers[_].image
  not startswith(image, "hooli.com/")
  msg := sprintf("image '%v' comes from untrusted registry", [image])
}

# By default kube-mgmt will try to load policies out of configmaps in the opa namespace OR configmaps in other namespaces labelled openpolicyagent.org/policy=rego.
kubectl create configmap untrusted-registry --from-file=untrusted-registry.rego -n opa
```

### 3.4.3 OPA gatekeeper

- During the validation process, Gatekeeper acts as a bridge between the API server and OPA. The API server will enforce all policies executed by OPA.
- When you install OPA gatekeeper, you will get below CRD's
```sh
# k get crd
NAME                                                 CREATED AT
configs.config.gatekeeper.sh                         2021-09-20T11:40:26Z
constraintpodstatuses.status.gatekeeper.sh           2021-09-20T11:40:26Z
constrainttemplatepodstatuses.status.gatekeeper.sh   2021-09-20T11:40:26Z
constrainttemplates.templates.gatekeeper.sh          2021-09-20T11:40:26Z
```
- constrainttemplates CRD allows people to declare new Constraints (new CRD)
- A Constraint is a declaration that its author wants a system to meet a given set of requirements. Each Constraint is written with Rego. All Constraints are evaluated as a logical AND. If one Constraint is not satisfied, then the whole request is rejected.

```sh
# Constraint template CRD that requires certain labels to be present on an arbitrary object.
apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
metadata:
  name: k8srequiredlabels
spec:
  crd:
    spec:
      names:
        kind: K8sRequiredLabels
      validation:
        # Schema for the `parameters` field
        openAPIV3Schema:
          properties:
            labels:
              type: array
              items: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8srequiredlabels
        violation[{"msg": msg, "details": {"missing_labels": missing}}] {
          provided := {label | input.review.object.metadata.labels[label]}
          required := {label | label := input.parameters.labels[_]}
          missing := required - provided
          count(missing) > 0
          msg := sprintf("you must provide labels: %v", [missing])
        }  
  
# k get crd
NAME                                                 CREATED AT
configs.config.gatekeeper.sh                         2021-09-20T11:40:26Z
constraintpodstatuses.status.gatekeeper.sh           2021-09-20T11:40:26Z
constrainttemplatepodstatuses.status.gatekeeper.sh   2021-09-20T11:40:26Z
constrainttemplates.templates.gatekeeper.sh          2021-09-20T11:40:26Z
k8srequiredlabels.constraints.gatekeeper.sh          2021-09-20T11:50:52Z

# A Constraint CRD that requires the label hr to be present on all namespaces.
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredLabels
metadata:
  name: ns-must-have-label-hr
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Namespace"]
  parameters:
    labels: ["hr"]

# kubectl create ns blue
Error from server ([ns-must-have-label-hr] you must provide labels: {"hr"}): admission webhook "validation.gatekeeper.sh" denied the request: [ns-must-have-label-hr] you must provide labels: {"hr"}

# kubectl describe k8srequiredlabels ns-must-have-label-hr
# Gatekeeper stores audit results as violations listed in the status field of the relevant Constraint.
Total Violations:  5
  Violations:
    Enforcement Action:  deny
    Kind:                Namespace
    Message:             you must provide labels: {"hr"}
    Name:                default
    Enforcement Action:  deny
    Kind:                Namespace
    Message:             you must provide labels: {"hr"}
    Name:                gatekeeper-system
    Enforcement Action:  deny
    Kind:                Namespace
    Message:             you must provide labels: {"hr"}
    Name:                kube-node-lease
    Enforcement Action:  deny
    Kind:                Namespace
    Message:             you must provide labels: {"hr"}
    Name:                kube-public
    Enforcement Action:  deny
    Kind:                Namespace
    Message:             you must provide labels: {"hr"}
    Name:                kube-system

# Alternative of kube-mgmt service in gatekeeper now is to create a sync config resource with the resources to be replicated into OPA. For example, the below configuration replicates all namespace and pod resources to OPA.

apiVersion: config.gatekeeper.sh/v1alpha1
kind: Config
metadata:
  name: config
  namespace: "gatekeeper-system"
spec:
  sync:
    syncOnly:
      - group: ""
        version: "v1"
        kind: "Namespace"
      - group: ""
        version: "v1"
        kind: "Pod"
```
## 3.5 Container Sandboxing
- namespaces : Restrict what processes can see like other processes, users, file-systems
- cgroups: Restrict the resource usage of processes like RAM, disk, CPU.
```sh
# c1 and c2 will run in different process namespaces
docker run --name c1 -d ubuntu sh -c 'sleep 1d'
docker run --name c2 -d ubuntu sh -c 'sleep 2d'

# c3 will run in same process namespace as c1. You can see both processes in c1 and c3.
docker run --name c3 --pid=container:c1 -d ubuntu sh -c 'sleep 3d'
```
### 3.5.1 gVisor
- https://gvisor.dev/docs/
- In docker, every container shares the same host OS kernel unlike VM's which have their own kernels.
- While using a single, shared kernel allows for efficiency and performance gains, it also means that container escape is possible with a single vulnerability.
- gvisor is an application kernel that provides an additional layer of isolation between running applications and the host operating system.
- It limits the host kernel surface accessible to the application while still giving the application access to all the features it expects (makes limited syscalls).
- However, this comes at the price of reduced application compatibility and higher per-system call overhead.
- gvisor uses runsc as container runtime. (docker uses runC as container runtime)

```sh
# Installing gvisor on worker node. This will install containerd which supports both runc and runsc container runtime interfaces
bash <(curl -s https://raw.githubusercontent.com/killer-sh/cks-course-environment/master/course-content/microservice-vulnerabilities/container-runtimes/gvisor/install_gvisor.sh)

```

### 3.5.2 Kata Containers
- Creates a light weight VM for each container, thus every container gets it's own guest VM kernel, hence limiting sys calls to host OS kernel.
- It will be almost like nested virtualization (VM inside a VM) which is not supported by lot of CSPs (except GCP but it has to be done manually)
- Performance here can be a concern.
- Uses kata as conatiner runtime

### 3.5.3 Runtime Classes
```sh
# To create a runtime class
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: gvisor/kata
handler: runsc/kata  # The name of the corresponding CRI configuration

# To use this, add in pod spec
runtimeClassName: gvisor/kata
```

# 4. Supply Chain Security
## 4.1 Minimize BAse Image footprint
- The top most image is built *FROM scratch*
- *Modular* : Do not try to combine different types of applications in one docker image. Keep them modularized.
- *Persist State* : Do not persist state inside a container.
- *Sim/Minimal Images* : Find an official image if it exists.
- *Multi-stage builds*

## 4.2 Whitelist Allowed Registres
- 3 ways of whitelisting
  - Using validating webhook configuration by deploying an admission controller server
  - Using OPA policy
  - Using ImagePolicyWebhook admission controller (discussed below)
    - Good things about ImagePolicyWebhook: The API server can be instructed to reject the images if the webhook endpoint is not reachable.
    - Bad things about ImagePolicyWebhook: More configuration files are expected on the API server node(s) compared to ValidatingWebhookConfiguration.

```sh
# Images with latest tag will be currently accepted.
# Deploy Image Policy Webhook server given below (create deployment & node port service)
https://github.com/kainlite/kube-image-bouncer/blob/master/kubernetes/image-bouncer-webhook.yaml
service/image-bouncer-webhook created
deployment.apps/image-bouncer-webhook created

# Create Admission kube config file
vi /etc/kubernetes/pki/admission_kube_config.yaml

apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority: /etc/kubernetes/pki/server.crt
    server: https://image-bouncer-webhook:30080/image_policy
  name: bouncer_webhook
contexts:
- context:
    cluster: bouncer_webhook
    user: api-server
  name: bouncer_validator
current-context: bouncer_validator
preferences: {}
users:
- name: api-server
  user:
    client-certificate: /etc/kubernetes/pki/apiserver.crt
    client-key:  /etc/kubernetes/pki/apiserver.key

# Create Admission configuration
vi /etc/kubernetes/pki/admission_configuration.yaml

apiVersion: apiserver.config.k8s.io/v1
kind: AdmissionConfiguration
plugins:
- name: ImagePolicyWebhook
  configuration:
    imagePolicy:
      kubeConfigFile: /etc/kubernetes/pki/admission_kube_config.yaml
      allowTTL: 50
      denyTTL: 50
      retryBackoff: 500
      defaultAllow: false # By default, if connection to webhook server is unreachable, the request will be denied.

# Update API server with these flags
--admission-control-config-file=/etc/kubernetes/pki/admission_configuration.yaml
--enable-admission-plugins=ImagePolicyWebhook

# Now all containers with latest tag will not be deployed.
```

## 4.3 Static analysis of workloads using KubeSec
```sh
# Installing kubesec
wget https://github.com/controlplaneio/kubesec/releases/download/v2.11.0/kubesec_linux_amd64.tar.gz
tar -xvf  kubesec_linux_amd64.tar.gz
mv kubesec /usr/bin/

# Scanning using kubesec
kubesec scan node.yaml
```

## 4.4 Scanning images using Trivy
```sh
# Add the trivy-repo
apt-get  update
apt-get install wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | sudo tee -a /etc/apt/sources.list.d/trivy.list

# Update Repo and Install trivy
apt-get update
apt-get install trivy

# Scan Image
trivy image nginx:1.19

# Scan only high severity
trivy image --severity=HIGH nginx:1.19

# Scan tar file
trivy image --input alpine.tar --format json --output /root/alpine.json
```

# 5. Monitoring, Logging & Runtime Security
## 5.1 Detect Threats Using Falco
- https://falco.org/docs/configuration/
- Falco uses system calls to secure and monitor a system, by:
  - Parsing the Linux system calls from the kernel at runtime
  - Asserting the stream against a powerful rules engine
  - Alerting when a rule is violated

- Made up of 3 things
  - Falco Configuration file : Defines how Falco is run, what rules to assert, and how to perform alerts. Location : /etc/falco/falco.yaml
  - Falco Userspace program : is the CLI tool falco that you can use to interact with Falco.
  - Driver : is a software that adheres to the Falco driver specification and sends a stream of system call information.
    - Falco kernel module : not all CSPs allow this
    - eBPF : eBPF is a revolutionary technology with origins in the Linux kernel that can run sandboxed programs in an operating system kernel.

```sh
# Inspect events generated by Falco
journalctl -fu falco

# Falco configuration file
cat /etc/falco/falco.yaml

# in case of multiple rules, the one coming at list of the list will take precedence
rules_file:
  - /etc/falco/falco_rules.yaml
  - /etc/falco/falco_rules.local.yaml
  - /etc/falco/k8s_audit_rules.yaml
  - /etc/falco/rules.d

json_output: false
log_stderr: true
log_syslog: true
log_level: info
priority: debug

syslog_output:
  enabled: true
file_output:
  enabled: false
  keep_alive: false # if true, file will be opened once and continously written to
  filename: ./events.txt
stdout_output:
  enabled: true
http_output:
  enabled: false
  url: http://some.url
program_output:
  enabled: false
  keep_alive: false
  program: "jq '{text: .output}' | curl -d @- -X POST https://hooks.slack.com"

# Sample Rule file
- rule: Debugfs Launched in Privileged Container
  desc: Detect file system debugger debugfs launched inside a privileged container which might lead to container escape.
  condition: >
    spawned_process and container
    and container.privileged=true
    and proc.name=debugfs
  output: Debugfs launched started in a privileged container (user=%user.name user_loginuid=%user.loginuid command=%proc.cmdline %container.info image=%container.image.repository:%container.image.tag)
  priority: WARNING
  tags: [container, cis, mitre_lateral_movement]

- list: shell_binaries
  items: [bash, csh, ksh, sh, tcsh, zsh, dash]

- macro: spawned_process
  condition: evt.type = execve and evt.dir=<
- macro: container
  condition: (container.id != host)

# To override, place the updated rule in /etc/falco/falco_rules.local.yaml. Then reload the Falco configuration and restart the engine without restarting the service.
kill -1 $(cat /var/run/falco.pid)

# If you use multiple Falco rules files, you might want to append new items to an existing list, rule, or macro. To do that, define an item with the same name as an existing item and add an append: true attribute to the list. When appending lists, items are added to the end of the list. When appending rules/macros, the additional text is appended to the condition: field of the rule/macro.
```

## 5.2 Ensure Immutability of Containers at Runtime
- Set readOnlyRootFileSystem: true
- Set priviledged: false (Priviledged means that container user 0-root is directly mapped to host user 0-root)
- set runAsUser: RunAsNonRoot
- Use volumes/mounts where you think the data will be written (log/caches) so that nobody can edit/add/delete file from other locations

```sh
apiVersion: v1
kind: Pod
metadata:
  labels:
    name: triton
  name: triton
  namespace: alpha
spec:
  containers:
  - image: httpd
    name: triton
    securityContext:
      readOnlyRootFilesystem: true
    volumeMounts:
    - mountPath: /usr/local/apache2/logs
      name: log-volume
  volumes:
  - name: log-volume
    emptyDir: {}
```

## 5.3 Enabling Audit Logs
- Audit records begin their lifecycle inside the kube-apiserver component. Each request on each stage of its execution generates an audit event, which is then pre-processed according to a certain policy and written to a backend
- Each request can be recorded with an associated stage. The defined stages are:
  - RequestReceived - The stage for events generated as soon as the audit handler receives the request, and before it is delegated down the handler chain.
  - ResponseStarted - Once the response headers are sent, but before the response body is sent. This stage is only generated for long-running requests (e.g. watch)
  - ResponseComplete - The response body has been completed and no more bytes will be sent.
  - Panic - Events generated when a panic occurred.

- The defined audit levels are:
  - None - don't log events that match this rule.
  - Metadata - log request metadata (requesting user, timestamp, resource, verb, etc.) but not request or response body.
  - Request - log event metadata and request body but not response body. This does not apply for non-resource requests.
  - RequestResponse - log event metadata, request and response bodies. This does not apply for non-resource requests.

```sh
# Creating Audit policy
vi /etc/kubernetes/prod-audit.yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
- level: Metadata
  namespaces: ["prod"]
  verbs: ["delete"]
  resources:
  - group: ""
    resources: ["secrets"]

# Enabling Auditing in API Server
 - --audit-policy-file=/etc/kubernetes/prod-audit.yaml
 - --audit-log-path=/var/log/prod-secrets.log
 - --audit-log-maxage=30
 - --audit-log-maxbackup=5
 - --audit-log-maxsize=100

# Adding volume/volume mounts in apiserver
# Volumes
  - name: audit
    hostPath:
      path: /etc/kubernetes/prod-audit.yaml
      type: File
  - name: audit-log
    hostPath:
      path: /var/log/prod-secrets.log
      type: FileOrCreate

# Volume Mounts
  - mountPath: /etc/kubernetes/prod-audit.yaml
    name: audit
    readOnly: true
  - mountPath: /var/log/prod-secrets.log
    name: audit-log
    readOnly: false
```