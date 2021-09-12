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
kubectl get deploy api-foo -o yaml | yq e 'del(.metadata.managedFields)' -

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
- Before 2.2, we only had the binary system of privileged (uid=0) and non-privileged processes; either your process could do everything or it was restricted to the subset of a standard user. Certain executables like ping, which needed to be run by standard users but also make privileged kernel calls
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
  - 

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
## 3.5 Container Sandboxing
### 3.5.1 gVisor
- https://gvisor.dev/docs/
- In docker, every container shares the same host OS kernel unlike VM's which have their own kernels.
- While using a single, shared kernel allows for efficiency and performance gains, it also means that container escape is possible with a single vulnerability.
- gvisor is an application kernel that provides an additional layer of isolation between running applications and the host operating system.
- It limits the host kernel surface accessible to the application while still giving the application access to all the features it expects (makes limited syscalls).
- However, this comes at the price of reduced application compatibility and higher per-system call overhead.
- Uses runsc as container runtime. (docker uses runC as container runtime)

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