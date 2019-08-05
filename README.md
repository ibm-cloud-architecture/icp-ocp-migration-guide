# ICP to OpenShift migration guide
## Key differences between ICP and OpenShift

IBM Cloud Private (ICP) and Red Hat OpenShift are different Kubernetes
distributions. Fundamentally, both are based on the core Kubernetes
technologies. Thus, they bring relatively consistent experience for
application development and platform operation. From migration
perspective, we'll focus on the key differences between the two
platforms.

The following is the summary of the key differences:

||**ICP**|**OpenShift**|**Migration Effort**|
|-|-|-|-|
|**Infrastructure**||||
|Hardware| x86\_64<br>Power (ppc64le)<br>IBM Z| X86\_64<br>Power|Z is large migration effort, OpenShift generally runs wherever RHEL runs|
|Operating System| Red Hat Enterprise Linux 7.3, 7.4, 7.5<br><br>Ubuntu 18.04 LTS and 16.04 LTS<br>SUSE Linux Enterprise (SLES) 12| RHEL<br>Red Hat CoreOS (RHCOS)|Migrating from Ubuntu / Suse to OpenShift, customer may require operation procedure change such as OS patching, security certification etc.|
|IaaS provider|VMWare/OpenStack<br>Most public cloud IaaS providers|VMWare/OpenStack<br>Most of the public cloud IaaS provider<br>IBM Cloud and Azure provide managed OpenShift service|Need to pay attention on the networking and storage for the specific IaaS provider, as well as any automation code specific to an IaaS provider|
|HA Cluster Topology|Master<br>Proxy<br>Management<br>VA|Master<br>Worker|	Migration effort should be part of the OpenShift planning and installation|
|Installation|Ansible installer Delivered as Docker image|Ansible installer (v4.x completely changed the installation procedure with Operator) Delivered as RPM or Docker image|Installation procedure particularly any automation script requires significant change|
|Container Registry|ICP private registry<br>External Docker Registry|OpenShift Container Registry (OCR)<br>External Docker Registry|Small effort|
|Kubernetes Version||1.11|Kubernetes is generally stable after 1.9 but there are some features (e.g. storage-related) that are beta in 1.11|
|**Development**||||
|Local dev environment|Vagrant based local ICP cluster with ICP Community edition|Minishift<br>All-in-one OKD|Small effort|
|Development Layer||Projects|Provides higher level Kubernetes construct simplifying deployments.|
|Development tools|Standard Kubernetes<br>Microprofile|Standard Kubernetes<br>Source-to-image (S2I)<br>fabric8|Not too much needs to done for developers|
|DevOps|Platform neutral DevOps toolchain|Packaged Jenkins for CI<br>ImageStream for container image<br>s2i|Large effort.|
|Application package|Standard Kubernetes yaml<br>Helm<br>Operator|Standard Kubernetes yaml<br>OpenShift template<br>OpenShift Application<br>Operator|Medium to large effort|
|Deployment|Standard Kubernetes deployment and strategy|OpenShift opionated DeploymentConfig and ImageStream|Suggest to keep the Kubernetes standard approach. Small effort|
|**Operation**||||
Command Line Tool|kubectl|oc (superset of kubetl)<br>kubectl|Small effort when cli is used any operation or devops automation|
|User interface|ICP UI|OpenShift UI|Small effort|
|Multi-tenancy|Standard Kubernetes namespace and RBAC|OpenShift Project with RBAC<br>Operator can apply Quotas and limit per project or cluster|Medium effort|
|**Networking**||||
|SDN (Software Defined Network)|Default on Calico<br>Support other Kubernetes supported SDN|Default to Red Hat Open vSwitch SDN<br>Can use other Kubernetes supported SDN as well|Small effort. Most of these are internal to ICP and OpenShift|
|Cluster DNS|CoreDNS|SkyDNS (3.x)<br>CoreDNS (4.x)||
|External Access for Services|Ingress Controller<br>Load Balancer|Router (HAProxy)<br>Load Balancer|Medium effort to update the service exposure|
|**Storage**||||
|File Storage|GlusterFS<br>NFS|GlusterFS<br>NFS<br>Ceph||
|**Security**||||
|Container permission|Allows to run container as root|Forbids to run a container as root by default (best practice)|Small effort to rebuild the application container|
|Authentication|OpenID with primarily LDAP identify provider|OAuth with identity provider<br>OpenShift supports different kinds of IAM|Small effort|
|Authorization|RBAC as above<br>Kubernetes called Pod Security Policies (PSP) beta|RBAC as above<br>OpenShift Security Context Constraint (SCC)|Small effort, some changes needed in particular to address the SCC|
|Securing the master|TLS to master<br>X.509 certifate or token to access API server|TLS<br>X.509 certifate or token to access API server<br>Project quota to limit the token rate|Small effort|


For further reading, you can check this blog published earlier
<https://apps.na.collabserv.com/blogs/ca5e7833-78b8-481c-8a14-ba70b22a20ce/entry/Comparing_IBM_Cloud_Private_ICP_with_RedHat_OpenShift?lang=en_us>

## Development Experience

### OpenShift Development Environment

The goal of OpenShift is to provide a great experience for both
Developers and System Administrators to develop, deploy, and run
containerized applications. Developers should love using OpenShift
because it enables them to take advantage of both containerized
applications and orchestration without having to know the details.
Developers are free to focus on their code instead of spending time
writing Dockerfiles and running docker builds.

OpenShift is a full platform that incorporates several upstream projects
while also providing additional features and functionality to make those
upstream projects easier to consume. The core of the platform is
containers and orchestration. For the container side of the house, the
platform uses images based upon the docker image format. For the
orchestration side, it is based on upstream Kubernetes project. Beyond
these two upstream projects, there are a set of additional Kubernetes
objects such as routes and deployment configs.

### Standard Interfaces Differences (oc tool usage vs. kubectl and HELM)

Both Developers and Operators communicate with the OpenShift Platform
via one of the following methods:

-   **Command Line Interface:** *The command line tool that we will be
    using as part of this training is called the **oc **tool.* This tool
    is written in the Go programming language and is a single executable
    that is provided for Windows, OS X, and the Linux Operating Systems.

-   **A Web Console:** User friendly graphical interface

-   **REST API:** Both the command line tool and the web console
    actually communicate to OpenShift via the same method, the REST
    API. Having a robust API allows users to create their own scripts
    and automation depending on their specific requirements. For
    detailed information about the REST API, check out the official
    documentation
    at: [https://docs.OpenShift.org/latest/rest\_api/index.html](https://docs.openshift.org/latest/rest_api/index.html)

IBM Cloud Private also provides a CLI. Many interactions with ICP though
happen through the standard Kubernetes CLI called **kubectl.**
Developers also made use of **HELM** as a package manager to deploy
workloads. Whereas the pattern for ICP developers was to make heavy use
of kubectl or HELM to deploy workloads and applications, OpenShift users
often make more use of the **oc** commandline tool than kubectl. (*Note:
HELM can be used in OpenShift environment but it must be installed into
OpenShift. IBM Cloud Paks provide this ability as a core service over
OpenShift*).

OpenShift aims to greatly simplify development and deployment of
applications, thus providing a layer over Containers (much like a Cloud
Foundry would), and the **oc tool** provides those tools.

### Projects

OpenShift is often referred to as a container application platform in
that it is a platform designed for ***the development and deployment of
containers.***

To contain your application, OpenShift use **projects**. The reason for
having a project to contain your application is to allow for controlled
access and quotas for developers or teams. More technically, it\'s a
visualization of the Kubernetes namespace based on the developer access
controls. Under the hood, while "project" is a separate object returned
by the OpenShift API, there is a one-to-one mapping between "projects"
and "namespaces" in Kubernetes.

The typical experience goes something like:

-   Developer logs in to the console or CLI and creates a project
-   Add artifacts to project. This can take several forms, for example
    -   Deploy an existing Image (usually Docker based) and with
        optionally additional YAML files.

    -   Create an application out of templates.

    -   Create pipelines out of several approaches. (OpenShift has a
        built in mechanism called Source 2 Image, of s2i that can deploy
        straight from a git repository)

-   Configure resources.

    -   Items include exposing a Route (Described later in the article)

    -   Scale Pods.

When you create a Project and add a deployment, several of the
Kubernetes Objects are created for you by default. This includes:

-   **Pods:** Where your containers run which you can begin to scale
    immediately.

-   **Services:** provide internal abstraction and load balancing within
    an OpenShift environment, but sometimes clients (users, systems,
    devices, etc.) **outside** of OpenShift need to access an
    application. 

-   **Routes:** The way that external clients are able to access
    applications running in OpenShift. (Similar to Ingress or Node
    Ports).

A great way to get started with the development experience is through
the following website.
[https://learn.OpenShift.com/](https://learn.openshift.com/)

### Migration of applications from ICP to OpenShift.

There are actually many paths you can take to do this.

-   Install HELM either through open source or through IBM Cloud Paks.
    An example of this is here
    ([https://github.com/ibm-cloud-architecture/refarch-cloudnative-kubernetes/tree/spring\#deploy-bluecompute-to-an-OpenShift-cluster](https://github.com/ibm-cloud-architecture/refarch-cloudnative-kubernetes/tree/spring#deploy-bluecompute-to-an-openshift-cluster))

-   Take existing Docker Images and applications, update YAML, and
    create a project with the oc tool. You can then use one of the
    mechanisms described earlier. This will require you to update
    existing CI/CD pipleines but moves you closer to the OpenShift
    environment.

### Development Environments

OpenShift developers can use several approaches to local development.

-   Develop code and Docker images locally and deploy to a remote
    cluster. There are several "managed OpenShift Options" on various
    public clouds.

-   If you need to run a local kubrnetes distribution you can use.

    -   **Minikube:** This is the standard community Kubernetes.
        However, this will require you maintain duplicate YAML
        artifacts. This approach is not recommended.

    -   **OKD:** This is the Origin Community Distribution that powers
        OpenShift. You can access it here:
        [[https://www.okd.io/]{.underline}](https://www.okd.io/). OKD
        provides a feature complete version of OpenShift.

    -   **Minishift** is a tool that helps you run OKD locally by
        launching a single-node OKD cluster inside a virtual machine.
        With Minishift you can try out OKD or develop with it,
        day-to-day, on your local machine. You can run Minishift on the
        Windows, macOS, and GNU/Linux operating systems. More
        information can be found here: <https://www.okd.io/minishift/>

OpenShift is not opinionated on the application stack and provides
templates for various popular OpenSource frameworks such as Spring, Java
EE, JBoss, Quarkus, Node, etc.... A great place to learn about various
types of applications you can build is here:
[https://learn.OpenShift.com/middleware/](https://learn.openshift.com/middleware/)

### Additional tools, CLI's, and Frameworks

In addition to the oc tool, there are several more CLI's, tools, and
frameworks that you should be aware of.

-   **odo:** a CLI tool for developers who are writing, building, and
    deploying applications on OpenShift. With odo, developers get an
    opinionated CLI tool that supports fast, iterative
    development. odo abstracts away Kubernetes and OpenShift concepts so
    developers can focus on what\'s most important to them: code.
    odo was created to improve the developer experience with OpenShift.
    Existing tools such as oc are more operations-focused and require a
    deep understanding of Kubernetes and OpenShift concepts. More
    information can be found here:
    [https://OpenShiftdo.org/](https://openshiftdo.org/)

-   **Source-to-Image (S2I):** Source-to-Image (S2I) is a toolkit and
    workflow for building reproducible container images from source
    code. It is worth noting that you can use any CI / CD tool with
    OpenShift as well. More information can be found here:
    [https://github.com/OpenShift/source-to-image](https://github.com/openshift/source-to-image).
    We will discuss this more in the next section.

-   **CodeReady:** Built on the open Eclipse Che project, Red Hat
    CodeReady Workspaces provides developer workspaces, which include
    all the tools and the dependencies that are needed to code, build,
    test, run, and debug applications.  More information can be found
    here:
    <https://developers.redhat.com/products/codeready-workspaces/overview>

OpenShift developers can also use popular projects such as ISTIO,
kNative, and others on the platform

-   **ISTIO** is a service mesh that provides features such as routing,
    secure communication, Circuit Breaker, and Application diagnostic
    tools. Istio is supported throught he OpenShift Service Mesh
    offering, which is a Tech Preview and will be GA at the end of
    Aug 2019. To learn how to use ISTIO on OpenShift, go here:
    [https://learn.OpenShift.com/servicemesh/](https://learn.openshift.com/servicemesh/)

-   **Knative** extends Kubernetes to provide components for building,
    deploying, and managing serverless applications

-   **Tekton** is a cloud-native CI/CD framework where pipeline stages are
    executed in containers. Tekton is part of the OpenShift Pipelines
    offering. For more information go here:
    [https://blog.OpenShift.com/cloud-native-ci-cd-with-OpenShift-pipelines/](https://blog.openshift.com/cloud-native-ci-cd-with-openshift-pipelines/)

-   **Operators** are a framework for building Kubernetes-native
    applications. Red Hat provides and SDK for getting up and running on
    creating Operators from Helm charts, Ansible playbooks, and go code.
    For more information see:
    <https://github.com/operator-framework/getting-started>

### IBM Cloud Pak for Applications and additional Open Source projects

IBM announced the [Cloud Pak for Applications](https://www.ibm.com/cloud/cloud-pak-for-applications) which includes
support for IBM application runtimes such as IBM WebSphere Liberty and
middleware such as IBM MobileFirst Foundation

It also includes various recently-announced open source projects
maintained by IBM around developer tooling. These include:

-   [**Kabanero**]: <https://kabanero.io>, which consists of CodeWind
    <https://codewind.dev> for IDE extensions to developer tools like
    Eclipse and VSCode, and Appsody <https://appsody.dev> for building
    templates for popular runtimes

-   **Razee** <https://razee.io> for Continuous Deployment

The IBM Cloud Pak for Applications is still in development and may
include more components in the future.

## Dev toolchain (Roland)

## DevOps

As mentioned earlier, OpenShift provides an opinionated development
platform around source-to-image (S2I) as a differentiator over upstream
community Kubernetes. As a comparison to ICP, it was not opinionated on
DevOps beyond providing (outdated) community Helm Charts for Jenkins.
S2I is an integrated build and deployment framework that developers can
use to run code in containers in the platform without additional
infrastructure.

Note that if DevOps procedures are already mature and not tied to the
platform, and infrastructure is outside of the platform, it's possible
to reuse most of it as OpenShift conforms to Kubernetes. There are some
minor differences around security which are discussed later in this
document.

That said, a large part of OpenShift value proposition is that it's an
integrated development platform in addition to being a container
orchestrator. OpenShift includes some CustomResourceDefinitions (CRDs)
around continuous integration (CI) and continuous deployment (CD) that
enhance developer productivity. As the controllers for these objects are
built-in to the OpenShift API, they are not portable outside of
OpenShift.

### ImageStream

An ImageStream represents an image either in the internal OpenShift
container image registry, or in an external registry. An image in an
external registry can be mirrored and cached in the local container
image registry.

There are a few related resources to ImageStreams:

-   The ImageStream resource represents the repository part of the image

-   The ImageStreamTag resource represents an individual tag, which
    points at the hash of the image as stored in the registry. This hash
    is immutable and every push to the tag will update the hash,
    assuming the image has changes.

For example, if we were to import
docker.io/ibmcom/websphere-liberty:latest, the ImageStream part would be
"docker.io/ibmcom/websphere-liberty", and the tag would be "latest". The
ImageStreamTag would represent the pointer to the image represented by
"docker.io/ibmcom/websphere-liberty:latest", which changes every time
someone pushes to the ibmcom/websphere-liberty:latest tag.

OpenShift will deploy the image hash in deployments and the
ImageStreamTag tracks the upstream images as they change. As such, we
can use ImageStreams to track changes to images even if the image in the
original tag changes.

Images in external registries can be imported into OpenShift as
ImageStreams, and mirrored on a schedule. ImageStream changes can
trigger builds or redeployments; this can be useful in cases such as
triggering rebuilds on a nightly patched image updates for base images,
or as part of a continuous deployment procedure where image tags are
used to track image deployments to certain environments.

Additionally, since the ImageStream objects are stored in
OpenShift/Kubernetes, RBAC can be applied to them and they can be scoped
to individual projects or shared to multiple projects. This is similar
to how ICP manages RBAC around images as well in its private registry.

View the FAQ on the ImageStream here:
[https://blog.OpenShift.com/image-streams-faq/](https://blog.openshift.com/image-streams-faq/)

### BuildConfig

For Continuous Integration, the BuildConfig is a CustomResource is used
to produce a target image based on inputs and triggers. The BuildConfig
takes as input:

-   Source code (such as a git repository) or binaries, (for example, a
    directory as part of an external pipeline)

-   Source ImageStream (for example a base image like
    ibmcom/websphere-liberty)

-   Target ImageStream which contains the built application artifact

    There are various strategies around BuildConfig, which control how
    the target image stream is assembled:

-   Source strategy: this is the core of S2I where a builder image is
    provided that builds the source and packages it into a target
    container image, then pushes it into the OpenShift private registry.
    This requires the builder image to have knowledge about how to turn
    code into a container image. For example, for Java code, the builder
    image may run "mvn package", take the output binaries and build an
    image from a Java runtime. Red Hat ships several builder images for
    popular runtimes, but any custom runtimes or deviations from the
    happy path may require additional work to support. Red Hat provides
    an SDK/documentation on how to build custom builder images here:
    [https://github.com/OpenShift/source-to-image](https://github.com/openshift/source-to-image)

-   Docker strategy: this is equivalent to running "docker build" on a
    local machine, except it is done through OpenShift. As part of this,
    the context directory and a Dockerfile are uploaded to OpenShift
    where it the container image is assembled from binaries. There are
    advantages to this, mainly that in some CI scenarios in multi-tenant
    environments where the administrators do not want to expose docker
    socket for direct "docker build", as this exposes root access on the
    machine where the container is assembled.

-   Pipeline strategy: this is equivalent to creating a staged build
    pipeline through Jenkins. In this BuildConfig type, an embedded
    Jenkins declarative pipeline is defined in the body of the resource.
    OpenShift will provision an instance of Jenkins in the project to
    execute the build and will sync the build status from Jenkins to the
    Build object (more on it below). The OpenShift Application console
    contains some UI elements that show the build status from Jenkins.

An instance of an execution of BuildConfig is a Build. Builds can be
triggered when the upstream source is changed, when the source
ImageStream changes, or manually using "oc new-build\". An execution of
BuildConfig results in a new Build object being created, which has a
build number that increments every time the build is run. BuildConfig
can maintain build history for both successful and unsuccessful builds.
The build itself is run in a build pod.

For more information, see here:
[https://docs.OpenShift.com/container-platform/3.11/dev\_guide/builds/index.html](https://docs.openshift.com/container-platform/3.11/dev_guide/builds/index.html)

### DeploymentConfig

OpenShift has DeploymentConfigs, which is a precursor to the Kubernetes
Deployments. The DeploymentConfig resource is not portable to
non-OpenShift Kubernetes distributions. Note that OpenShift also
supports the familiar Deployment resource as well, so in terms of moving
from ICP or other Kubernetes distributions, offers basically zero
migration effort and is more community-friendly.

DeploymentConfig does provide deeper integration with ImageStreams, in
that when an ImageStream is updated, OpenShift can perform an update of
the Deployment. OpenShift can also extend this integration with
ImageStreams to regular Deployments by configuration, see
[https://docs.OpenShift.com/container-platform/3.11/dev\_guide/managing\_images.html\#using-is-with-k8s](https://docs.openshift.com/container-platform/3.11/dev_guide/managing_images.html#using-is-with-k8s).

Additionally, DeploymentConfig supports a few advanced deployment
strategies, which are detailed here:
[https://docs.OpenShift.com/container-platform/3.11/dev\_guide/deployments/deployment\_strategies.html](https://docs.openshift.com/container-platform/3.11/dev_guide/deployments/deployment_strategies.html).
Most notably, they claim support for "canary" deployments, although the
documentation suggests the regular rolling update is a form of canary
deployment (which it isn't, as the deployment continues to get rolled
over as soon as the health checks pass). There is also support for A/B
testing and blue-green deployments.

There are additional features and differences between Deployments and
DeploymentConfigs in OpenShift. When a DeploymentConfig rolls out a
deployment, a "deploy" pod is created that performs the actual
deployment, as opposed to a controller running on the master performing
the rollout. This may be slightly more scalable in very large clusters
where many rolling deployments are happening simultaneously.
Additionally, rollouts may be paused and resumed as needed. Also, a
handy command is the "oc rollout latest", which just re-deploys the same
version of the pod; this is useful if a ConfigMap has changed and the
pods need to restart to refresh them.

For more information, see here:
[https://docs.OpenShift.com/container-platform/3.11/dev\_guide/deployments/how\_deployments\_work.html](https://docs.openshift.com/container-platform/3.11/dev_guide/deployments/how_deployments_work.html)

### Templates

OpenShift provides support for Template resources, which are regular
OpenShift objects with parametrized fields in them. This is similar to
Helm template, but without the advanced ability to generate random data,
conditionals, or complex variable types.

The "oc process" command is used to convert a template to a regular
resource. The Template is a list of one or more templated resources, and
can be stored in the OpenShift API for re-use, or processed from local
filesystem. Templates form the base for the "oc new-app\" command which
generates a list of resources from a list of parameters.

Again, as templates are very OpenShift specific, use discretion before
using. There are several other open-source Kubernetes templating
projects, for example Helm and Kustomize, that are more portable and
more community-friendly. Generally Red Hat frowns upon Helm 2.x as
server side tiller requires large permissions and the helm client
requires read access to the namespace where tiller runs; Helm 3
addresses this by including tiller on client side.

See here for more information:
[https://docs.OpenShift.com/container-platform/3.11/dev\_guide/templates.html](https://docs.openshift.com/container-platform/3.11/dev_guide/templates.html)

# Infrastructure

This chapter explores the infrastructure consideration when migrating
from ICP to OpenShift. It covers the hardware platform, IaaS and
hypervisors, operating system and platform automation.

## Hardware and hypervisor

ICP can be deployed on (Linux) x86\_64, Power (ppc64le) and IBM Z and
LinuxOne. OpenShift now can only run x86\_64 hardware. Each has its own
sizing recommendation in terms of CPU, memory and disk space. You can
reference the system requirement for both below:

ICP (3.2) hardware requirement guide -
<https://www.ibm.com/support/knowledgecenter/SSBS6K_3.2.0/supported_system_config/hardware_reqs.html>

OpenShift (3.11) hardware requirement -
[https://docs.OpenShift.com/container-platform/3.11/install/prerequisites.html\#hardware](https://docs.openshift.com/container-platform/3.11/install/prerequisites.html#hardware)

Both ICP and OpenShift can run on Hypervisors like VMware, OpenStack and
Hyper-V in a private cloud environment. ICP is also supported on IBM
PowerVC.

## IaaS

Both ICP and OpenShift can run on public or private IaaS. In public. We
have tested ICP on IBM Cloud, Azure, AWS, GCP, and Huawei Cloud. On the
other hand, we have tested OpenShift on IBM Cloud, Azure, AWS.

For OpenShift on public cloud, there are potentially 3 offering:

-   Managed OpenShift cluster. This includes IBM IKS managed OpenShift
    (beta) and Azure Managed OpenShift

-   Guided-provision OpenShift cluster. The IaaS vendors provide guided
    automation procedure to provision a full OpenShift cluster either
    through UI or automation scripts. For example, Azure OpenShift
    cluster and AWS OpenShift quickstart.

-   Build your own cluster. End user provisions IaaS VMs (or bare
    metal), then install OpenShift on top of the VMs.

ICP doesn't have a managed edition.

## Operating System

This is where you should pay the most attention when migrating from ICP.

Both platforms can only run on top of Linux OS. ICP supports Red Hat
Enterprise Linux (RHEL) 7.3, 7.4 and 7.5, Ubuntu 18.04 LTS and 16.04
LTS, SUSE Linux Enterprise (SLES) 12. While OpenShift supports only RHEL
7.4 or later in 3.x, or Red Hat Enterprise Linux CoreOS (RHCOS) in
release 4.x. In OpenShift Container Platform 4.1, you must use RHCOS for
all masters, but you can use Red Hat Enterprise Linux (RHEL) as the
operating system for compute, or worker, machines. If you choose to use
RHEL workers, you must perform more system maintenance than if you use
RHCOS for all of the cluster machines.

What does this mean is that you need to switch RHEL or RHCOS when
migrating ICP running on Ubuntu or Suse Linux. Most of this is
infrastructure related Ops activity.

# Storage

# Security
## SELinux

OpenShift requires SELinux to be "enforcing" and "targeted" mode. When
containers are run, the container image's filesystem is labeled using a
random label and the container processes are labeled the same way, so
that only the container processes can access its own filesystem and no
other processes. Any mounted filesystems (secrets, configmaps, or
volumes) will have an SELinux policy applied to them to allow the
container to read and write to them.

## PodSecurityPolicy vs SecurityContextConstraints

OpenShift SecurityContextContsraints (SCC) is the pre-cursor to the
PodSecurityPolicy (PSP) in upstream community Kubernetes. As such, a lot
of the properties of the PSP come directly from the SCC. These objects
are cluster-scoped policies designed to limit the access of containers
to the host kernel. Most containers do not need to privileged access to
the host and should as a best practice not depend on the uid of the user
owning the container process. However, many containers on DockerHub and
even some IBM middleware require running as root or some other
capabilities in order to function.

One important thing to note is that while the PodSecurityPolicy objects
can be created in OpenShift, the platform will ignore these objects and
only enforces the SecurityContextConstraints objects. OpenShift ships
with some out of the box SCCs, the default "restricted" policy is the
most restrictive, and the "privileged" policy is the most open.

One very large difference is that the default policy in OpenShift will
generate random a uid/gid from a range for the container process to run
as (the "restricted" policy), and if your container depends on a
specific uid/gid being set, the container may not run. One common
example is if container requires reads or writes to the local filesystem
as a specific user. In this case, the "nonroot" SCC seems to match the
"ibm-restricted-psp" default policy that ICP ships with.

Here is a comparison of the out-of-box SCCs to those shipped with ICP,
as well as some brief comments:

|**OpenShift**|**ICP**|**Comments**|
|-|-|-|
|anyuid|ibm-anyuid-psp|Container is allowed to run as any uid, including root, but within restricted SELinux context|
|hostaccess|(n/a)|Container is allowed to access host namespaces (i.e. can mount filesystem and network of the host), but must run as random non-root user|
|(n/a)|ibm-anyuid-hostaccess-psp|Container is allowed to access host namespaces (i.e. can mount filesystem, access host network, and access any other namespaced resources on the host), and may run as any user|
|hostmount-anyuid|ibm-anyuid-hostpath-psp|Container is allowed to run as any user and can mount host directories|
|hostnetwork|(n/a)|Container can run on the host network, but must run as random selected non-root user|
|nonroot|ibm-restricted-psp|Container can run as any user except root; this is useful for containers that expect to run as a particular UID from its local /etc/passwd|
|privileged|ibm-privileged-psp|Run as any user and have access to any host features. This is essentially running as root right on the worker node and should be used sparingly|
|restricted|(n/a)|(OpenShift Default) Denies access to most host features and must run as random-selected uid.|

In order for a pod to be able to run with additional access to the host
system, it's necessary to apply the SCC to the service account the pod
executes as. One subtle difference between SCC and PSP is the RBAC
around it; SCCs have a "users" property that lists the entities allowed
to use the SCC while PSPs are controlled with roles and rolebindings.
You can use the following command to apply the SCC to a service account,
which under the covers adds the service accounts to the "users" property
of the SCC.

```bash
oc adm policy add-scc-to-user <scc> system:serviceaccount:<namespace>:<serviceaccount>
oc adm policy remove-scc-from-user <scc> system:serviceaccount:<namespace>:<serviceaccount>
```

Identity Providers
------------------

OpenShift supports one or more Identity Providers as user directory
sources for authentication. As OpenShift is a development platform, the
default behavior is that any user that can authenticate to OpenShift is
able to create a project (mappingMethod "claim"). This behavior can be
changed during installation or after installation by using mappingMethod
"lookup", the downside is that the administrator must manually add user
resources to OpenShift before they will be authorized to use the
platform.
[https://docs.OpenShift.com/container-platform/3.11/install\_config/configuring\_authentication.html\#LookupMappingMethod](https://docs.openshift.com/container-platform/3.11/install_config/configuring_authentication.html#LookupMappingMethod)
for more information.

Role-based Access Control
-------------------------

As Kubernetes RBAC was submitted upstream by Red Hat from OpenShift
features, much of the RBAC in ICP is largely the same in ICP and
OpenShift. Roles and ClusterRoles are groups of permissions on objects
in the Kubernetes API. RoleBindings and ClusterRoleBindings are objects
that bind roles to identities to access those permissions. Users,
groups, and service accounts may have multiple role bindings which
aggregated together gives them an access list of parts of the platform
they may access.

One shortcut around assigning roles/cluster roles to users exists in the
oc CLI, which under the covers creates a RoleBinding or
ClusterRoleBinding, instead of the awkward "kubectl create rolebinding"
and "kubectl create clusterrolebinding" commands:

```bash
oc adm policy add-role-to-user <role> <user>
oc adm policy add-cluster-role-to-user <role> <user>
oc adm policy remove-role-from-user <role> <user>
oc adm policy remove-cluster-role-from-user <role> <user>
```

### ImagePolicy

OpenShift also contains an image policy, although it is not stored as a
Custom Resource as it is in ICP. This can be configured on the master
nodes. See:

[https://docs.OpenShift.com/container-platform/3.11/admin\_guide/image\_policy.html](https://docs.openshift.com/container-platform/3.11/admin_guide/image_policy.html)

# Networking

From a developer point of view, the pod networking in OpenShift uses
largely the same concepts as ICP and Kubernetes in general. There are
some implementation differences in OpenShift networking to watch out for
if you are managing the platform.

## OpenShift SDN

The default networking implementation in OpenShift is the OpenShift SDN.

[https://docs.OpenShift.com/container-platform/3.11/architecture/networking/sdn.html](https://docs.openshift.com/container-platform/3.11/architecture/networking/sdn.html)

OpenShift SDN has with three different plugins that provide different
levels of network isolation between projects:

-   **ovs-subnet**: (default) flat network that allows all projects to
    talk to all projects

-   **ovs-multitenant**: all projects are isolated from each other, with
    a single exception the `default` project where the OpenShift router
    and internal image registry run

-   **ovs-networkpolicy**: allows fine-grained control of network
    isolation using NetworkPolicy objects (equivalent to ICP).

When installing OpenShift, Red Hat recommends always installing using
the **ovs-networkpolicy** plugin which provides near parity with ICP
feature with Calico. To use this, add the following parameter to the
ansible hosts file before installation:

`os_sdn_network_plugin_name='redhat/OpenShift-ovs-multitenant'`

Note that it's possible to run Calico on OpenShift instead of Openshfit
SDN; however Red Hat does not support this directly and the client will
need to purchase support directly from Tigera. The list of additional
vendor-supported network plugins are available here:

[https://docs.OpenShift.com/container-platform/3.11/install\_config/configuring\_sdn.html\#admin-guide-configuring-sdn-available-sdn-providers](https://docs.openshift.com/container-platform/3.11/install_config/configuring_sdn.html#admin-guide-configuring-sdn-available-sdn-providers)

## OpenShift SDN Architecture

OpenShift SDN networking components live in the `openshift-sdn` project
in OpenShift, and consist of two daemonsets, `ovs` and `sdn`.

`ovs` is a containerized version of Open vSwitch which is an open source
SDN software used most commonly in OpenStack. This will manage a bridge
device, vxlan tunnel device for the pod network, and all of the virtual
ethernet devices (veths) for each pod as they are created and destroyed.

`sdn` is a component used to program openvswitch by synchronizing routes
to the other worker nodes and any cluster IP services created in the
cluster. The routes are programmed as open vswitch flows and the cluster
IPs are configured using netfilter (iptables) rules.

To dump the flows for debugging or informational purposes, you may
install the "openvswitch" package on any cluster node, and use
`ovs-ofctl` to view the flow table. See
[https://docs.OpenShift.com/enterprise/3.1/admin\_guide/sdn\_troubleshooting.html\#debugging-local-networking](https://docs.openshift.com/enterprise/3.1/admin_guide/sdn_troubleshooting.html#debugging-local-networking)
for more information. This output is helpful to understand how pod
traffic is forwarded.

In contrast to ICP/Calico, which uses a single controller pod running on
the master nodes to orchestrate subnet selection, routes and network
policy rules, and a daemonset "calico-node" running across each cluster
node to program iptables rules and do route propagation. In ICP/Calico,
the `kube-proxy` container running on every node programs the cluster
IPs in iptables rules instead of the `calico-node` pod.

In both ICP and Calico cases, the daemonset runs as a privileged
container on each host in order to have access to the host network.

## IP Address Management

As in standard Kubernetes, both OpenShift and ICP have a pod overlay
network where address space is defined for pods, and pod IP addresses
are drawn from subnets selected from this address space. In ICP this was
defined using the "network_cidr" property in the installation
config.yaml. OpenShift also has the same concept, where the cluster
network CIDR defined in `osm_cluster_network_cidr` in the ansible
hosts file, the default is `10.128.0.0/14`. You can view the subnet in the
`clusternetwork` custom resource in OpenShift (`oc get clusternetwork`).

Every node in the cluster will receive a "slice" of this address space.
One additional parameter in OpenShift is the
`osm_host_subnet_length`, which defines the size of the subnets
assigned to each node in the cluster where pods running on them will be
assigned IP addresses from. In ICP, Calico automatically selected this
size based on the number of nodes in the cluster and the size of the pod
network, and was able to resize and "steal" subnets from other nodes
when particular worker nodes exhausted their pool. In OpenShift this is
a static length. The default value of this is 9, which indicates that
every worker node will get 32-9=23 bits of subnet space (i.e. a /23
subnet, or 512 IP addresses). The assigned host subnets are stored in
the `hostsubnets` Kubernetes custom resource (`oc get hostsubnets`). It's
important to select a subnet length that will satisfy both the number of
worker nodes and the expected number of pods on each worker node in the
cluster.

Like in ICP, there is an additional "service network" overlay network,
which is a non-overlapping address space with the pod network that
ClusterIP services are defined on. In OpenShift the installation
parameter for this is `openshift_portal_net`.

## Pod Routing and Route Propagation

In ICP, Calico propagated routes using a node-to-node mesh where every
worker node became a "router" for its assigned subnet on the pod network
and the routes were communicated using border gateway protocol (BGP).
Since BGP is a standard protocol used on the internet, it was possible
for non-cluster nodes to join the peer-to-peer mesh and the routes to be
propagated outside of the cluster and potentially gain some visibility
into the pod network with external tools. However, because of the
node-to-node mesh there can be scalability issues when the cluster
becomes very large, BGP route reflectors could be used to propagate
routes instead.

In OpenShift, the routes are stored in Kubernetes resources and the
"sdn" DaemonSet programs the routes on each cluster node as flows in the
local openvswitch tables. There is a bridge interface on each node that
all pods receive a port on, and a tunnel interface where all outbound
pod network traffic is sent when the destination pod is not running on
the local node.

The following documentation helps to understand the network flows:

[https://docs.OpenShift.com/container-platform/3.11/architecture/networking/sdn.html\#sdn-packet-flow](https://docs.openshift.com/container-platform/3.11/architecture/networking/sdn.html#sdn-packet-flow)

## Network Isolation

In contrast to ICP and Calico's usage of iptables rules, OpenShift SDN
uses VXLAN to perform project-level isolation. Every project is assigned
a Virtual Network Identifier (VNID), and as traffic leaves the Open
vSwitch tunnel, the VNID is added to the outgoing packet. When traffic
reaches the destination, if the worker node does not have a policy
(either the same VNID, or an explicit Open vSwitch flow from a Network
Policy) that allows the traffic, it is dropped. As mentioned earlier the
"default" namespace runs the router and registry and as such, every
project is allowed to access this project, which is given the special
VNID 0. It's important for administrators not to expose "default" to
users to deploy pods in general as all projects in the cluster will have
network access to it.

You can read more details here:

[https://docs.OpenShift.com/container-platform/3.11/architecture/networking/sdn.html\#network-isolation-multitenant](https://docs.openshift.com/container-platform/3.11/architecture/networking/sdn.html#network-isolation-multitenant)

In some environments, OpenShift may run on top of infrastructure that
already uses VXLAN for isolation (such as VMware and NSX) and the VXLAN
port used must be changed due to conflicts. This can be done by
following the steps documented here:

[https://docs.OpenShift.com/container-platform/3.11/install\_config/configuring\_sdn.html\#config-changing-vxlan-port-for-cluster-network](https://docs.openshift.com/container-platform/3.11/install_config/configuring_sdn.html#config-changing-vxlan-port-for-cluster-network)

## NetworkPolicy

NetworkPolicy is largely the same in OpenShift as it is in ICP. There is
one difference in that OpenShift only supports ingress NetworkPolicy, so
network policies with egress rules do not work and egress network policy
is controlled using a separate EgressNetworkPolicy object.

NetworkPolicy objects in OpenShift result in flow rules in Open vSwitch,
and if using a podSelector to match pods, the more pods that match the
rule, the more rules are created, which may cause some scalability
issues. See documentation for an explanation:

[https://docs.OpenShift.com/container-platform/3.11/admin\_guide/managing\_networking.html\#admin-guide-networking-using-networkpolicy-efficiently](https://docs.openshift.com/container-platform/3.11/admin_guide/managing_networking.html#admin-guide-networking-using-networkpolicy-efficiently)

## EgressNetworkPolicy and EgressRouter

As mentioned in previous section, the OpenShift EgressNetworkPolicy is a
separate object used to control egress traffic from pods to external
subnets. These are implemented at Layer 3 in openflow table rules. The
destinations may also be DNS names, but these are implemented using a
DNS lookup of the name and the subsequent rules on the resolved IP
address for the DNS record's TTL. You can see more information in the
documentation here:
[https://docs.OpenShift.com/container-platform/3.11/admin\_guide/managing\_networking.html\#admin-guide-limit-pod-access-egress](https://docs.openshift.com/container-platform/3.11/admin_guide/managing_networking.html#admin-guide-limit-pod-access-egress)

OpenShift has an object that allows all egress to a particular external
service go through a single node, called EgressRouter. This allows
traffic coming from the cluster to an external service appear from a
static IP and allows operations to whitelist that router. See:
[https://docs.OpenShift.com/container-platform/3.11/admin\_guide/managing\_networking.html\#admin-guide-limit-pod-access-egress-router](https://docs.openshift.com/container-platform/3.11/admin_guide/managing_networking.html#admin-guide-limit-pod-access-egress-router)

## DNS

ICP runs a DaemonSet across the masters containing CoreDNS for cluster
DNS lookup and name resolution. DNS was only available inside of pods,
as the kubelet would set each pod's /etc/resolv.conf to point at the
service IP address of the CoreDNS pod, and the host's /etc/resolv.conf
is used for upstream name resolution.

OpenShift 3.11 implements DNS slightly differently: SkyDNS runs on every
node and is embedded within the atomic-OpenShift-node service listening
on port 53. This node will sync service names and endpoints retrieved
from etcd to the local SkyDNS. Every node in the cluster will have its
/etc/resolv.conf rewritten to point at the local copy of SkyDNS. All
pods will also have their /etc/resolv.conf rewritten to point at the IP
address of the local host. This means that service names (using FQDN of
the cluster internal domain) are resolvable even from cluster nodes.

OpenShift will not start if NetworkManager is not enabled on all nodes.
Make sure that NetworkManager is managing all interfaces
(NM\_CONTROLLED=yes in /etc/sysconfig/network-scripts/ifcfg-eth\*). A
script that runs when NetworkManager brings up the interface will
rewrite the local /etc/resolv.conf to point at SkyDNS; the upstream DNS
servers are stored in /etc/origin/node/resolv.conf.

See the documentation for more information:

[https://docs.OpenShift.com/container-platform/3.11/architecture/networking/networking.html\#architecture-additional-concepts-OpenShift-dns](https://docs.openshift.com/container-platform/3.11/architecture/networking/networking.html#architecture-additional-concepts-openshift-dns)

Note that OpenShift 4.x implements this differently and has moved to the
more familiar CoreDNS.

## Routes vs Ingress

In order to get external cluster traffic into the cluster, ICP used the
Proxy Nodes which run an nginx-based ingress controller. Ingress
resources stored in Kubernetes were used to program the nginx
configuration to accept Layer-7 traffic based on specific rules, and
could leverage certain nginx features like path-based rewrites and TLS
termination using annotations on the ingress resource.

In OpenShift, there is a similar component running on the "infra" nodes
called the Router. This is an HAProxy container, and runs in the special
"default" project that all projects should have access to. OpenShift
uses a special "Route" object that pre-dates "Ingress" resources in
Kubernetes, which can be used to expose Layer 7 traffic, terminate TLS.
There are a few more options that are exposed as first-class properties
of Routes such as being able to passthrough TLS connections or
re-encrypt them.

In later versions of OpenShift (3.10+), the router is able to translate
"Ingress" objects to "Routes". However, HAProxy is not as feature-rich
as nginx and as such some features in the ICP ingress controller are not
available using OpenShift routes, most notably path-based rewrites. A
workaround is to run a standalone nginx controller that can perform
these rewrites as needed in each project, and expose that using through
the OpenShift router.

When OpenShift is installed, it requires a wildcard domain pointing at
the IP address or load balancer in front of the nodes where the router
is installed (**OpenShift\_hosted\_registry\_routehost**). All routes
will by default be given a DNS name like
\<route-name\>-\<project-name\>.\<app-subdomain\>.

More documentation about the default HAProxy router, including some
advanced use cases like router sharding (which is similar to the ICP
isolated proxy use case) is here:
[https://docs.OpenShift.com/container-platform/3.11/install\_config/router/default\_haproxy\_router.html\#install-config-router-default-haproxy](https://docs.openshift.com/container-platform/3.11/install_config/router/default_haproxy_router.html#install-config-router-default-haproxy)

## External Integration with F5 Load Balancer

Note that like ICP, there is an F5 BIGIP controller for OpenShift where
a controller is able to program an F5 appliance through the API in
response to Kubernetes resources. See:
[https://clouddocs.f5.com/containers/v2/OpenShift/](https://clouddocs.f5.com/containers/v2/openshift/)

# Operation -- Cluster Management, Monitoring and Logging

Operation maybe one of the complex areas requires extra planning and
effort to migrate from ICP to OpenShift.

## Cluster Management

We mentioned the different options to access ICP and OpenShift in early
chapters. From operation perspective either manual or automated, the
command line tools (cli) might be the most relevant tool. The good news
is that both platform support "kubectl" to operate your cluster. The not
so good news is that both have their own flavor of cli (ICP has the
cloudctl while OpenShift has oc). Most of the standard kubernetes tasks
can be carried out by sticking to "kubectl". That puts migration as
small effort to migrate any "cloudctl" command to either "kubectl" or
"oc" or sunset them.

One area you need to pay attention is that OpenShift runs only on RHEL
or RHCOS operating system. That may introduce some migration work when
your ICP is running on non-RedHat OS. For example, if you have operation
scripts handles the patches update on OS, service restart etc.

## Monitoring

Both platforms are adopting the CNCF projects as de-facto standard when
comes to monitoring. They are Grafana and Prometheus. ICP has fairly
decent integration with both technologies and OpenShift 3.11 installs
them by default. But this doesn't mean the migration is that
straightforward.

First, Prometheus may collect different set of metrics. It will be at
least a medium level of effort to adjust the Prometheus Query Language
and tested in new OpenShift platform.

Then, you might need to migrate the Grafana dashboards that purposely
built for ICP. OpenShift comes with some sample dashboard like Docker or
Kubernetes monitoring via Prometheus.

Alerting is another area you need to consider. In theory, OpenShift
Prometheus supports AlertManager (can be installed as optional
component). But ensuring the existing ICP alerts fully function in
OpenShift including Notification by email, webhooks, Slack, PagerDuty
and alert Silencing, aggregation, inhibiting can take quite bit of
effort.

## Logging

ICP deploys an ELK (ElasticSearch, Logstash, Kibana) stack, referred to
as the management logging service, to collect and store all
Docker-captured logs.

OpenShift uses the EFK (ElasticSearch, fluentd, Kibana) stack as a
logging solution. The main difference comparing to ICP is how the logs
are shipped out of the cluster with Fluentd. But most of that is
implementation detail and relatively transparent to the application and
end user.

# Migration Strategy -- ICP Cluster migration
[Migration Strategy](./migration_strategy.md)
