# AAF Virtual Home

Author: Bradley Beddoes and Shaun Mangelsdorf

Copyright 2014, Australian Access Federation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

## Background
There exists a community of researchers that are unable to take advantage of the services provided by the 
AAF because they are not a member of, or associated with, an organisation that is a subscriber to the AAF. 
They are thus unable to obtain an identity and credentials that would enable their use of the federation 
services and resources. These researchers can be from small research organisations, work with government 
departments or commercial organisations or may be citizen researchers. 

The current AAF Virtual Home Organisation (VHO) software, taken from the Federation of Switzerland, 
is now legacy software. The VHO software does not support higher levels of assurance, provides little 
work flow for creating and managing end users, has no end user self management features as well as 
supports a limited number of end users, making it inadequate for small research organisations wanting 
to use it as their indentify provider. This means that researchers without a relationship with an IdP 
are unable to connect to the Federation. 

The new VHR would solve this problem by allowing small research groups that are unable to, or would 
rather not, deploy an IdP to subscribe to the AAF and use the VHR as their identity provider. The AAF 
would offer this as an enhanced service to the sector. 

## Key Benefits
* Increased functionality over that provided by the existing Virtual Home Organisation (VHO)
* Removal of technical and financial barriers to on-board research groups into the federation (eg. Bioplatforms Australia, Platforms for Collaboration)
* Improved speed at which researchers will be able to gain access to federated services (removing technical barriers faced by smaller research groups and organisations wanting to gain access to federated services)

The VHR will increase access to the following subscriber groups:

 1. Small cohorts of researchers that do not belong to organisations subscribed to the AAF (e.g. research bodies)
 2. Commercial researchers (that usually partner with AAF subscribers)
 3. Citizen researchers that are associated with an AAF subscribed organisation
 4. International researchers associated with an AAF subscribed organisation.

## Key Deliverables
1. A complete user self-service web interface to request accounts, manage passwords, reset forgotten passwords
2. A mechanism for 2 factor authentication
3. Workflow and administrative interface for subscribers to manage users
4. Workflow and administrative interfaces for supplying higher Levels of Identity Assurance to end users
5. Usage reports
6. High availability architecture
7. Full integration into the AAF Federation Registry

## Local Dependencies
As of VH 1.5.0 (March 2017) there is an extra step required to build the AAF
patched version of Groovy for dependency resolution purposes.

To build AAF Groovy:

1. Be on Java 7
1. Be in the root directory of the virtualhome project checked out from
Github
1. `git submodule init`
1. cd aaf-patched-groovy
1. ./gradlew clean dist

To build VH WAR file:

1. Return to ../virtualhome and use `grails war` as normal.

To develop VH code:

1. Return to ../virtualhome and use `grails Y` as normal.
