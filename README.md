[![Auth Server Build](https://github.com/iotauth/iotauth/actions/workflows/maven.yml/badge.svg?branch=main)](https://github.com/iotauth/iotauth/actions/workflows/maven.yml)
[![Example Tests](https://github.com/iotauth/iotauth/actions/workflows/example.yml/badge.svg?branch=main)](https://github.com/iotauth/iotauth/actions/workflows/example.yml)
[![Entity Integration Tests](https://github.com/iotauth/iotauth/actions/workflows/integration-test.yml/badge.svg?branch=main)](https://github.com/iotauth/iotauth/actions/workflows/integration-test.yml)
[![Multi-Auth Integration Tests](https://github.com/iotauth/iotauth/actions/workflows/multi-auth-test.yml/badge.svg?branch=main)](https://github.com/iotauth/iotauth/actions/workflows/multi-auth-test.yml)
[![sst-c-api Tests](https://github.com/iotauth/iotauth/actions/workflows/sst-c-api-tests.yml/badge.svg?branch=main)](https://github.com/iotauth/iotauth/actions/workflows/sst-c-api-tests.yml)
[![sst-c-api C++ Tests](https://github.com/iotauth/iotauth/actions/workflows/sst-c-api-cpp-tests.yml/badge.svg?branch=main)](https://github.com/iotauth/iotauth/actions/workflows/sst-c-api-cpp-tests.yml)

The badges show the status of the continuous integration (CI) workflows on `main`.
See [**CI workflows**](.github/workflows/README.md) for what each workflow tests and how to run the tests locally.

# Overview
---
This is a repository for the open-source project **SST (Secure Swarm Toolkit)** and its local authentication and authorization entity, **Auth**, for the security of distributed systems and the Internet of Things (IoT). Auth is a local point of authorization, and Auth's main roles are 1) providing authentication/authorization for its locally registered entities or devices and 2) working as a bridge of authorization between its local entities and the Internet. 

Our conference papers [[IoTDI '17](https://dl.acm.org/citation.cfm?id=3054980)] (winner of **ACM/IEEE Best Paper Award at CPSWeek '17**), [[FiCloud '16](http://ieeexplore.ieee.org/document/7575852/)] describe a secure network architecture with key distribution mechanisms using Auth (local, automated authorization entity).
The architecture provides security guarantees while addressing IoT-related issues, including resource constraints and intermittent connectivity.
The architectural concept of locally centralized, globally distributed authentication and authorization is illustrated in our magazine article [[IT Professional '17](https://ieeexplore.ieee.org/document/8057722/)].
Our ACM journal article [[ACM TIOT '20](https://dl.acm.org/doi/abs/10.1145/3375837)] presents a secure migration technique as a recovery mechanism from Denial-of-Service (DoS) attacks or failures.
In 2023, we released the C API for SST, which was introduced in an open-source software journal [[SoftwareX '23](https://www.sciencedirect.com/science/article/pii/S2352711023000869)].
We also applied SST for securing large-scale key-value storage [[SIGMOD '25](https://dl.acm.org/doi/10.1145/3725354)] and for access control of decentralized and distributed file systems [[Mid4CC '23](https://dl.acm.org/doi/10.1145/3631309.3632832)].
Furthermore, we built SST Testbed [[ICIT '26](https://ieeexplore.ieee.org/document/11490150)], a testbed for experimenting with attacks and defenses for distributed embedded systems and IoT using SST, which also won the **[1st place](https://2025.esweek.org/awards-2025/) in the Embedded System Software Competition (ESSC) at ESWEEK '25** ([[YouTube Video of SST Testbed](https://www.youtube.com/watch?v=DU9cHmDfRYI)]).

More publications on SST or using SST include [[SmartSP '24](https://arxiv.org/abs/2411.13441)], [[FDL '23](https://ieeexplore.ieee.org/document/10272133)], and [[SenSys '23 - Poster Abstract]](https://dl.acm.org/doi/10.1145/3625687.3628408).

For the most in-depth technical document of SST, please refer to this Ph.D. dissertation [[UC Berkeley '17](https://www2.eecs.berkeley.edu/Pubs/TechRpts/2017/EECS-2017-139.html)].

This repository includes 1) an open-source Java implementation of Auth and 2) sample code for local entities to use Auth (authentication/authorization) services provided by Auth in various programming languages for different platforms.

Please visit the [SST website](https://iotauth.github.io/) for more information.

# Prerequisites
---

1. OpenSSL command-line tools for creating certificates and keystores of Auths and example entities
2. Java 11 or above
3. [IntelliJ IDEA](https://www.jetbrains.com/idea/) for managing Java project of Auth
4. [Maven CLI (command line interface)](http://maven.apache.org/ref/3.1.0/maven-embedder/cli.html) for building Auth from the command line
5. Node.js for running example server and client entities

# Directory structure
---
- **android**: Directory for SST's Auth and entities for the Android platform (*currently under development*)
- **auth**: Directory for the Java implementation of Auth (local authentication/authorization entity), IntelliJ IDEA project
- **entity**: Directory for SST's APIs in C, Python, and JavaScript and example IoT entities using SST to be authenticated/authorized by Auth. This directory also includes [a sub-directory](https://github.com/iotauth/iotauth/tree/main/entity/node/accessors) for *Secure Communication Accessors* as software building blocks for writing IoT applications.
- **examples**: Directory for scripts and descriptions to run example Auths and entities. The [`examples/scripts/`](examples/scripts/) subdirectory contains automated end-to-end integration test scripts for C, C++, Node.js, and Python clients and servers, with a single Auth or with two Auths; see [`examples/scripts/README.md`](examples/scripts/README.md).
- **.github/workflows**: GitHub Actions workflows for continuous integration (CI): the Auth build, example generation, entity integration tests with one Auth and with two Auths, sst-c-api tests, Python formatting, and CodeQL; see [`.github/workflows/README.md`](.github/workflows/README.md).

# Quick start for SST
---
Please check [QUICKSTART.md](https://github.com/iotauth/iotauth/blob/main/QUICKSTART.md) for a quick start of SST.

# Detailed examples with Auths and entities
---
See "How to run examples" in [README.md under *examples/*](https://github.com/iotauth/iotauth/blob/main/examples/README.md) for a fully working example.

# Continuous integration (CI) tests
---
Every push and pull request to `main` runs the GitHub Actions workflows below.
[`.github/workflows/README.md`](.github/workflows/README.md) describes each workflow in detail, including how the tests are structured and how to run them locally.

| Workflow | What it checks |
| --- | --- |
| [Auth Server Build](.github/workflows/maven.yml) | Auth builds with Maven. |
| [Example Tests](.github/workflows/example.yml) | `examples/generateAll.sh` generates the credentials, configurations, and Auth databases of the example Auths and entities. |
| [Entity Integration Tests](.github/workflows/integration-test.yml) | Python unit tests, and every C, Node.js, and Python client-server combination against a single Auth ([details](.github/workflows/README.md#entity-integration-tests)). |
| [Multi-Auth Integration Tests](.github/workflows/multi-auth-test.yml) | Node.js, C, C++, and Python client-server pairs across two Auths, where the server's Auth fetches the session key from the client's Auth ([details](.github/workflows/README.md#multi-auth-integration-tests)). |
| [sst-c-api Tests](.github/workflows/sst-c-api-tests.yml), [sst-c-api C++ Tests](.github/workflows/sst-c-api-cpp-tests.yml) | The C and C++ API unit tests and examples of [sst-c-api](https://github.com/iotauth/sst-c-api) against this version of Auth. |
| [Python Formatting](.github/workflows/python-formatting.yml) | Ruff lint and format checks for `entity/python` on pull requests. |
| [CodeQL](.github/workflows/codeql-analysis.yml) | Static analysis for Java, JavaScript, and Python. |

# Contributors
---
## Active Contributors
- [Hokeun Kim](https://hokeun.github.io/) (Assistant Professor at Arizona State University)
- [Salomon Lee](https://www.linkedin.com/in/salomon-lee-637b0921) (Senior Scientific Programmer, Polaris Wireless)
- [Dongha Kim](https://github.com/Jakio815) (Ph.D. Student at Arizona State University)
- [Carlos Beltran Quinonez](https://github.com/CarlosBeltranQ) (M.S. Student at Arizona State University)
- [Sunyoung Kim](https://github.com/sunnykim638) (Ph.D. Student at Arizona State University)
- [Jose Felix](https://github.com/JFelix000) (M.S. Student at Arizona State University)
- [Deeparghya Dutta Barua](https://deeparghya.com/) (Ph.D. Student at Arizona State University)
- [Divyansh Tare](https://github.com/dtare05) (Undergraduate Student at Arizona State University)

## Former Contributors
- [Eunsuk Kang](https://eskang.github.io/) (Associate Professor at Carnegie Mellon University)
- [Marten Lohstroh](https://people.eecs.berkeley.edu/~marten/) (CEO at Xronos Inc.)
- [Taekyung Kim](https://github.com/LukeKimm) (Commissioned Officer in the Republic of Korea Army)
- [Yeongbin Jo](https://github.com/yeongbin7) (Embedded Software Engineer at Hyundai Rotem)
- [Kushal Paliwal](https://github.com/kushalpaliwal01) (Software Engineer at Globus Medical)
- [Krutyanjay Shinde](https://kjshinde.github.io/) (Hardware Validation Engineer at WattEV, Inc)

# External libraries
---
- **bluecove-2.1.2.jar**: For Bluetooth APIs, exists under auth/library/jars

# Disclaimer
---
This project is currently intended for academic and research purposes, although the ultimate goal of this project is to build a secure and robust network architecture for the Internet of Things. Therefore, users must use the provided source codes with caution at their own risk when the tools provided in this project are used for commercial or safety-critical purposes.

# Acknowledgement
---
This work was supported in part by the TerraSwarm Research Center, one of six centers supported by the STARnet phase of the Focus Center Research Program (FCRP), a Semiconductor Research Corporation program sponsored by MARCO and DARPA.
This work was supported in part by the National Research Foundation of Korea (NRF) grants funded by the Korea government (MSIT).

*Last updated on October 26, 2026*
