# Key Agreement for Decentralized Secure Group Messaging with Strong Security Guarantees (Java Prototype)

Java prototype implementation of the protocol described in our paper "Key Agreement for Decentralized Secure Group Messaging with Strong Security Guarantees". The prototype implements a full decentralized secure group messaging protocol, including application message encryption, signatures, prekeys, etc., even though the paper mostly focuses on the key agreement part (found in group\_protocol\_library/src/main/java/org/trvedata/sgm/FullDcgkaProtocol.java).

The implementation in this repository is an academic prototype for demonstration purposes only.  It has not undergone thorough security testing and should not be used in production.

Part of the [TRVE Data project](http://www.trvedata.org/).

## Project organisation

This prototype contains both a library implementation and CLI programs.  It is organised as a [multi-project gradle build](https://guides.gradle.org/creating-multi-project-builds/). The `group_protocol_library` module contains all protocol code including unit tests. The `cli_demo_*` modules cover different client implementations which depend on the `group_protocol_library`.

## Getting started

Run the following in the same folder as this `README.md` file to ensure a rebuild of the library and the execution of all tests. This command will recursively apply `clean` and then `test` to all modules:

```
$ ./gradlew clean test

BUILD SUCCESSFUL in 2s
8 actionable tasks: 7 executed, 1 up-to-date
```

To run one of the demos with a given set of parameters run the following command:

```
$ ./gradlew :cli_demo_local:run --args="parameters for the demo"

> Task :cli_demo_local:run
000000 [I] DczkaClientFactor: Created client Alice with IdentityKey hash code 1468310087
000009 [I] DczkaClientFactor: Created client Bob with IdentityKey hash code -124241047
Hello to 2 created clients.

BUILD SUCCESSFUL in 0s
5 actionable tasks: 1 executed, 4 up-to-date
```

To run the full evaluation used in our paper, do:
```
$ ./run_evaluation.sh <csvOutputFolder>
```
