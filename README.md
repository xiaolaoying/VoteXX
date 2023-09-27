# VoteXX Election System

VoteXX is the first election system that has “extreme coercion resistance”. This project aims at implementing a prototype of VoteXX.

## Voting protocol

The extended abstract of the paper can be found [here](https://eprint.iacr.org/2022/1212.pdf).

Main features of VoteXX:
* End-to-end Verifiable
* Privacy
* Extreme Coercion-resistant (voter can nullify his voter even if the coercer knows all the secret information)

Roles of VoteXX:
* Voter
* Election Authority: responsible for authenticating voters
* Trustees: respondible for tallying
* Hedgehog: can nullify a voter's ballot if the voter cast the ballot under coercion

## The library

The library implements four core building blocks of VoteXX in JavaScript:
* `protocol/DKG/`: A simple DKG protocol (see [Simple_DKG.md](https://github.com/xiaolaoying/VoteXX/blob/master/doc/Simple_DKG.md))
* `protocol/MIX_AND_MATCH/`: The mix and match protocol based on [Jakobsson and Juels's proposal](http://www.arijuels.com/wp-content/uploads/2013/09/JJ00a.pdf)
* `protocol/NIZKs/verifiable_shuffle/`: The shuffle argument based on [Bayer and Groth's proposal](http://www0.cs.ucl.ac.uk/staff/J.Groth/MinimalShuffle.pdf)
* `protocol/NIZKs/nullification.js`: The novel succinct NIZK for nullifying a ballot

## Build and run

### Run the building blocks

* `example/` includes the examples of running the four protocols.
* Run `protocol/NIZKs/benchmarks/benchmark.js` to evaluate the nullification NIZK.

### Run the server

Dependencies: 
* MongoDB
* npm
* node

```bash
npm install
node server.js
```

This will start a server running on `http://localhost:3000`.

## Features not yet completed

* Do the cryptographic operations in the frontend (right now they are done in the backend).
* Correct the shuffle argument for shuffling a vector of ciphertexts.
* Add shuffle arguments in the mix and match protocol.
* Store the bulletin board in the database (right now it is stored in the memory).
* Support verifying the election using browser.
* Support any number of trustees.
* Support elegible voter list (right now everyone can vote).
* Change an alert to a beautiful BootStrap modal.
* Support "forget password".
* Support GitHub/Gooble login.
* Optimize the shuffle argument.
* Trustees do mix and match instantly when a nullification request arrives.
