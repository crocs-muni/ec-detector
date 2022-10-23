# EC Detector #

EC detector is a code parser that can determine, with some degree of confidence, which elliptic curves a given piece of code contains. The output can then be verified by a human expert.

Run the following to download a list of standard elliptic curves from https://dissect.crocs.fi.muni.cz/
```
python3 load_curves.py
```
To run the detection, execute

```
python3 ecdetector.py <package>
```

A package can be given as a path to a local directory, a local file, a local compressed archive, wild-card address, a remote archive, URL to a single source file, or a GitHub link. 

**This project is a fork of https://github.com/Wind-River/crypto-detector**
