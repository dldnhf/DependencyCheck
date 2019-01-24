Manual Analyzer
===============

*Experimental*: This analyzer is considered experimental. While this analyzer may 
be useful and provide valid results more testing must be completed to ensure that
the false negative/false positive rates are acceptable. 

For cases where none of the analyzers work well enough, and even a hints file does
not work because dependencies are not detected at all, the Manual Analyzer can be
used to read evidence from predefined properties files which have been put right
next to the dependencies (e.g., a repository with C++ libraries in 
These files have to have extension .dependencyproperties, should be named like the 
library, and contain 3 properties VENDOR, PRODUCT, VERSION, following the (Java) 
properties file syntax.

Example: `cpp_libraries\curl-7.20.1\curl-7.20.1.dependencyproperties`:
```
VENDOR=haxx
PRODUCT=curl
VERSION=7.20.1
```

The Manual Analyzer finds and reads these files and adds evidence with highest 
confidence. Thus, Dependency Check determines the right CPE based on this evidence 
(e.g., cpe:/:haxx:curl:7.20.1) and – if there are any – lists the vulnerabilities.

That is, the first part, defining the right vendor, product, and version 
information for each dependency is done manually (but in an easy to maintain way by 
adding small text files right where the libraries are stored), while the second part, 
finding up-to-date vulnerabilities for each dependency, is automatic. 

File names scanned: *.dependencyproperties
