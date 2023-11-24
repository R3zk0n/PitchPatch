# PitchPatch - (WIP)

 


PitchPatch aims to automate the boring steps of patch diffing. It tries to automated downloading the vulnerable KB and patched KB allowing for uses in other tools such as BinDiff and Diphora.

* Finds the KB for the CVE provided.
* Downloads the Patched and Unpatched versions.
* Flag implemented to use [winbinindex](https://winbindex.m417z.com/) to download respective files.

## Caveats
As this project requires using alot values from MSFT updates, I expect things to change and break rapidly. 

Major points to improve on are:

* Getting it working currently..
