# DISVA - Docker Image Static Vulnerability Analyzer

## disvā (Pali) - abs. having seen; having understood; having found out [√dis + tvā]


Hi, welcome to our Intro to Cloud Computing course project -- **DISVA** Docker Image Static Vulnerability Analyzer (WIP!). 

So far, we have the ability to fetch a list of packages found within a docker image.
We do this by first generating a .tar archive of the target image with `docker save <image_name> > <tarball_name>`, which can then be processed. 

- First, we examine the manifest in the toplevel directory of the archive, and proceed through the layers which comprise the docker image. We selectively extract file relevant to operating system version and package management from each of the layers, using regular expressions. All files that get extracted are stored in a temporary directory, `temp_extract`, which is then cleaned up when the tool finishes. We try to do as little file writing and as much in-memory processing as possible for speed's sake, but we may tweak this because the contents of docker files can be arbitrarily large. 

- We then determine the package manager being used and extract the list of packages using an appropriate method. We currently support parsing the installed packages of the DPKG + apt, apk, and rpm package managers. DPKG + apt, and apk support is fairly simple, and rpm is more complex. Rpm uses a binary database file at `/var/lib/rpm/Packages`, which is only meant to be parsed by rpm. To support this, the scanner queries the database with `rpm --db-path /absolute/path/to/file -qa` to get the installed packages. This technically makes this scanner a partial dynamic-analysis tool, but this seems to be the only way to access 

- Lastly, we produce a well-formatted JSON of the packages found within the docker image. The list produced by our tool may not be exhaustive, but could still identify odd package installations as a precaution. 

- We plan to then cross reference the package list with vulnerability databases like (`)https://nvd.nist.gov/) and produce a summary of possible security issues.

- This project was heavily inspired by the EMBA project found at (https://github.com/e-m-b-a/emba), though ours is obviously nowhere near as feature rich. 

- This project utilized LLMs for code generation, specifically Anthropic's Claude 3.7 Sonnet model. 

- To verify that the layer scanning works properly, I compared the outputs of running the tool on both `ubuntu:latest` and the ubuntu image defined in `Dockerfile.ubuntu_tree`, which simply installs one more package in the image. I additionally ran it on `mongo:latest`, `redis:latest`, `nginx:latest`, `alpine:latest`, and `centos/postgresql-10-centos7:latest`, and it succesfully identified installed packages in all cases. 