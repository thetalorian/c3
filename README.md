# kloudi
kloudi, because you know you can't get enough of the cloud.

# Summary
For those of us who like to ensure the provisioning process is cheap, repeatable, and scalable. Kloudi is a collection of tools and libaries for AWS that is very easy and very repeatable.

# Getting started
Make sure you are using the secret sauce of zambi before using kloudi.
see, https://github.com/CityGrid/zambi

```
pip install kloudi
```

# Usage
We like to ensure the provisioning process is very repeatable. So we suppliment the CLI tools we have home grown with ini config files that we create and store in git for revision contorl management. See the examples directory for a set of config examples on our github page, https://github.com/jesco39/kloudi/tree/master/tests/confs

For a list of commands and options
```
C3EC2Provision.py -h
```

# Optional packages
The userdata.pl script is also used for provisioning, it requires the cg-cloud-init RPM.

A userdata.pl exampl script can be found in https://github.com/jesco39/kloudi/tree/master/tests/bin

If the userdata.pl script starts with sha-bang '#!' it will then be run on frist boot.

The userdata.pl script can be set via the AWS_BASE_DIR system variable
```
