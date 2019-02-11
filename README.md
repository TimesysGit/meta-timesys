What is meta-timesys
====================

This Yocto layer provides scripts for image manifest generation used for security monitoring and notification, customer support, recipe source mirroring, recipe modifications, demos, etc.

Some of the features are aimed at Timesys customers with active subscriptions.  Using these features requires an API Keyfile, which you can learn about setting up from the LinuxLink document here:

https://linuxlink.timesys.com/docs/wiki/engineering/LinuxLink_Key_File


Quick Start
===========

The fastest way to try meta-timesys and its security features is to try dropping it into your existing BSP (clone alongside other layers, add to bblayers.conf). These are instructions to try it from scratch with a pretty minimal Yocto environment.

Although a build is not required to create an image manifest or use the CVE script, BitBake does need to run (to make the manifest), so it is easiest if you adhere to the Yocto system requirements as found here:

http://www.yoctoproject.org/docs/2.4/ref-manual/ref-manual.html#intro-requirements

### Clone poky and meta-timesys

```sh
git clone git://git.yoctoproject.org/poky.git -b jethro
git clone https://github.com/TimesysGit/meta-timesys.git -b jethro
```

### Activate yocto build environment (needed for manifest creation)

```
source poky/oe-init-build-env
```

### Add meta-timesys to _conf/bblayers.conf_

Follow format of the file, just add meta-timesys after the default poky/meta, etc.

### Check an Image for CVEs

When you run the following script without any arguments, you will be prompted to select an image to check (one can also be provided as an argument to skip the GUI).

```sh
../meta-timesys/scripts/checkcves.py
```

### Create an image manifest (optional)

The _checkcves.py_ script will create a manifest automatically, but you may want to save certain configurations to pass to the script, upload to LinuxLink, or share with teammates or Timesys support. Using a pregenerated image manifest speeds up the script significantly, so doing that is recommended if your configuration is not changing often.

```sh
../meta-timesys/scripts/manifest.sh core-image-minimal manifest.json
```

### Kernel Config filter (optional)

You may pass a kernel _.config_ file to the _checkcves.py_ script, which will be uploaded to LinuxLink along with the image manifest. This filter will reduce the number of kernel CVEs reported by removing those related to features which are not being built for your kernel.

**NOTE: This must be a _full_ kernel config, not a defconfig!**

```sh
../meta-timesys/scripts/checkcves.py -k /path/to/kernel/.config
```


Maintainers
===========

Steve Bedford \<steve.bedford@timesys.com\>
