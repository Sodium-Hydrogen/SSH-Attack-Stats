# SSH-Attack-Stats #
A simple script that will run in MOTD on a linux server and will tell you the attack statistics.<br>
This will work the best if you have fail2ban and [GeoIP][geoipurl] set up and allow access to the SSH login.<br>

* On debian based linux distrobutions fail2ban is in the apt package manager.
* As of 2020-01-13 the original project geoiplookup has been depricated and a drop in replacement has been written.
  * Goiplookup can be used with the [GeoIP][geoipurl] instructions by renaming the goiplookup file to geoiplookup.
  * The database is no longer public for geoip so the new precompiled versions of goiplookup have a key built in. 
  * Version 0.2.2 didn't work to use the precomplied binaries so I installed an older version and ran `geoiplookup self-update` which worked
### I highly suggest setting up GeoIP and fail2ban to increase security and remove attack surfaces to your ssh session! ###
I also suggest:
* Disable root login
* Disable password login in favor of large secure keys, etc. RSA 4096
* If an account must have a password only allow password prompt for that user
* Non standard usernames do increase security
* Increase the jail time and find time in fail2ban. (More than a day) 


I am not liable for any attempts against your ssh whether successful or not.

__Large log files do slow down the program and could make logining into your server via ssh slow. If this happens you can remove `ssh`, `sshkey` and `geoip` from `/etc/update-motd.d/42-log-stats` to improve prefomance.__

## Syntax ##

This program takes arguments or it won't display any information.
To have it display a specific file it must be specified as follows<br>
* Username and tries for passwords -> ```ssh```
* Username and tries for public key -> ```sshkey```
* GeoIp blocking -> ```geoip```
* Fail2Ban jail counting -> ```f2b```
* User logins -> ```login```

```-c``` can be used to declare the number of lines shown. ex.<br>
```
/usr/local/bin/log-stats ssh -c 5
```
Usually the ssh argument will display every try in the logs, but when ```-c``` is used it will now only display 5 if possible<br>

```-a``` reports everything for the argument used with it. This is the defualt behavior of ```ssh``` but not ```geoip``` or ```login```. When used with one of the latter two it will display a full list of everything in the logs and for ```login``` it will display some system runtime loging. ex.<br>
```
/usr/local/bin/log-stats geoip -a
```

Additionally if you use the ```-f``` argument the program will filter out some results from the list you specify. ```-f``` takes a minimum of two arguments, the number of items to be filtered and the items being filtered. ex.<br>
```
/usr/local/bin/log-stats ssh -f 1 root
```
Tells the program to display usernames and tries but filter out every instance of root.
You can add more by increasing the number like this.
```
/usr/local/bin/log-stats ssh -f 2 root pi
```
The filter does not work on fail2Ban because there is only one line of information shown.

The last argument is the ```-m``` argument that only works with ```login```. It will sort it and display the output in groups so all of one user until the count value is displayed then the next is and so forth. ex.<br>
```
/usr/local/bin/log-stats login -m
```
## Installation ##

Simply navigate into the directory with all the files and run.
``` 
sh install.sh
```
If you want to filter out results then you will modify the 42-log-stats file before installing.
If you want the stats to be higher or lower then just replace the 42 on the file 42-log-stats and in the install.sh file. <br>

When replacing it, the higher the number the lower it will appear in MOTD.<br>

This is a list of the default Ubuntu MOTD files<br>
* 00-header 
* 10-help-text
* 90-updates-available  
* 91-release-upgrade
* 98-fsck-at-reboot
* 98-reboot-required

### Screenshot ###
![Screenshot](Screenshot.png?raw=true)

#### Authors ####
[Mike Julander][mikeurl]

#### License ####
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details

[geoipurl]: https://www.axllent.org/docs/view/ssh-geoip/
[mikeurl]: https://mikej.tech
