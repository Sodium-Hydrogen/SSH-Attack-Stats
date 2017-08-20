# SSH-Attack-Stats #
A simple script that will run in MOTD on a linux server and will tell you the attack statistics.<br>
This will work the best if you have fail2ban and [GeoIP][geoipurl] set up and allow access to the SSH login.<br>

With SSH allowing username and passwords it is a good idea to disable the root account and to allow logging in to only one account with an odd username and a very long password.<br>

I am not liable for any attempts against your ssh whether successful or not.

## Syntax ##

This program takes arguments or it won't display any information.
To have it display a specific file it must be specified as follows<br>
* Username and tries -> ```ssh```
* GeoIp blocking -> ```geoip```
* Fail2Ban jail counting -> ```f2b```<br>
Additionally if you use the ```-f``` argument the program will filter out some results from the list you specify. ex.<br>
```
/usr/local/bin/log-stats -f 1 ssh root
```
Tells the program to display usernames and tries but filter out every instance of root.
You can add more by increasing the number like this.
```
/usr/local/bin/log-stats -f 2 ssh root pi
```
The filter does not work on fail2Ban because there is only one line of information shown.

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
