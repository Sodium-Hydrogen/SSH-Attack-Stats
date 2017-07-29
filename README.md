# SSH-Attack-Stats #
A simple script that will run in MOTD on a linux server and will tell you the attack statistics.<br>
This will work the best if you have fail2ban and [GeoIP][geoipurl] set up and allow access to the SSH login.<br>

With SSH allowing username and passwords it is a good idea to disable the root account and to allow logging in to only one account with an odd username and a very long password.<br>

I am not liable for any attempts against your ssh whether successful or not.

## Installation ##

Simply navigate into the directory with all the files and run 
``` sh install.sh ```

If you want the stats to be higher or lower then just replace the 42 on the file 42-log-stats and in the install.sh file. <br>

When replacing it, the higher the number the lower it will appear in MOTD.<br>

This is a list of the default Ubuntu MOTD files<br>
* 00-header 
* 10-help-text
* 90-updates-available  
* 91-release-upgrade
* 98-fsck-at-reboot
* 98-reboot-required

#### Authors ####
[Mike Julander][mikeurl]

#### License ####
This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

[geoipurl]: https://www.axllent.org/docs/view/ssh-geoip/
[mikeurl]: https://mikej.tech
