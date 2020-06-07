Intended for servers but goes through all steps scored aswell as unscored and applies actions when applicable (and possible).
Should be complete unless mentioned below

### Skipped 
* 3.3.3 **Ensure IPv6 is disabled**
* 3.7 **Ensure wireless interfaces are disabled**, assumes no wireless interfaces exists
* 4.1.1.3 **Ensure audit logs are not automatically deleted**, assumes the standard rotate is used instead
* 4.2.2.1-5 **Syslog-ng stuff**, the script assumes rsyslog is used instead
* 5.3.3 **Ensure password reuse is limited**, no forced password changes
* 5.4.1.1 **Ensure password expiration is 365 days or less**, no forced password changes. It's just annoying and encourages bad password hygiene. If required it should likely be handled centrally with the rest of the 5.X stuff
* 5.4.1.2 **Ensure minimum days between password changes is 7 or more**, no forced password changes
* 5.4.1.3 **Ensure password expiration warning days is 7 or more**, no forced password changes
* 5.4.1.5 **Ensure all users last password change date is in the past**
* 5.5 **Ensure root login is restricted to system console**, cause fudge going through a shitton of TTYs
* 6.2.10 **Ensure users dot files are not group or world writeable**
* 6.1.1 **Audit system file permissions**, unless there's an intern that has too much time to do it.
