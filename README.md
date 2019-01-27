# ParadoxIP150v2_Hassio
Hassio addon based on the ParadoxIP150v2 project by Tertiush

While there is already a Paradox IP150 addon available for Hass.io (Paradox IP150 MQTT Adapter: https://github.com/alfredopironti/Paradox_IP150), this project makes use of the IP150's Web port (80) implementation which is sometimes a bit unstable. I personally couldn't get it working successfully or at least consistantly enough to use as my main solution. 

Looking around for other similar projects, I found an implementation by Tertiush's (ParadoxIP150v2: https://github.com/Tertiush/ParadoxIP150v2) that uses the IP150's software port (10000) rather than the Web one (80) which seems to be more stable. It comes with its drawbacks as explained on the project's page.

Please note this project aims to take Tertiush's MQTT implementation using the IP150's software port and package it into a Hass.io addon so everyone can benefit, especially those who who were having issues with the previous addon. Anyone who can chip in this project is more than welcome as I will have very limited time to invest onto it. Thanks to Tertiush for the hard work; all credits goes to him. I'd also like to thank alfredopironti who did the first Hass.io addon and inspired me to start this one. :)

UPDATE: This was a quick 2 days project I wanted to finish during my summer vacations. Sadly, I did not have enough time so consider this INCOMPLETE. If anyone wants to take over, be my guest. ;)
